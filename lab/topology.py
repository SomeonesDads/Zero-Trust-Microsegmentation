from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "configs" / "lab.json"
SECRET_KEYS = ("LAB_APP_SECRET", "LAB_POSTGRES_PASSWORD", "LAB_REDIS_PASSWORD",
               "SHOP_USERNAME", "SHOP_PASSWORD")
PRIVATE = tuple(ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def load_config(path: Path = DEFAULT_CONFIG) -> dict:
    config = json.loads(path.read_text())
    if config["name"] != "ztm" or config["container_count"] != 15:
        raise ValueError("this topology requires lab name ztm and 15 containers")
    networks = [ipaddress.ip_network(config[key]) for key in
                ("link_subnet", "frontend_subnet", "application_subnet", "data_subnet")]
    if networks[0].prefixlen != 30 or any(net.prefixlen != 24 for net in networks[1:]):
        raise ValueError("use one /30 link and three /24 service subnets")
    if any(net.version != 4 or not any(net.subnet_of(private) for private in PRIVATE) for net in networks):
        raise ValueError("all lab subnets must be RFC1918 IPv4")
    if any(left.overlaps(right) for i, left in enumerate(networks) for right in networks[i + 1:]):
        raise ValueError("lab subnets overlap")
    if [config["host1_ip"], config["host2_ip"]] != [str(ip) for ip in networks[0].hosts()]:
        raise ValueError("host IPs must be the two addresses of the dedicated /30 link")
    if config["frontend_gateway"] != str(networks[1][1]):
        raise ValueError("frontend_gateway must be the first frontend address")
    if config["web_addresses"] != [str(networks[1][offset]) for offset in (11, 12)]:
        raise ValueError("web_addresses must use frontend offsets 11 and 12")
    if config["web_port"] != 8080:
        raise ValueError("the web service listens on port 8080")
    bridges = config["bridges"]
    if set(bridges) != {"frontend", "application", "data"} or len(set(bridges.values())) != 3:
        raise ValueError("three distinct bridges are required")
    if any(not re.fullmatch(r"ztm-[a-z]{1,8}", name) for name in bridges.values()):
        raise ValueError("bridge names must start with ztm- and fit Linux interface names")
    return config


def address(config: dict, tier: str, offset: int) -> str:
    return str(ipaddress.ip_network(config[f"{tier}_subnet"])[offset])


def build_topology(config: dict, web_config: str = "../services/web/nginx.conf") -> dict:
    """15 containers, three host bridges, no Docker management interfaces.

    Schema references:
    https://containerlab.dev/manual/nodes/#none-mode
    https://containerlab.dev/manual/kinds/bridge/
    """
    nodes = {bridge: {"kind": "bridge"} for bridge in config["bridges"].values()}
    links = []
    counter = 0

    def attach(name: str, tier: str, interface: str, offset: int) -> None:
        nonlocal counter
        counter += 1
        bridge = config["bridges"][tier]
        links.append({"endpoints": [f"{name}:{interface}", f"{bridge}:ztmv{counter}"]})
        nodes[name]["exec"].extend([
            f"ip address replace {address(config, tier, offset)}/24 dev {interface}",
            f"ip link set dev {interface} up",
        ])

    def node(name: str, role: str, env: dict | None = None) -> None:
        nodes[name] = {"kind": "linux", "image": f"ztm-{role}:m2",
                       "labels": {"ztm.role": role, "ztm.mode": "lab"},
                       "env": env or {}, "exec": []}

    for replica in (1, 2):
        web, auth, api = f"web-{replica}", f"auth-{replica}", f"api-{replica}"
        redis, postgres = f"redis-{replica}", f"postgres-{replica}"
        node(web, "web")
        nodes[web]["binds"] = [f"{web_config}:/etc/nginx/nginx.conf:ro"]
        attach(web, "frontend", "eth1", 10 + replica)
        attach(web, "application", "eth2", 10 + replica)
        nodes[web]["exec"].append(
            f"ip route replace {config['link_subnet']} via {config['frontend_gateway']} dev eth1")
        node(auth, "auth", {key: "${" + key + "}" for key in ("LAB_APP_SECRET", "SHOP_USERNAME", "SHOP_PASSWORD")})
        attach(auth, "application", "eth1", 20 + replica)
        node(api, "api", {
            "LAB_APP_SECRET": "${LAB_APP_SECRET}",
            "LAB_POSTGRES_PASSWORD": "${LAB_POSTGRES_PASSWORD}",
            "LAB_REDIS_PASSWORD": "${LAB_REDIS_PASSWORD}",
            "REDIS_HOST": address(config, "data", 40 + replica),
            "POSTGRES_HOST": address(config, "data", 50 + replica),
        })
        attach(api, "application", "eth1", 30 + replica)
        attach(api, "data", "eth2", 30 + replica)
        node(redis, "redis", {"LAB_REDIS_PASSWORD": "${LAB_REDIS_PASSWORD}"})
        attach(redis, "data", "eth1", 40 + replica)
        node(postgres, "postgres", {
            "POSTGRES_USER": "shop", "POSTGRES_DB": "shop",
            "POSTGRES_PASSWORD": "${LAB_POSTGRES_PASSWORD}",
        })
        attach(postgres, "data", "eth1", 50 + replica)

    for index in range(1, 5):
        name = f"decoy-{index}"
        node(name, "decoy", {"SERVICE_NAME": name})
        attach(name, "application" if index <= 2 else "data", "eth1", 200 + index)

    node("controller", "controller")
    nodes["controller"]["labels"]["ztm.mode"] = "simulation"
    nodes["controller"]["cap-add"] = []
    nodes["controller"].pop("exec")
    return {
        "name": config["name"],
        "topology": {
            "defaults": {
                "network-mode": "none", "privileged": False, "cap-add": ["NET_ADMIN"],
                "sysctls": {"net.ipv4.ip_forward": "0", "net.ipv6.conf.all.disable_ipv6": "1"},
            },
            "nodes": nodes, "links": links,
        },
    }


def render(config: dict, directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    nginx = (ROOT / "services" / "web" / "nginx.conf").read_text()
    for offset in (21, 22, 31, 32):
        nginx = nginx.replace(f"10.77.20.{offset}", address(config, "application", offset))
    web_config = directory / "nginx.conf"
    web_config.write_text(nginx)
    path = directory / "ztm.clab.yml"
    # JSON is also valid YAML and avoids requiring PyYAML for host preparation.
    path.write_text(json.dumps(build_topology(config, str(web_config.resolve())), indent=2) + "\n")
    return path
