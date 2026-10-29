from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess

TABLE = "ztm_lab"
OWNER = "managed-by-ztm"
SYSCTLS = {"net.core.bpf_jit_enable": "1", "net.core.bpf_jit_harden": "2",
           "net.ipv4.ip_forward": "1"}


def run(argv: list[str], *, check: bool = True, input: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(argv, check=check, text=True, capture_output=True, input=input, timeout=120)


def validate_interface(interface: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface):
        raise ValueError("invalid dedicated lab interface")
    return interface


def owns_table(output: str) -> bool:
    return any(entry.get("table", {}).get("comment") == OWNER
               and entry["table"].get("name") == TABLE
               and entry["table"].get("family") == "inet"
               for entry in json.loads(output).get("nftables", []))


def rules(config: dict, interface: str) -> str:
    """Only the two frontend web sockets cross the dedicated Host 2 link.

    The private application/data bridges have no host addresses. Filtering
    applies before Containerlab's permissive FORWARD rules. Other firewall
    tables and chains remain untouched.
    """
    validate_interface(interface)
    fronts = ", ".join(config["web_addresses"])
    bridges = ", ".join('"' + name + '"' for name in config["bridges"].values())
    subnets = ", ".join(config[key] for key in ("frontend_subnet", "application_subnet", "data_subnet"))
    same_bridge = "\n".join(f'        iifname "{name}" oifname "{name}" accept' for name in config["bridges"].values())
    return f'''table inet {TABLE} {{
    comment "{OWNER}"
    chain forward {{
        type filter hook forward priority -200; policy accept;
        iifname "{interface}" ip saddr {config["host2_ip"]} ip daddr {{ {fronts} }} tcp dport 8080 accept
        oifname "{interface}" ip saddr {{ {fronts} }} ip daddr {config["host2_ip"]} tcp sport 8080 ct state established,related accept
        iifname "{interface}" ip daddr {{ {subnets} }} drop
        oifname "{interface}" ip saddr {{ {subnets} }} drop
{same_bridge}
        iifname {{ {bridges} }} drop
        oifname {{ {bridges} }} drop
    }}
}}
'''


def prepare(config: dict, interface: str, state_path: Path, apply: bool = False) -> dict:
    validate_interface(interface)
    plan = {"interface": interface, "host1_ip_required": config["host1_ip"],
            "sysctls": SYSCTLS, "bridges": config["bridges"],
            "frontend_gateway": config["frontend_gateway"], "nftables": rules(config, interface),
            "apply": apply}
    if not apply:
        return plan
    if os.geteuid() != 0:
        raise PermissionError("prepare --apply requires root for bridges, nftables and sysctls")
    previous = json.loads(state_path.read_text()) if state_path.exists() else None
    if previous and (previous["config"] != config or previous["interface"] != interface):
        raise RuntimeError("existing lab preparation uses another configuration; clean it first")
    addresses = json.loads(run(["ip", "-j", "address", "show", "dev", interface]).stdout)
    if not any(item["local"] == config["host1_ip"] for link in addresses for item in link["addr_info"]):
        raise RuntimeError("configure the dedicated /30 link on Host 1 before preparation")
    old_sysctls = {key: run(["sysctl", "-n", key]).stdout.strip() for key in SYSCTLS}
    table = run(["nft", "-j", "list", "table", "inet", TABLE], check=False)
    if table.returncode == 0 and (not previous or not owns_table(table.stdout)):
        raise RuntimeError("refusing to overwrite an unowned nftables table")
    existing = {}
    for bridge in config["bridges"].values():
        result = run(["ip", "-j", "-d", "link", "show", "dev", bridge], check=False)
        if result.returncode == 0:
            data = json.loads(result.stdout)[0]
            if data.get("ifalias") != OWNER or data.get("linkinfo", {}).get("info_kind") != "bridge":
                raise RuntimeError(f"refusing to use unowned interface {bridge}")
            existing[bridge] = data
    # Refuse to claim an existing route to a service subnet.
    routes = json.loads(run(["ip", "-j", "route", "show"]).stdout)
    service_networks = [ipaddress.ip_network(config[f"{tier}_subnet"])
                        for tier in ("frontend", "application", "data")]
    for route in routes:
        destination = route.get("dst", "default")
        if destination == "default":
            continue
        if any(ipaddress.ip_network(destination).overlaps(net) for net in service_networks):
            if route.get("dev") not in existing:
                raise RuntimeError("a lab subnet conflicts with an existing host route")
    state_path.parent.mkdir(parents=True, exist_ok=True)
    if previous is None:
        state_path.write_text(json.dumps({"config": config, "interface": interface,
                                         "sysctls": old_sysctls}, indent=2))
        state_path.chmod(0o600)
    # Install isolation before enabling routing or giving the frontend an IP.
    run(["nft", "-f", "-"], input=(f"delete table inet {TABLE}\n" if table.returncode == 0 else "") + rules(config, interface))
    for bridge in config["bridges"].values():
        if bridge not in existing:
            run(["ip", "link", "add", bridge, "type", "bridge"])
            run(["ip", "link", "set", "dev", bridge, "alias", OWNER])
        run(["ip", "link", "set", "dev", bridge, "up"])
        run(["sysctl", "-w", f"net.ipv6.conf.{bridge}.disable_ipv6=1"])
    run(["ip", "address", "replace", f"{config['frontend_gateway']}/24", "dev", config["bridges"]["frontend"]])
    for key, value in SYSCTLS.items():
        run(["sysctl", "-w", f"{key}={value}"])
    return plan


def cleanup(state_path: Path, apply: bool = False) -> dict:
    state = json.loads(state_path.read_text())
    if not apply:
        return {"restore_sysctls": state["sysctls"], "remove_owned_bridges": state["config"]["bridges"],
                "remove_owned_table": TABLE, "apply": False}
    if os.geteuid() != 0:
        raise PermissionError("cleanup --apply requires root")
    bridges = state["config"]["bridges"].values()
    for bridge in bridges:
        ports = run(["ip", "-j", "link", "show", "master", bridge], check=False)
        if ports.returncode == 0 and json.loads(ports.stdout):
            raise RuntimeError(f"{bridge} still has attached interfaces; destroy the topology first")
        result = run(["ip", "-j", "-d", "link", "show", "dev", bridge], check=False)
        if result.returncode == 0 and json.loads(result.stdout)[0].get("ifalias") != OWNER:
            raise RuntimeError(f"refusing to remove unowned bridge {bridge}")
    table = run(["nft", "-j", "list", "table", "inet", TABLE], check=False)
    if table.returncode == 0 and not owns_table(table.stdout):
        raise RuntimeError("refusing to remove unowned firewall table")
    for key, value in state["sysctls"].items():
        run(["sysctl", "-w", f"{key}={value}"])
    if table.returncode == 0:
        run(["nft", "delete", "table", "inet", TABLE])
    for bridge in bridges:
        run(["ip", "link", "delete", bridge], check=False)
    state_path.unlink()
    return {"restored": True}
