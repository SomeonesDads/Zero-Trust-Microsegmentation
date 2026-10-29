from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import subprocess
import sys
import time
from urllib.parse import urlparse
from urllib.request import Request, build_opener, ProxyHandler

from lab.network import cleanup, prepare, run, validate_interface
from lab.topology import DEFAULT_CONFIG, ROOT, SECRET_KEYS, build_topology, load_config, render

DEFAULT_OUTPUT = ROOT / "data" / "lab"
IMAGES = ("web", "auth", "api", "redis", "postgres", "decoy", "controller")


def inspect() -> dict:
    tools = {tool: shutil.which(tool) for tool in
             ("docker", "containerlab", "clang", "bpftool", "pkg-config", "chronyc", "nft", "ip", "sysctl", "ethtool")}
    versions = {}
    for tool, flag in (("docker", "--version"), ("containerlab", "version"),
                       ("clang", "--version"), ("bpftool", "version"), ("chronyc", "--version")):
        if tools[tool]:
            versions[tool] = run([tools[tool], flag], check=False).stdout.splitlines()[:1]
    daemon = run(["docker", "info", "--format", "{{.ServerVersion}}"], check=False) if tools["docker"] else None
    libbpf = run(["pkg-config", "--modversion", "libbpf"], check=False) if tools["pkg-config"] else None
    kernel = tuple(int(value) for value in platform.release().split(".")[:2])
    return {"os": platform.platform(), "python": platform.python_version(), "kernel": platform.release(),
            "kernel_supported": kernel >= (5, 15),
            "btf": Path("/sys/kernel/btf/vmlinux").is_file(), "tools": tools, "versions": versions,
            "docker_daemon": bool(daemon and daemon.returncode == 0),
            "libbpf": libbpf.stdout.strip() if libbpf and libbpf.returncode == 0 else None,
            "missing": [name for name, executable in tools.items() if executable is None]}


def require_host_prerequisites() -> None:
    report = inspect()
    problems = list(report["missing"])
    if not report["kernel_supported"]:
        problems.append("Linux kernel >= 5.15")
    if not report["btf"]:
        problems.append("kernel BTF")
    if not report["docker_daemon"]:
        problems.append("accessible Docker daemon")
    if not report["libbpf"]:
        problems.append("libbpf development package")
    if problems:
        raise RuntimeError("host prerequisites missing: " + ", ".join(problems))


def environment(path: Path, required: tuple[str, ...] = SECRET_KEYS) -> dict[str, str]:
    env = dict(os.environ)
    if path.exists():
        for line in path.read_text().splitlines():
            if line.strip() and not line.lstrip().startswith("#"):
                name, value = line.split("=", 1)
                if name not in SECRET_KEYS or not value.strip():
                    raise ValueError("unexpected or empty lab environment entry")
                env.setdefault(name, value.strip())
    missing = [key for key in required if not env.get(key)]
    if missing:
        raise ValueError("missing environment variables: " + ", ".join(missing) + "; run the secrets command")
    return env


def make_secrets(path: Path) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as file:
        for key in SECRET_KEYS:
            file.write(key + "=" + ("shopper" if key == "SHOP_USERNAME" else secrets.token_hex(32)) + "\n")
    return {"environment_file": str(path), "mode": "0600"}


def validate_target(host: str, config: dict) -> str:
    parsed = urlparse(host)
    if (parsed.scheme != "http" or parsed.username or parsed.password or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment or parsed.port != config["web_port"]
            or parsed.hostname not in config["web_addresses"]):
        raise ValueError("target must be an explicit http://<lab-web-IP>:8080 URL")
    return host.rstrip("/")


def http_json(host: str, path: str, *, body: dict | None = None, token: str | None = None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = Request(host + path, headers=headers,
                      data=json.dumps(body).encode() if body is not None else None)
    # Lab traffic must never follow ambient proxy configuration.
    with build_opener(ProxyHandler({})).open(request, timeout=5) as response:
        return json.load(response)


def smoke(host: str, config: dict, env: dict[str, str]) -> dict:
    host = validate_target(host, config)
    deadline = time.monotonic() + 60
    last_error = None
    while time.monotonic() < deadline:
        try:
            http_json(host, "/api/health")
            break
        except (OSError, ValueError) as error:
            last_error = error
            time.sleep(1)
    else:
        raise RuntimeError(f"shopping dependencies did not become ready: {last_error}")
    login = http_json(host, "/auth/login", body={"username": env["SHOP_USERNAME"], "password": env["SHOP_PASSWORD"]})
    products = http_json(host, "/api/products")
    body = {"items": [{"product_id": products[0]["id"], "quantity": 1}]}
    cart = http_json(host, "/api/cart", body=body, token=login["token"])
    order = http_json(host, "/api/checkout", body=body, token=login["token"])
    if order["total_cents"] != cart["total_cents"] or order["order_id"] <= 0:
        raise RuntimeError("checkout did not persist a valid order")
    return {"status": "ok", "host": host, "products": len(products),
            "order_id": order["order_id"], "total_cents": order["total_cents"]}


def verify(config: dict, env: dict[str, str]) -> dict:
    """Host 1 acceptance: count, networking, both replicas, and dependencies."""
    result = run(["docker", "ps", "-q", "--filter", f"label=containerlab={config['name']}"])
    ids = result.stdout.split()
    if len(ids) != config["container_count"]:
        raise RuntimeError(f"expected 15 running containers, found {len(ids)}")
    containers = json.loads(run(["docker", "inspect", *ids]).stdout)
    expected_names = {"/clab-ztm-" + name for name, node in build_topology(config)["topology"]["nodes"].items()
                      if node["kind"] == "linux"}
    if {item["Name"] for item in containers} != expected_names:
        raise RuntimeError("running containers do not match the expected topology")
    if any(item["HostConfig"]["NetworkMode"] != "none" for item in containers):
        raise RuntimeError("a lab container has an unintended Docker management network")
    for tier in ("application", "data"):
        data = json.loads(run(["ip", "-j", "address", "show", "dev", config["bridges"][tier]]).stdout)
        if any(link["addr_info"] for link in data):
            raise RuntimeError(f"{tier} bridge must have no host IP addresses")
    for key, expected in (("net.core.bpf_jit_enable", "1"), ("net.core.bpf_jit_harden", "2")):
        if run(["sysctl", "-n", key]).stdout.strip() != expected:
            raise RuntimeError(f"host tuning mismatch: {key}")
    # Check every API/auth replica, not only the load-balanced frontend.
    for replica in (1, 2):
        run(["docker", "exec", f"clab-ztm-api-{replica}", "python", "-c",
             "import json,urllib.request; print(json.load(urllib.request.urlopen('http://127.0.0.1:8080/health')))"])
        run(["docker", "exec", f"clab-ztm-auth-{replica}", "node", "-e",
             "fetch('http://127.0.0.1:3000/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"])
    checks = [smoke(f"http://{ip}:8080", config, env) for ip in config["web_addresses"]]
    return {"containers": len(ids), "host1_checks": checks,
            "host2_acceptance": "Run smoke and load on Host 2 after installing its frontend route."}


def host2_route(config: dict, interface: str, apply: bool = False) -> dict:
    validate_interface(interface)
    command = ["ip", "route", "replace", config["frontend_subnet"],
               "via", config["host1_ip"], "dev", interface]
    if apply:
        if os.geteuid() != 0:
            raise PermissionError("host2-route --apply requires root")
        data = json.loads(run(["ip", "-j", "address", "show", "dev", interface]).stdout)
        if not any(item["local"] == config["host2_ip"] for link in data for item in link["addr_info"]):
            raise RuntimeError("configure Host 2's dedicated /30 address first")
        run(command)
    return {"command": command, "host2_ip_required": config["host2_ip"], "apply": apply}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="M2 isolated Containerlab app; privileged changes require --apply.",
        epilog="Host 1: secrets, render, prepare --interface LAB_NIC --apply, build, deploy, verify. "
               "Host 2: host2-route --interface LAB_NIC --apply, smoke --host URL, load --host URL. "
               "Configure 10.77.0.1/30 and 10.77.0.2/30 on the dedicated link first. "
               "Install requirements-dev.txt for tests; load/requirements.txt on Host 2.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--env-file", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("inspect", "secrets", "render", "build", "deploy", "destroy", "verify"):
        commands.add_parser(name)
    for name in ("prepare", "host2-route"):
        sub = commands.add_parser(name)
        sub.add_argument("--interface", required=True, help="dedicated private lab NIC/VLAN; never the public interface")
        sub.add_argument("--apply", action="store_true")
    sub = commands.add_parser("cleanup")
    sub.add_argument("--apply", action="store_true")
    for name in ("smoke", "load"):
        sub = commands.add_parser(name)
        sub.add_argument("--host", required=True)
        if name == "load":
            sub.add_argument("--users", type=int, default=50)
            sub.add_argument("--rps", type=float, default=100)
            sub.add_argument("--duration", default="5m")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        env_path = args.env_file or args.output / "lab.env"
        state_path = args.output / "host-state.json"
        if args.command == "inspect":
            result = inspect()
        elif args.command == "secrets":
            result = make_secrets(env_path)
        elif args.command == "render":
            result = {"topology": str(render(config, args.output)), "containers": 15}
        elif args.command == "prepare":
            if args.apply:
                require_host_prerequisites()
            result = prepare(config, args.interface, state_path, args.apply)
        elif args.command == "cleanup":
            result = cleanup(state_path, args.apply)
        elif args.command == "host2-route":
            result = host2_route(config, args.interface, args.apply)
        elif args.command == "build":
            for role in IMAGES:
                dockerfile = "Dockerfile" if role == "controller" else f"services/{role}/Dockerfile"
                subprocess.run(["docker", "build", "-t", f"ztm-{role}:m2", "-f", dockerfile, "."],
                               cwd=ROOT, check=True)
            result = {"images": list(IMAGES)}
        elif args.command in ("deploy", "destroy"):
            env = environment(env_path)
            if args.command == "deploy" and not state_path.exists():
                raise RuntimeError("run prepare --apply before deployment")
            topology = render(config, args.output)
            subprocess.run(["containerlab", args.command, "--topo", str(topology)],
                           cwd=ROOT, env=env, check=True)
            result = {"topology": str(topology), "command": args.command}
        elif args.command == "verify":
            result = verify(config, environment(env_path))
        elif args.command == "smoke":
            result = smoke(args.host, config, environment(env_path, ("SHOP_USERNAME", "SHOP_PASSWORD")))
        else:
            host = validate_target(args.host, config)
            if args.users <= 0 or args.rps <= 0:
                raise ValueError("users and rps must be positive")
            env = environment(env_path, ("SHOP_USERNAME", "SHOP_PASSWORD"))
            env["ZTM_RPS_PER_USER"] = str(args.rps / args.users)
            env["ZTM_CONFIG"] = str(args.config.resolve())
            args.output.mkdir(parents=True, exist_ok=True)
            subprocess.run([sys.executable, "-m", "locust", "-f", str(ROOT / "load" / "locustfile.py"),
                            "--headless", "--host", host, "--users", str(args.users),
                            "--spawn-rate", str(min(args.users, 20)), "--run-time", args.duration,
                            "--csv", str(args.output / "locust"), "--exit-code-on-error", "1"],
                           env=env, check=True)
            result = {"configured_requests_per_second": args.rps,
                      "measured_throughput": "See locust_stats.csv; configured RPS is only a pacing target."}
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(f"lab: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
