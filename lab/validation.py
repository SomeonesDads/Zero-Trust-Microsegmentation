"""Read-only clock checks and explicit, allow-listed lab acceptance probes."""
from __future__ import annotations

import json
import re
import socket
import time

from lab.network import run, validate_interface
from lab.topology import address


def parse_clock(text: str, bound_ms: float = 5) -> dict:
    match = re.search(r"System time\s*:\s*([\d.eE+-]+) seconds (fast|slow)", text)
    leap = re.search(r"Leap status\s*:\s*(.+)", text)
    stratum = re.search(r"Stratum\s*:\s*(\d+)", text)
    offset = float(match[1]) * 1000 if match else None
    synchronized = bool(leap and leap[1].strip() == "Normal" and stratum and 0 < int(stratum[1]) < 16)
    return {"available": True, "synchronized": synchronized, "absolute_offset_ms": offset,
            "bound_ms": bound_ms, "latency_valid": synchronized and offset is not None and abs(offset) <= bound_ms}


def clock_status() -> dict:
    try:
        result = run(["chronyc", "tracking"], check=False)
        if result.returncode:
            return {"available": False, "latency_valid": False, "error": result.stderr.strip()}
        return parse_clock(result.stdout)
    except (OSError, TimeoutError) as error:
        return {"available": False, "latency_valid": False, "error": str(error)}


def host2_isolation(config: dict, interface: str) -> dict:
    """Bind test sockets to the dedicated NIC; never use an ambient default route."""
    validate_interface(interface)
    checks = []
    targets = [(ip, 8080, True) for ip in config["web_addresses"]]
    targets += [(address(config, "application", 31), 8080, False),
                (address(config, "data", 41), 6379, False),
                (address(config, "data", 51), 5432, False)]
    for ip, port, expected in targets:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0")
            client.bind((config["host2_ip"], 0))
            client.settimeout(2)
            reached = client.connect_ex((ip, port)) == 0
        checks.append({"ip": ip, "port": port, "reachable": reached, "expected": expected})
    return {"passed": all(x["reachable"] == x["expected"] for x in checks), "checks": checks}


def connection_probe(config: dict, count: int = 20) -> dict:
    """Open harmless TCP connections from api-1 to its lab decoy; no payloads."""
    if not 1 <= count <= 10000:
        raise ValueError("connections must be between 1 and 10000")
    # decoy-3 is in the same data bridge as api-1 and listens on TCP/8080.
    target = address(config, "data", 203)
    script = ("import json,socket,time; result=[]; "
              f"target=({target!r},8080); "
              f"\nfor i in range({count}):\n"
              " with socket.create_connection(target,timeout=2) as s:\n"
              "  result.append({'src_ip':s.getsockname()[0],'src_port':s.getsockname()[1]})\n"
              " time.sleep(0.02)\n"
              "print(json.dumps(result))")
    started = time.monotonic()
    result = run(["docker", "exec", f"clab-{config['name']}-api-1", "python", "-c", script])
    return {"source": f"clab-{config['name']}-api-1", "target": target, "port": 8080,
            "count": count, "started_mono": started, "ended_mono": time.monotonic(),
            "connections": json.loads(result.stdout)}
