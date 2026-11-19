"""Read-only registry for Containerlab interfaces, including network-mode=none."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import subprocess


def command(argv: list[str]) -> str:
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=15).stdout


@dataclass(frozen=True)
class ContainerIdentity:
    container_id: str
    name: str
    service: str
    pid: int
    netns_id: int
    cgroup_id: int | None
    ips: tuple[str, ...]
    interfaces: tuple[dict, ...] = ()


class IdentityRegistry:
    def __init__(self, lab_name: str = "ztm") -> None:
        self.lab_name = lab_name
        self.containers: dict[str, ContainerIdentity] = {}
        self.by_ip: dict[str, ContainerIdentity] = {}
        self.by_netns: dict[int, ContainerIdentity] = {}

    def replace(self, identities: list[ContainerIdentity]) -> None:
        containers, ips, namespaces = {}, {}, {}
        for item in identities:
            if item.netns_id in namespaces:
                raise ValueError("ambiguous shared network namespace in lab")
            containers[item.container_id] = item
            namespaces[item.netns_id] = item
            for address in item.ips:
                if address in ips:
                    raise ValueError(f"ambiguous container IP: {address}")
                ips[address] = item
        # Replace the whole snapshot, removing stopped containers and stale IPs.
        self.containers, self.by_ip, self.by_netns = containers, ips, namespaces

    def refresh(self) -> None:
        ids = command(["docker", "ps", "-q", "--filter", f"label=containerlab={self.lab_name}"]).split()
        if not ids:
            raise RuntimeError(f"no running containers for lab {self.lab_name}")
        host_links = {x["ifindex"]: x["ifname"] for x in json.loads(command(["ip", "-j", "link"]))}
        identities = []
        # Never serialize Docker Config.Env, which contains application secrets.
        for item in json.loads(command(["docker", "inspect", *ids])):
            pid = int(item["State"]["Pid"])
            if pid <= 0 or not item["State"]["Running"]:
                raise RuntimeError("container changed while refreshing registry; retry snapshot")
            ns_path = Path(f"/proc/{pid}/ns/net")
            netns = ns_path.stat().st_ino
            links = json.loads(command(["nsenter", "-t", str(pid), "-n", "ip", "-j", "address"]))
            ips, interfaces = [], []
            for link in links:
                if link["ifname"] == "lo":
                    continue
                addresses = [a["local"] for a in link.get("addr_info", []) if a["family"] == "inet"]
                ips.extend(addresses)
                interfaces.append({"name": link["ifname"], "ifindex": link["ifindex"],
                    "host_ifindex": link.get("link_index"),
                    "host_veth": host_links.get(link.get("link_index")), "ips": addresses})
            cgroup_id = None
            for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines():
                if line.startswith("0::"):
                    path = Path("/sys/fs/cgroup") / line[3:].lstrip("/")
                    if path.exists():
                        cgroup_id = path.stat().st_ino
            if ns_path.stat().st_ino != netns:
                raise RuntimeError("namespace changed during registry snapshot")
            # StartedAt distinguishes a restart with the same Docker ID.
            generation = item["Id"] + "@" + item["State"]["StartedAt"]
            identities.append(ContainerIdentity(generation, item["Name"].lstrip("/"),
                item["Config"].get("Labels", {}).get("ztm.role", "unknown"),
                pid, netns, cgroup_id, tuple(ips), tuple(interfaces)))
        self.replace(identities)

    def snapshot(self) -> list[dict]:
        return [asdict(item) for item in self.containers.values()]
