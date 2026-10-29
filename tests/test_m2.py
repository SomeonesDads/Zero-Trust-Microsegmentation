from __future__ import annotations

import base64
import hashlib
import hmac
import json
import subprocess
import time

from httpx import ASGITransport, AsyncClient
import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from lab.cli import environment, host2_route, make_secrets, smoke, validate_target
from lab.network import cleanup, prepare, rules
from lab.topology import ROOT, SECRET_KEYS, build_topology, load_config, render
from services.api.server import Store, authenticate, build_app

CONFIG = load_config()


def test_topology_count_isolation_and_replica_wiring() -> None:
    topology = build_topology(CONFIG)["topology"]
    nodes = topology["nodes"]
    containers = {name: node for name, node in nodes.items() if node["kind"] == "linux"}
    assert len(containers) == CONFIG["container_count"] == 15
    assert topology["defaults"]["network-mode"] == "none"
    assert topology["defaults"]["sysctls"]["net.ipv4.ip_forward"] == "0"
    assert topology["defaults"]["privileged"] is False
    assert all("ports" not in node for node in containers.values())
    membership = {name: set() for name in containers}
    endpoints = set()
    for link in topology["links"]:
        left, right = link["endpoints"]
        assert left not in endpoints and right not in endpoints
        endpoints.update((left, right))
        name, interface = left.split(":")
        bridge, port = right.split(":")
        membership[name].add(bridge)
        assert len(port) <= 15
    front, app, data = (CONFIG["bridges"][tier] for tier in ("frontend", "application", "data"))
    for index in (1, 2):
        assert membership[f"web-{index}"] == {front, app}
        assert membership[f"auth-{index}"] == {app}
        assert membership[f"api-{index}"] == {app, data}
        assert membership[f"redis-{index}"] == {data}
        assert membership[f"postgres-{index}"] == {data}
    assert not membership["controller"]
    assert containers["controller"]["labels"]["ztm.mode"] == "simulation"


def test_committed_topology_matches_renderer_and_has_no_secrets(tmp_path) -> None:
    committed = json.loads((ROOT / "containerlab/ztm.clab.yml").read_text())
    assert committed == build_topology(CONFIG)
    output = render(CONFIG, tmp_path)
    assert (tmp_path / "nginx.conf").read_text() == (ROOT / "services/web/nginx.conf").read_text()
    assert "${LAB_POSTGRES_PASSWORD}" in output.read_text()


def test_secrets_are_private_and_environment_overrides_file(tmp_path, monkeypatch) -> None:
    path = tmp_path / "lab.env"
    make_secrets(path)
    assert path.stat().st_mode & 0o777 == 0o600
    assert set(line.split("=")[0] for line in path.read_text().splitlines()) == set(SECRET_KEYS)
    with pytest.raises(FileExistsError):
        make_secrets(path)
    monkeypatch.setenv("SHOP_USERNAME", "override")
    assert environment(path)["SHOP_USERNAME"] == "override"


def test_dry_run_host_prep_and_route_never_execute_commands(tmp_path, monkeypatch) -> None:
    def unexpected(*args, **kwargs):
        raise AssertionError("dry-run executed a host command")

    monkeypatch.setattr("lab.network.run", unexpected)
    monkeypatch.setattr("lab.cli.run", unexpected)
    assert prepare(CONFIG, "lab0", tmp_path / "state.json")["apply"] is False
    route = host2_route(CONFIG, "lab0")
    assert route["command"] == ["ip", "route", "replace", "10.77.10.0/24", "via", "10.77.0.1", "dev", "lab0"]
    assert not (tmp_path / "state.json").exists()
    with pytest.raises(ValueError):
        prepare(CONFIG, "eth0;bad", tmp_path / "state.json")


def test_firewall_is_scoped_and_only_exposes_web() -> None:
    policy = rules(CONFIG, "lab0")
    assert "flush ruleset" not in policy
    assert "table inet ztm_lab" in policy
    assert "10.77.0.2" in policy and "tcp dport 8080 accept" in policy
    assert "10.77.20.0/24" in policy and "10.77.30.0/24" in policy
    assert 'iifname { "ztm-front", "ztm-app", "ztm-data" } drop' in policy


@pytest.mark.parametrize("host", [
    "http://8.8.8.8:8080", "http://10.77.30.51:8080", "http://localhost:8080",
    "http://10.77.10.11", "https://10.77.10.11:8080", "http://10.77.10.11:8080/path",
    "http://user:pass@10.77.10.11:8080", "http://10.77.10.11:8080?x=1",
])
def test_target_allowlist_rejects_non_web_or_external_targets(host) -> None:
    with pytest.raises(ValueError):
        validate_target(host, CONFIG)


def sign(secret="secret", expired=False):
    body = json.dumps({"sub": "shopper", "exp": time.time() + (-60 if expired else 60)}).encode()
    payload = base64.urlsafe_b64encode(body).decode().rstrip("=")
    signature = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return "Bearer " + payload + "." + signature


class FakeStore:
    def __init__(self):
        self.orders = []
        self.closed = False

    async def products(self):
        return [{"id": 1, "name": "Notebook", "price_cents": 3500}]

    async def health(self):
        pass

    def save_order(self, username, items, total):
        self.orders.append((username, items, total))
        return len(self.orders)

    async def close(self):
        self.closed = True


@pytest.mark.asyncio
async def test_shopping_api_auth_cart_checkout_and_validation() -> None:
    store = FakeStore()
    application = build_app(store, "secret")
    async with application.router.lifespan_context(application):
        async with AsyncClient(transport=ASGITransport(app=application), base_url="http://lab") as client:
            assert (await client.get("/health")).json()["status"] == "ok"
            assert len((await client.get("/products")).json()) == 1
            body = {"items": [{"product_id": 1, "quantity": 2}]}
            assert (await client.post("/cart", json=body)).status_code == 401
            headers = {"Authorization": sign()}
            assert (await client.post("/cart", json=body, headers=headers)).json() == {"total_cents": 7000}
            checkout = await client.post("/checkout", json=body, headers=headers)
            assert checkout.json() == {"order_id": 1, "total_cents": 7000}
            assert store.orders[0] == ("shopper", body["items"], 7000)
            assert (await client.post("/checkout", json=body, headers={"Authorization": sign(expired=True)})).status_code == 401
            assert (await client.post("/cart", json={"items": [{"product_id": 999, "quantity": 1}]}, headers=headers)).status_code == 404
            assert (await client.post("/cart", json={"items": [{"product_id": 1, "quantity": -1}]}, headers=headers)).status_code == 422
    assert store.closed


@pytest.mark.asyncio
async def test_redis_catalog_cache_miss_then_hit() -> None:
    class Cache:
        value = None
        async def get(self, key):
            return self.value
        async def set(self, key, value, ex):
            assert key == "catalog" and ex == 30
            self.value = value

    store = Store.__new__(Store)
    store.cache = Cache()
    queries = []
    def query():
        queries.append(1)
        return [{"id": 1, "price_cents": 3500}]
    store.query_products = query
    assert await store.products() == await store.products()
    assert len(queries) == 1


def test_node_auth_token_is_accepted_by_python_api() -> None:
    result = subprocess.run(
        ["node", "-e", "const {token}=require('./services/auth/server.js'); process.stdout.write(token('shopper','secret'));"],
        cwd=ROOT, text=True, capture_output=True, check=True)
    assert authenticate("Bearer " + result.stdout, "secret") == "shopper"


@pytest.mark.asyncio
async def test_dependency_failure_is_a_readiness_failure() -> None:
    class Unavailable(FakeStore):
        async def health(self):
            raise RedisConnectionError("unavailable")

    application = build_app(Unavailable(), "secret")
    async with application.router.lifespan_context(application):
        async with AsyncClient(transport=ASGITransport(app=application), base_url="http://lab") as client:
            assert (await client.get("/health")).status_code == 503


def test_host_preparation_and_cleanup_preserve_scope_and_original_tuning(tmp_path, monkeypatch) -> None:
    from subprocess import CompletedProcess
    from lab.network import OWNER, SYSCTLS

    commands = []
    def fake_run(argv, **kwargs):
        commands.append((argv, kwargs))
        if argv[:4] == ["ip", "-j", "address", "show"]:
            output = [{"addr_info": [{"local": CONFIG["host1_ip"]}]}]
        elif argv[:2] == ["sysctl", "-n"]:
            return CompletedProcess(argv, 0, "0\n", "")
        elif argv[:3] == ["nft", "-j", "list"]:
            return CompletedProcess(argv, 1, "", "not found")
        elif argv[:4] == ["ip", "-j", "-d", "link"]:
            return CompletedProcess(argv, 1, "", "not found")
        elif argv[:4] == ["ip", "-j", "route", "show"]:
            output = [{"dst": "default", "dev": "uplink"}]
        else:
            output = []
        return CompletedProcess(argv, 0, json.dumps(output), "")

    monkeypatch.setattr("lab.network.os.geteuid", lambda: 0)
    monkeypatch.setattr("lab.network.run", fake_run)
    state_path = tmp_path / "state.json"
    prepare(CONFIG, "lab0", state_path, apply=True)
    assert json.loads(state_path.read_text())["sysctls"] == {key: "0" for key in SYSCTLS}
    nft_index = next(i for i, (argv, _) in enumerate(commands) if argv == ["nft", "-f", "-"])
    forward_index = next(i for i, (argv, _) in enumerate(commands) if argv == ["sysctl", "-w", "net.ipv4.ip_forward=1"])
    assert nft_index < forward_index
    assert all("flush" not in argv for argv, _ in commands)

    def cleanup_run(argv, **kwargs):
        commands.append((argv, kwargs))
        if argv[:3] == ["nft", "-j", "list"]:
            output = {"nftables": [{"table": {"name": "ztm_lab", "family": "inet", "comment": OWNER}}]}
        elif argv[:4] == ["ip", "-j", "-d", "link"]:
            output = [{"ifalias": OWNER}]
        else:
            output = []
        return CompletedProcess(argv, 0, json.dumps(output), "")

    monkeypatch.setattr("lab.network.run", cleanup_run)
    assert cleanup(state_path, apply=True) == {"restored": True}
    assert not state_path.exists()
    deletes = [argv[-1] for argv, _ in commands if argv[:3] == ["ip", "link", "delete"]]
    assert set(deletes) == set(CONFIG["bridges"].values())
    assert (["sysctl", "-w", "net.ipv4.ip_forward=0"], {}) in commands


@pytest.mark.parametrize("conflict", ["firewall", "bridge", "route"])
def test_host_preparation_rejects_conflicts_before_mutations(tmp_path, monkeypatch, conflict) -> None:
    from subprocess import CompletedProcess

    def fake_run(argv, **kwargs):
        if argv[:4] == ["ip", "-j", "address", "show"]:
            output = [{"addr_info": [{"local": CONFIG["host1_ip"]}]}]
        elif argv[:2] == ["sysctl", "-n"]:
            return CompletedProcess(argv, 0, "0", "")
        elif argv[:3] == ["nft", "-j", "list"]:
            return CompletedProcess(argv, 0 if conflict == "firewall" else 1, "{}", "")
        elif argv[:4] == ["ip", "-j", "-d", "link"]:
            return CompletedProcess(argv, 0 if conflict == "bridge" else 1, "[{}]", "")
        elif argv[:4] == ["ip", "-j", "route", "show"]:
            output = [{"dst": "10.77.0.0/16", "dev": "unrelated"}]
        else:
            raise AssertionError("unexpected mutation: " + repr(argv))
        return CompletedProcess(argv, 0, json.dumps(output), "")

    monkeypatch.setattr("lab.network.os.geteuid", lambda: 0)
    monkeypatch.setattr("lab.network.run", fake_run)
    with pytest.raises(RuntimeError):
        prepare(CONFIG, "lab0", tmp_path / "state.json", apply=True)
    assert not (tmp_path / "state.json").exists()
