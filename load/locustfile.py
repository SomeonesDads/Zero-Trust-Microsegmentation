"""Benign shopping traffic from Host 2; each task issues exactly one request."""
from pathlib import Path
import os
import sys
import time

from locust import HttpUser, constant_throughput, events, task
from locust.exception import StopUser

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lab.cli import validate_target
from lab.topology import DEFAULT_CONFIG, load_config


@events.init.add_listener
def check_target(environment, **_):
    validate_target(environment.host, load_config(Path(os.environ.get("ZTM_CONFIG", DEFAULT_CONFIG))))


class Shopper(HttpUser):
    wait_time = constant_throughput(float(os.environ.get("ZTM_RPS_PER_USER", "2")))

    def login(self):
        with self.client.post("/auth/login", json={
                "username": os.environ["SHOP_USERNAME"], "password": os.environ["SHOP_PASSWORD"]},
                catch_response=True) as response:
            if response.status_code != 200:
                response.failure("login failed")
                raise StopUser()
            self.client.headers["Authorization"] = "Bearer " + response.json()["token"]
            self.expires = time.monotonic() + 3500

    def on_start(self):
        self.client.trust_env = False
        self.login()

    def refresh(self):
        if time.monotonic() > self.expires:
            self.login()

    @task(6)
    def browse(self):
        self.refresh()
        self.client.get("/api/products")

    @task(3)
    def cart(self):
        self.refresh()
        self.client.post("/api/cart", json={"items": [{"product_id": 1, "quantity": 2}]})

    @task(1)
    def checkout(self):
        self.refresh()
        self.client.post("/api/checkout", json={"items": [{"product_id": 2, "quantity": 1}]})
