"""Shopping API: parameterized Postgres queries and Redis catalog caching."""
from __future__ import annotations

import asyncio
import base64
from contextlib import asynccontextmanager
import hashlib
import hmac
import json
import os
import time

from fastapi import FastAPI, Header, HTTPException, Request
import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field
from redis.asyncio import Redis
from redis.exceptions import RedisError


class Item(BaseModel):
    product_id: int = Field(gt=0)
    quantity: int = Field(ge=1, le=100)


class Cart(BaseModel):
    items: list[Item] = Field(min_length=1, max_length=20)


def authenticate(authorization: str | None, secret: str) -> str:
    try:
        scheme, encoded = (authorization or "").split(" ", 1)
        if scheme.lower() != "bearer":
            raise ValueError("invalid scheme")
        payload, signature = encoded.split(".", 1)
        expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("invalid signature")
        body = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        if body["exp"] <= time.time() or not isinstance(body["sub"], str):
            raise ValueError("expired or invalid token")
        return body["sub"]
    except (ValueError, KeyError, TypeError, UnicodeError) as error:
        raise HTTPException(401, "invalid or expired token") from error


class Store:
    def __init__(self) -> None:
        # Pass fields separately: secrets are never interpolated into URLs/SQL.
        self.db = {"host": os.environ["POSTGRES_HOST"], "dbname": "shop", "user": "shop",
                   "password": os.environ["LAB_POSTGRES_PASSWORD"], "connect_timeout": 3}
        self.cache = Redis(host=os.environ["REDIS_HOST"], password=os.environ["LAB_REDIS_PASSWORD"],
                           decode_responses=True, socket_timeout=3, socket_connect_timeout=3)

    def query_products(self) -> list[dict]:
        with psycopg.connect(**self.db, row_factory=dict_row) as connection:
            return connection.execute("SELECT id, name, price_cents FROM products ORDER BY id").fetchall()

    async def products(self) -> list[dict]:
        cached = await self.cache.get("catalog")
        if cached:
            return json.loads(cached)
        products = await asyncio.to_thread(self.query_products)
        await self.cache.set("catalog", json.dumps(products), ex=30)
        return products

    def save_order(self, username: str, items: list[dict], total: int) -> int:
        with psycopg.connect(**self.db) as connection:
            return connection.execute(
                "INSERT INTO orders (username, items, total_cents) VALUES (%s, %s, %s) RETURNING id",
                (username, Jsonb(items), total)).fetchone()[0]

    async def health(self) -> None:
        await self.cache.ping()
        await asyncio.to_thread(self.query_products)

    async def close(self) -> None:
        await self.cache.aclose()


def build_app(store: Store | None = None, secret: str | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(application: FastAPI):
        application.state.store = store or Store()
        application.state.secret = secret or os.environ["LAB_APP_SECRET"]
        try:
            yield
        finally:
            await application.state.store.close()

    application = FastAPI(title="Isolated shopping lab", lifespan=lifespan)

    @application.get("/health")
    async def health(request: Request) -> dict:
        try:
            await request.app.state.store.health()
        except (psycopg.Error, RedisError, OSError, TimeoutError) as error:
            raise HTTPException(503, "database unavailable") from error
        return {"status": "ok", "service": "api", "dependencies": ["redis", "postgres"]}

    @application.get("/products")
    async def products(request: Request) -> list[dict]:
        return await request.app.state.store.products()

    async def calculate(cart: Cart, request: Request, authorization: str | None) -> tuple[str, int]:
        username = authenticate(authorization, request.app.state.secret)
        catalog = {item["id"]: item for item in await request.app.state.store.products()}
        if any(item.product_id not in catalog for item in cart.items):
            raise HTTPException(404, "unknown product")
        total = sum(catalog[item.product_id]["price_cents"] * item.quantity for item in cart.items)
        return username, total

    @application.post("/cart")
    async def cart(body: Cart, request: Request, authorization: str | None = Header(default=None)) -> dict:
        _, total = await calculate(body, request, authorization)
        return {"total_cents": total}

    @application.post("/checkout")
    async def checkout(body: Cart, request: Request, authorization: str | None = Header(default=None)) -> dict:
        username, total = await calculate(body, request, authorization)
        order_id = await asyncio.to_thread(request.app.state.store.save_order, username,
                                          [item.model_dump() for item in body.items], total)
        return {"order_id": order_id, "total_cents": total}

    return application


app = build_app()
