#!/bin/sh
set -eu
: "${LAB_REDIS_PASSWORD:?LAB_REDIS_PASSWORD is required}"
exec redis-server --bind 0.0.0.0 --protected-mode yes --requirepass "$LAB_REDIS_PASSWORD" --save "" --appendonly no
