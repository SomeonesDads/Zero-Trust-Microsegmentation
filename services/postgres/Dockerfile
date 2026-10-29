FROM postgres:16.6-alpine3.20
RUN apk add --no-cache iproute2
COPY services/postgres/init.sql /docker-entrypoint-initdb.d/001-shop.sql
