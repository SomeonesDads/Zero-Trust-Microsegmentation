FROM redis:7.4.2-alpine
RUN apk add --no-cache iproute2
COPY services/redis/start.sh /usr/local/bin/lab-redis
ENTRYPOINT ["sh", "/usr/local/bin/lab-redis"]
