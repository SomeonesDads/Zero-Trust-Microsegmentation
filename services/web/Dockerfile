FROM nginx:1.27.3-alpine
RUN apk add --no-cache iproute2
COPY services/web/nginx.conf /etc/nginx/nginx.conf
