FROM node:22.13.0-alpine3.21
RUN apk add --no-cache iproute2
WORKDIR /opt/auth
COPY services/auth/server.js .
ENV NODE_ENV=production
CMD ["node", "server.js"]
