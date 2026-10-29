FROM python:3.10.16-alpine3.21
RUN apk add --no-cache iproute2
WORKDIR /opt/decoy
COPY services/decoy/server.py .
CMD ["python", "server.py"]
