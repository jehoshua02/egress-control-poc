FROM alpine:3.19

RUN apk add --no-cache \
    ca-certificates \
    curl \
    nmap-ncat \
    bind-tools \
    wireguard-tools \
    iproute2 \
    iptables \
    bash

COPY test.sh /test.sh
RUN chmod +x /test.sh
