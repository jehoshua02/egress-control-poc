FROM alpine:3.19

RUN apk add --no-cache \
    ca-certificates \
    curl \
    nmap-ncat \
    bind-tools

COPY test.sh /test.sh
RUN chmod +x /test.sh
