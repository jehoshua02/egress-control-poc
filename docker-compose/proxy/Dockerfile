FROM mitmproxy/mitmproxy:10.4.2

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iptables \
        dnsmasq \
        iproute2 \
        procps \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
COPY dnsmasq.conf /etc/dnsmasq.d/proxy.conf
RUN chmod +x /entrypoint.sh

EXPOSE 8080 8443 8081 53/udp

ENTRYPOINT ["/entrypoint.sh"]
