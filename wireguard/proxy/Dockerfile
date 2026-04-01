FROM mitmproxy/mitmproxy:10.4.2

RUN pip install cryptography

COPY scripts/enforcer.py /home/mitmproxy/scripts/enforcer.py
COPY gen-client-conf.py /home/mitmproxy/gen-client-conf.py
