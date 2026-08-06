FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       openfortivpn ppp haproxy socat ca-certificates curl iproute2 iputils-ping netcat-openbsd procps \
    && rm -rf /var/lib/apt/lists/*

COPY start-site.sh /usr/local/bin/start-site.sh
RUN chmod +x /usr/local/bin/start-site.sh

ENTRYPOINT ["/usr/local/bin/start-site.sh"]
