FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends strongswan strongswan-swanctl libcharon-extra-plugins libcharon-extauth-plugins libstrongswan-extra-plugins libstrongswan-standard-plugins haproxy iproute2 iputils-ping curl netcat-openbsd procps ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY vpn-supervisor.sh /usr/local/sbin/vpn-supervisor.sh
COPY start-ipsec.sh /usr/local/bin/start-ipsec.sh
RUN chmod 0755 /usr/local/sbin/vpn-supervisor.sh /usr/local/bin/start-ipsec.sh
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD grep -qx online /run/vpn-health || exit 1
CMD ["/usr/local/bin/start-ipsec.sh"]
