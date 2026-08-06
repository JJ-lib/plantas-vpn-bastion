FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates dumb-init haproxy iproute2 iputils-ping openvpn ppp pptp-linux \
 && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /usr/local/bin/access-vpn-entrypoint
RUN chmod 0755 /usr/local/bin/access-vpn-entrypoint
ENTRYPOINT ["/usr/bin/dumb-init", "--", "/usr/local/bin/access-vpn-entrypoint"]
