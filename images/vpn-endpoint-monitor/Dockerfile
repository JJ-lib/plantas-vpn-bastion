# Pinned Bookworm Python runtime shared with the panel image.
FROM python@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    XDG_CACHE_HOME=/tmp

# Debian Bookworm's credential-free IKE scanner, pinned to the package version
# used by this worker. No VPN profile/auth package or Docker CLI is installed.
RUN apt-get update \
    && apt-get install --no-install-recommends --yes \
       ca-certificates \
       ike-scan=1.9.5-3.1+b1 \
    && rm -rf /var/lib/apt/lists/* \
    && addgroup --system --gid 65532 monitor \
    && adduser --system --uid 65532 --gid 65532 --no-create-home monitor \
    && mkdir -p /opt/vpn-endpoint-monitor /tmp \
    && chown -R 65532:65532 /opt/vpn-endpoint-monitor /tmp

WORKDIR /opt/vpn-endpoint-monitor
COPY --chown=65532:65532 panel-app/vpn_endpoint_monitor.py ./vpn_endpoint_monitor.py
USER 65532:65532

ENTRYPOINT ["python", "-u", "vpn_endpoint_monitor.py"]
