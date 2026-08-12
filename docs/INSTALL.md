# Installation

This guide bootstraps the generic Bastión VPN control plane from a reviewed checkout. It does not create customer credentials, publish operational data, or silently promote a generated site.

## 1. Host prerequisites

- Linux with Docker Engine and Compose v2.
- Network capabilities required by the selected engine: commonly `/dev/net/tun`, `/dev/ppp`, or IPsec kernel support.
- Protected storage for secrets and runtime volumes.
- A change window and rollback path for production.

The root Compose file uses immutable image references for deployed components and builds the Guacamole JSON context locally. Make required images available through the approved registry or image-load process before starting a production host.

## 2. Clone into the deployment path

```bash
sudo install -d -o root -g root /opt/bastion-vpn
git clone https://github.com/juanuto/plantas-vpn-bastion.git /opt/bastion-vpn
cd /opt/bastion-vpn
```

If a different path is required, set `BASTION_PROJECT_ROOT` in `.env`; the example remains `/opt/bastion-vpn`.

## 3. Prepare the environment

```bash
cp .env.example .env
chmod 600 .env
openssl rand -hex 32
```

Place the generated value in `GUAC_JSON_KEY` through the approved secret workflow. Do not paste it into a ticket, shell history, commit, or chat transcript. Generated site profiles, credentials, and proxy declarations are provisioned separately under the protected deployment boundary.

## 4. Validate before starting

```bash
docker compose config --quiet

git rev-parse --verify HEAD
# Validate a deployment-owned generated site overlay, if one exists:
docker compose -f /path/to/deployment/site-overlay.yml config --quiet
```

## 5. Start the control plane

```bash
docker compose up -d
docker compose ps
curl --fail http://127.0.0.1/
```

Use the published TLS/HTTP entrypoint appropriate to your environment. Do not expose the administration plane directly to the Internet without an authentication and network-control review.

## 6. Promote a generated site

1. Confirm the exact repository commit and image digests.
2. Install the protected profile, secret material, and generated overlay outside Git.
3. Validate the generated site overlay.
4. Start only the selected site data plane.
5. Verify tunnel, SA, virtual interface, and expected route gates independently.
6. Test one approved TCP/HTTP target from inside the site namespace.
7. Enable user-facing publication and run one scoped canary.
8. Record the result and retain the previous known-good bundle for rollback.

For endpoint-monitor schema compatibility, coordinated token rotation, scoped
promotion, persistence checks, and rollback, follow the
[endpoint monitor deployment runbook](operations/vpn-endpoint-monitor-deployment.md).

## 7. Verify and observe

```bash
docker compose ps
docker compose logs --tail=200 panel
docker compose logs --tail=200 vpn-reconciler
docker compose logs --tail=200 caddy
```

Logs must be filtered before sharing. Never use an environment dump as a health check.

## Rollback

Stop promotion, restore the previous reviewed bundle, preserve container identities where the operational procedure requires it, and rerun tunnel/SA/interface gates. Do not recreate every VPN container as a generic recovery step.
