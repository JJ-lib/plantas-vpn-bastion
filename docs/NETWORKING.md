# Networking

The networking model is based on namespace isolation and explicit proxy publication.

## Network layers

| Layer | Role |
| --- | --- |
| Host | Runs Docker and central ingress; should not acquire every customer route. |
| Bastion network | Connects Caddy, panel, Guacamole, guacd, and selected proxy endpoints. |
| Plant namespace | Owns the VPN interface, remote routes, and plant-local HAProxy listeners. |
| Customer network | Remote service space reached through the plant tunnel. |

## Overlapping address space

Overlapping private ranges are safe only while route tables remain isolated. Do not connect two plant namespaces to one shared L3 network or add broad host routes as a shortcut. Identify duplicate addresses by plant slug and proxy endpoint.

## Publication model

```text
bastion listener -> plant HAProxy listener -> customer target
```

For HTTP, include the correct path, redirect, WebSocket, and TLS behavior. For TCP, use a dedicated listener and `mode tcp`.

## Reachability checks

```bash
docker compose ps
docker compose config --quiet
# If a deployment-owned generated overlay exists:
docker compose -f /path/to/deployment/site-overlay.yml config --quiet
```

A central TCP connection to a proxy proves only the proxy listener. It does not prove tunnel or target reachability. Validate central-to-proxy, namespace-to-target, tunnel/SA/interface, then application behavior.

## Ports, DNS, and TLS

Keep host-facing ports documented in non-secret proxy declarations. Do not publish a plant RDP listener on the host when Guacamole can reach it over the bastion network. Document whether TLS is end-to-end, re-encrypted, or intentionally not verified for a legacy target. Treat `verify none` as a reviewed exception, never a default.

## Common mistakes

- Testing from the host instead of the plant namespace.
- Adding host routes to compensate for a missing namespace.
- Publishing a root-relative web application under a subpath.
- Reusing a proxy port across plant projects.
- Assuming `docker compose ps` proves the remote service is reachable.
