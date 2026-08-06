# Frequently asked questions

## 1. Is Bastión VPN hosted?

No. It is a self-hosted Docker/Compose platform.

## 2. Does it install VPN clients on workstations?

No. VPN engines run inside isolated bastion containers.

## 3. Can two plants use the same private IP range?

Yes, while their routes remain in separate namespaces and the correct plant endpoint is selected.

## 4. Is the whole customer network routed to the host?

No. The intended model is explicit HAProxy publication of selected targets.

## 5. Which engines are present?

The tree contains OpenFortiVPN/PPP, OpenVPN, Libreswan, and strongSwan image variants. Support is engine- and profile-specific.

## 6. Are credentials stored in Git?

Never. Git contains templates and non-secret proxy intent only.

## 7. What is `GUAC_JSON_KEY`?

The shared secret used by the Guacamole JSON authentication integration. Generate and inject it outside Git.

## 8. Can I use another deployment path?

Set `BASTION_PROJECT_ROOT` and validate resulting mounts. The default is `/opt/bastion-vpn`.

## 9. Does `docker compose config` prove a VPN works?

No. Tunnel, SA, interface, route, and target gates are separate.

## 10. Why is this not a complete public demo?

The root Compose file references production-oriented images and external runtime material. A portable synthetic demo is planned.

## 11. Can I expose RDP directly on the host?

Avoid it when Guacamole can reach the plant proxy over the bastion network.

## 12. How are root-relative web apps handled?

Use a dedicated listener or reviewed rewrite strategy when an application assumes `/` as its base path.

## 13. Where are runtime databases backed up?

In the protected deployment backup system with the material required to restore them. Never in Git.

## 14. How do I add a site connection?

Start from `templates/`, generate the overlay and proxy declarations in the protected deployment area, store the real profile externally, validate, start, and run the gates in [CONFIGURATION.md](CONFIGURATION.md). Do not add the generated files or operational data to this repository.

## 15. Does every push deploy production?

No. CI validates source/manifests; promotion is manual and hash-checked.

## 16. What belongs in a bug report?

Only redacted metadata: commit/image tag, engine, safe slug, state, timestamps, and error category.

## 17. Where do I report a vulnerability?

Use the private GitHub security advisory path in [SECURITY.md](../SECURITY.md).

## 18. Is the project licensed?

No open-source license has been declared for Bastión VPN yet. Upstream Guacamole license files remain in its source tree.
