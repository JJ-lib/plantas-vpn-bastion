# VPN endpoint monitor egress policy

The endpoint monitor is intentionally attached to a network with outbound
access, but it must not be allowed to reach private or reserved address space.
Application-level DNS validation is not the only control: the deployment host
must enforce the same deny policy at the container-network boundary.

## Required host control

Before enabling `VPN_ENDPOINT_MONITOR_COLLECTION_ENABLED`, the operator must
apply an egress policy for the monitor container or its dedicated network that:

- permits the panel's internal service address and approved public VPN
  endpoints;
- denies loopback, link-local, RFC1918, CGNAT, multicast, and all other
  reserved destinations;
- denies forwarding to the Docker socket, panel database, VPN namespaces, and
  plant-internal networks;
- logs only normalized policy decisions, never packet payloads or credentials.

The Compose labels
`com.plantas-vpn-bastion.egress-policy-required=true` and
`com.plantas-vpn-bastion.monitor-egress-policy=deny-private-linklocal-cgnat-reserved`
are the discovery contract for the host firewall/controller. A deployment
must fail closed if those labels are not mapped to an enforced host policy.
The repository does not install host firewall rules and the monitor container
does not receive `NET_ADMIN`, `NET_RAW`, or Docker-socket access.

## Promotion gate

Record, without including secrets, the following before promotion:

1. the monitor container identity and network identity;
2. the enforced deny-list policy identifier and revision;
3. a positive probe to a synthetic public test address;
4. negative probes proving loopback, link-local, RFC1918, CGNAT, multicast,
   and reserved destinations are blocked at the network boundary.

If the host policy cannot be verified independently, leave collection disabled.

## Repository-provided nftables policy

The generic deployment defines two dedicated networks:

- `vpn_endpoint_monitor_api` (`vpnmon-api0`, internal) carries only the
  authenticated panel/worker API traffic;
- `vpn_endpoint_monitor_egress` (`vpnmon-egress0`) is the worker's only
  external route.

The panel remains on the ordinary bastion network and the internal API
network. The worker is deliberately absent from the ordinary bastion network,
so it cannot address VPN, Guacamole, Caddy, database, or Docker services there.
IPv6 is disabled on both monitor networks.

Install the root-owned host policy before starting or promoting the worker:

```sh
sudo ./scripts/install-vpn-endpoint-monitor-egress.sh
sudo systemctl is-enabled vpn-endpoint-monitor-egress.service
sudo systemctl is-active vpn-endpoint-monitor-egress.service
sudo nft list table inet vpn_endpoint_monitor
```

The unit is required by and ordered before `docker.service`. A rule-load
failure therefore blocks Docker startup instead of leaving the monitor with
unrestricted egress. The firewall matches named bridges, not a transient
container address. It permits established replies and global-unicast IPv4
traffic from the external bridge, denies reserved destinations, denies all
host-local access from either monitor bridge, and prevents cross-network
forwarding into or out of the internal API bridge.

Before installation, validate the exact candidate with:

```sh
sudo nft list table inet vpn_endpoint_monitor >/dev/null 2>&1 || \
  sudo nft add table inet vpn_endpoint_monitor
sudo nft -c -f firewall/vpn-endpoint-monitor.nft
```

For rollback, first disable collection and remove only the monitor container.
Then disable the unit and delete its owned table:

```sh
sudo systemctl disable --now vpn-endpoint-monitor-egress.service
sudo nft delete table inet vpn_endpoint_monitor
```

Do not stop Docker and do not recreate VPN containers merely to roll back this
policy. Keep the service installed while any container remains attached to a
monitor network.