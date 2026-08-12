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
The repository does not install host firewall rules. The monitor receives no
`NET_ADMIN` or Docker-socket access. It drops every capability and adds back
only `NET_RAW`, which is required by the pinned `iputils-ping` ICMP binary and
by `ike-scan=1.9.5-2`. The image contains no VPN authentication material.

Required outbound traffic is limited to:

- ICMP Echo to sanitized public endpoint addresses;
- TCP to the configured public SSL-VPN, OpenVPN TCP, or PPTP control port;
- UDP/500 and, when NAT-T applies, UDP/4500 for credential-free `ike-scan`;
- the configured OpenVPN UDP public port;
- DNS through the deployment-approved resolver;
- HTTP to `panel:5000` only on the internal Compose network.

`NET_RAW` does not replace the host egress policy. Before activation, verify
that the policy blocks private, link-local, CGNAT, metadata, multicast, and
reserved destinations even if DNS changes after configuration.

## Promotion gate

Record, without including secrets, the following before promotion:

1. the monitor container identity and network identity;
2. the enforced deny-list policy identifier and revision;
3. a positive probe to a synthetic public test address;
4. negative probes proving loopback, link-local, RFC1918, CGNAT, multicast,
   and reserved destinations are blocked at the network boundary.

If the host policy cannot be verified independently, leave collection disabled.
