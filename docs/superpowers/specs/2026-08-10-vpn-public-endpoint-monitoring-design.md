# VPN Public Endpoint Monitoring Design

**Status:** Proposed and approved for implementation planning  
**Date:** 2026-08-10  
**Scope:** Generic Bastion VPN control plane

## 1. Purpose

Operators need to distinguish two materially different failure domains when a VPN is offline:

1. the public VPN gateway or its network path is not responding; or
2. the public gateway is reachable, but the local client, authentication, proposals, generated configuration, container, tunnel, routes, or target validation failed.

The control plane will add a small, read-only monitoring subsystem that probes each active VPN's public endpoint every five minutes. It will never authenticate, change a VPN record, restart a container, or modify the onboarding/runtime state. Its result is diagnostic evidence displayed on the corresponding site card to administrators and ordinary users.

## 2. Goals

- Probe active public VPN endpoints every five minutes without relying on ICMP.
- Use a transport- or protocol-aware probe instead of treating every VPN as TCP.
- Raise a visible site-card alert after two consecutive conclusive failures.
- Clear the alert after the first conclusive successful probe.
- Keep public-endpoint health separate from tunnel/runtime health.
- Give administrators more diagnostic detail without exposing gateway addresses to ordinary users.
- Persist the latest health state and transition timestamps across restarts.
- Operate with no VPN credentials, profile files, Docker socket, or access to the panel database.
- Fail safely: monitor failure must not change or restart any VPN.

## 3. Non-goals

The first release will not:

- restart VPNs automatically;
- send email, chat, webhook, or pager notifications;
- provide long-term charts or a full time-series database;
- prove that protected equipment behind the tunnel is reachable;
- treat an ICMP echo response as proof that a VPN service is available;
- claim that PPTP GRE works merely because TCP/1723 accepts a connection;
- classify a silent generic UDP service as down when the protocol cannot produce a conclusive response;
- expose public gateway hostnames or addresses to non-administrators.

## 4. Terminology and evidence precedence

The feature must use precise terms:

- **Public endpoint health:** whether the configured public VPN service produced a conclusive protocol/transport response.
- **Tunnel health:** whether the local VPN runtime has established the required interface, SA, routes, or selectors.
- **Target health:** whether an optional protected target is reachable through the tunnel.

A public endpoint probe is supporting diagnostic evidence, not a replacement for the existing runtime validation. Evidence precedence is:

1. an already-established healthy tunnel is stronger evidence than a failed external probe;
2. a successful public probe does not prove authentication or tunnel establishment;
3. a failed public probe after two consecutive checks indicates a likely remote gateway, firewall, DNS, or Internet-path problem;
4. an inconclusive UDP probe must not be converted into a failure.

## 5. Architecture

### 5.1 Components

Add a dedicated `vpn-endpoint-monitor` service. It runs a small Python worker from the control-plane image (or a purpose-built minimal image) and has outbound network access.

The monitor must not mount:

- `/var/run/docker.sock`;
- panel data volumes;
- project configuration directories;
- VPN profiles, generated secrets, or deployment credentials.

The monitor communicates with the panel over the internal Compose network through two authenticated internal endpoints:

- `GET /internal/vpn-endpoint-monitor/targets`
- `POST /internal/vpn-endpoint-monitor/results`

Caddy must deny external access to `/internal/`. The panel must independently authenticate both endpoints with a deployment-provided monitor token read from an external secret file and compared in constant time. Caddy filtering is defense in depth, not the authentication boundary.

### 5.2 Safe target contract

The target endpoint returns only the fields needed for probing:

- VPN ID;
- opaque target revision;
- VPN type;
- host;
- port;
- relevant public transport (`tcp` or `udp`);
- IKE version and aggressive/main mode where applicable;
- whether NAT-T probing is applicable.

It must not return usernames, passwords, PSKs, certificates, profile content, internal selectors, target equipment, or encrypted fields.

Only active VPN records are included. Draft onboarding records continue using the existing isolated onboarding validation path.

The target revision is derived from the probe-relevant configuration. Results carrying a stale revision are rejected, preventing an in-flight result from being stored after an administrator edits the endpoint.

### 5.3 Result contract

Each result contains:

- VPN ID;
- target revision;
- probe type;
- outcome: `reachable`, `unreachable`, or `inconclusive`;
- normalized public code;
- bounded latency in milliseconds when meaningful;
- worker observation timestamp.

The monitor never posts raw subprocess output, packets, exception messages, DNS responses, addresses, or endpoint banners. The panel validates every field and owns all state transitions and counters.

## 6. Probe strategy

Every cycle starts immediately when the worker launches and then repeats every 300 seconds. A cycle applies a small random jitter and uses at most four concurrent probes. Each network attempt has a three-second timeout and bounded retries within the cycle.

Before probing, DNS names are resolved. Only global unicast addresses are eligible. Loopback, link-local, private, carrier-grade NAT, multicast, unspecified, and reserved destinations are rejected as `inconclusive/private_or_reserved_destination`. This prevents the feature from becoming an internal port scanner.

When a hostname resolves to multiple eligible addresses, the endpoint is reachable if any eligible address produces a conclusive success. The result is unreachable only when all eligible addresses produce conclusive failures.

### 6.1 Fortinet SSL VPN

Use a TCP connect probe to the configured host and port.

- completed TCP handshake: `reachable/tcp_accept`;
- refused, timed out, or unreachable across all eligible addresses: `unreachable/tcp_unreachable`;
- DNS or policy problem: normalized DNS/policy outcome.

The probe does not perform TLS authentication or submit VPN credentials.

### 6.2 OpenVPN over TCP

Use the same bounded TCP connect probe.

A successful handshake proves only that a service accepts TCP connections on that endpoint.

### 6.3 PPTP

Probe TCP/1723, or the explicitly configured PPTP control port when supported by the model.

The UI and diagnostic text must state that this validates only the PPTP control socket; it does not validate GRE forwarding or tunnel establishment.

### 6.4 IPsec IKEv1/IKEv2

Use a protocol-aware IKE probe rather than TCP or generic UDP. The implementation may use a pinned `ike-scan` package in the monitor image, with:

- the configured IKE version;
- IKE aggressive mode when configured;
- destination UDP/500;
- a NAT-T UDP/4500 attempt when applicable;
- tightly bounded timeout and retry values;
- no authentication material.

Any syntactically valid IKE response, including a normalized notification response, proves that the public IKE endpoint replied and is `reachable/ike_response`. Silence after the bounded attempts is `unreachable/ike_no_response` only when the selected probe is considered conclusive for that configuration.

The implementation must validate the exact `ike-scan` version and invocation in automated tests. It must not parse or store raw responder payloads.

### 6.5 OpenVPN over UDP

A generic UDP connect does not prove that a port is open. The monitor may use a protocol-specific, credential-free OpenVPN reset/handshake probe if the implementation can verify it against supported OpenVPN versions.

Until such a probe is proven reliable:

- a protocol response is `reachable/openvpn_udp_response`;
- an explicit ICMP port-unreachable response is `unreachable/udp_port_unreachable`;
- silence is `inconclusive/udp_silent` and never increments the failure counter.

## 7. Persistence and state transitions

Add a `vpn_endpoint_health` table owned by the panel:

- `vpn_id` (primary key);
- `target_revision`;
- `probe_type`;
- `state` (`healthy`, `suspect`, `down`, `unknown`, `stale`, `disabled`);
- `public_code`;
- `consecutive_failures`;
- `first_failure_at`;
- `last_checked_at`;
- `last_success_at`;
- `last_transition_at`;
- `latency_ms`.

State transitions are atomic:

- conclusive success → `healthy`, reset failures and clear `first_failure_at`;
- first conclusive failure → `suspect`, failures = 1, no user alert;
- second consecutive conclusive failure → `down`, failures = 2, alert eligible;
- additional conclusive failures → remain `down`, increment with a safe cap;
- inconclusive → retain the last conclusive health state but update the observation code; do not increment failures;
- endpoint revision change → reset to `unknown` before accepting results for the new target;
- inactive/deleted VPN → remove or mark the health record `disabled`.

With five-minute polling, two consecutive scheduled failures normally surface an outage within approximately five to ten minutes, depending on when the remote failure begins relative to the schedule.

A result older than 15 minutes is `stale`. Staleness is an administrative monitoring warning, not a public claim that the VPN gateway is down.

## 8. User interface

### 8.1 Site cards for all users

When all of the following are true:

- public endpoint state is `down`;
- at least two consecutive conclusive failures exist;
- the existing tunnel/runtime state is offline;

show a compact alert on the corresponding site card:

> Public VPN gateway is not responding

The localized Spanish production label may be:

> El servidor público de la VPN no responde

Ordinary users see no hostname, address, port, latency, probe command, or raw diagnostic.

If the tunnel is online, suppress the public alert because established tunnel evidence takes precedence. Administrators may still see a non-blocking probe discrepancy.

### 8.2 Administrative VPN table

Add a compact public-endpoint column or detail block with:

- healthy/suspect/down/unknown/stale state;
- probe type;
- consecutive failure count;
- last check time;
- last successful check time;
- last latency where meaningful;
- normalized explanation.

The endpoint itself may remain visible to administrators because it is already shown in the current VPN administration table.

### 8.3 Diagnostic matrix

| Tunnel/runtime | Public endpoint | Displayed interpretation |
|---|---|---|
| Online | Reachable | Normal |
| Offline | Reachable | Gateway responds; inspect local runtime, authentication, proposals, configuration, or routing |
| Offline | Down | Possible remote VPN server, firewall, DNS, or Internet-path outage |
| Offline | Unknown/stale | Insufficient external evidence |
| Online | Down | Tunnel evidence wins; suppress user alert and show an administrator-only discrepancy |

## 9. Security and operational controls

- External monitor token supplied through an external Docker secret, never committed or logged.
- Internal endpoints blocked at Caddy and authenticated in Flask.
- Constant-time token comparison.
- Strict response/request schemas and body-size limits.
- No Docker socket or panel database mount in the worker.
- No VPN credentials, certificates, profiles, or internal target information in the worker.
- Global-unicast destination enforcement after DNS resolution.
- Bounded concurrency, timeouts, retries, and result sizes.
- Sanitized error codes only; no raw scanner output in SQLite or UI.
- Read-only root filesystem, dropped Linux capabilities, and non-root worker where possible. If binding a privileged IKE source port is required, add only `NET_BIND_SERVICE`; do not run privileged.
- The worker must never call VPN restart, pause, activation, generation, or reconciliation paths.

## 10. Failure handling

- Monitor unavailable: existing VPN operation is unaffected; health becomes stale after 15 minutes.
- Panel unavailable: worker retries the next cycle with bounded backoff and stores no unbounded local queue.
- Invalid/stale target revision: panel rejects the result; worker refreshes targets next cycle.
- DNS returns only non-global addresses: inconclusive policy result, no down alert.
- Probe tool crashes or is missing: administrative `probe_error`/stale indication, no public down alert.
- Database migration failure: panel startup fails closed with the existing migration error path; no partial health schema is used.

## 11. Deployment and rollback

The feature is delivered through the existing manual, immutable-image promotion workflow:

1. migrate the panel schema;
2. deploy the updated panel and Caddy internal-route policy;
3. add the monitor secret;
4. start the monitor service with an immutable image;
5. verify one safe synthetic/canary endpoint before enabling card alerts;
6. observe at least two cycles;
7. enable display for all active VPNs.

Rollback stops/removes only the monitor service and reverts the panel/Caddy image references. The health table may remain unused; rollback must not alter VPN configuration or runtime containers.

## 12. Testing strategy

Automated tests must cover:

- schema migration and idempotency;
- target API redaction and active-only filtering;
- internal authentication and Caddy external blocking;
- stale revision rejection;
- TCP success, refusal, timeout, DNS failure, and multi-address behavior;
- global-unicast destination policy;
- IKEv1, IKEv1 aggressive, IKEv2, and NAT-T command/result normalization;
- UDP silence remaining inconclusive;
- two-failure transition to `down`;
- first-success recovery to `healthy`;
- inconclusive results not incrementing failures;
- stale monitor behavior;
- user-card alert visibility and absence of endpoint details;
- administrator diagnostic detail;
- tunnel-online precedence suppressing the user alert;
- worker running without Docker socket/database access;
- full existing Linux suite, Compose validation, ShellCheck, and secret scanning.

Integration tests use documentation-only addresses and fake probe runners. They must never contact real customer endpoints.

## 13. Acceptance criteria

The feature is acceptable when:

1. every active supported VPN receives a probe attempt every five minutes;
2. two consecutive conclusive endpoint failures produce `down` state;
3. a down endpoint plus offline tunnel shows an alert on that site's card to administrators and authorized users;
4. the alert contains no gateway details for ordinary users;
5. one successful probe clears the alert;
6. inconclusive UDP silence never produces a down alert;
7. an online tunnel suppresses the ordinary-user endpoint alert;
8. no probe changes, restarts, pauses, activates, or regenerates a VPN;
9. the monitor has no Docker socket, panel database, VPN profile, or VPN credential access;
10. all existing and new tests pass against the exact immutable release candidate.

## 13. Security review gates before implementation

The following gates are mandatory additions to this design. They override any earlier wording that permits a weaker implementation:

- **DNS rebinding and SSRF:** resolve each hostname once per probe, validate every returned address as a global unicast address, and probe only the exact vetted numeric address. TCP sockets must use numeric-address resolution; subprocess probes must receive the numeric IP, never the original hostname. Reject IPv4-mapped IPv6 private/reserved addresses. The monitor deployment must also have host/network egress policy denying private, link-local, metadata, CGNAT, multicast, and reserved ranges.
- **IKE evidence:** IKE silence is `inconclusive` unless the exact pinned implementation, source-port behavior, timeout conversion, and configured proposal set make the result conclusive. `ike-scan` timeout values must be converted explicitly from seconds to milliseconds. Source-port-500 probes are serialized and require the minimum capability; unsupported or incomplete proposals cannot produce `down`.
- **Ordering and idempotency:** endpoint configuration has a monotonic generation, and every accepted result carries a panel-issued cycle/lease identifier. The panel accepts at most one result per VPN, generation, and cycle slot, rejects older cycles atomically, and makes duplicate submissions idempotent. Panel acceptance time is stored separately from worker observation time.
- **Freshness:** `last_accepted_at` and `last_conclusive_at` are distinct. Public alerts require two fresh conclusive failures from distinct cycles. DNS/system/tool failures and UDP silence are inconclusive and cannot preserve a public alert indefinitely; systemic monitor failures trigger monitor-health suppression.
- **SQLite concurrency:** every connection configures WAL and `busy_timeout`; state transitions use `BEGIN IMMEDIATE` or an equivalent conditional UPSERT with generation/cycle predicates. File-backed multi-connection and concurrent schema-start tests are required.
- **Promotion safety:** collection, administrator diagnostics, and ordinary-user card alerts have independent feature flags. `VPN_ENDPOINT_PUBLIC_ALERTS_ENABLED` defaults to `false`. Canary mode accepts an explicit approved target selector and never creates a synthetic production `vpns` row.
- **Secrets and ingress:** the Compose secret mechanism must specify UID/GID, mode, readability by the non-root monitor, and rotation. Flask authentication remains mandatory. Caddy denies the internal API before imports/catch-all routes; black-box tests cover methods, encoded paths, doubled slashes, and route ordering.
- **Rollback:** routine rollback removes only monitor artifacts and leaves the additive health table in place. It must not restore the whole panel database or erase concurrent VPN/equipment changes. SQLite backups use the supported backup mechanism, and unrelated container IDs/restart counts are verified unchanged.
