"""Bounded, protocol-aware probes for public VPN endpoints.

This module is deliberately stateless.  It accepts the already-sanitized target
contract from the panel, performs one bounded probe, and returns only the
normalized result DTO used by ``vpn_endpoint_health``.  DNS, sockets, and the
``ike-scan`` subprocess are dependency-injected in tests; no VPN credentials or
raw diagnostic material is ever returned.
"""

from __future__ import annotations

import errno
import inspect
import ipaddress
import math
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping


MAX_HOST_LENGTH = 253
MIN_PORT = 1
MAX_PORT = 65_535
MAX_PROBE_TIMEOUT_SECONDS = 3.0
MAX_RETRIES = 2
MAX_LATENCY_MS = 60_000
MAX_TARGET_REVISION_LENGTH = 64
MAX_TARGET_GENERATION = 2**63 - 1
MAX_CYCLE_ID = 2**63 - 1
MAX_LEASE_ID_LENGTH = 128
MAX_VPN_ID = 2**63 - 1
MAX_DNS_ANSWERS = 32
MAX_UDP_RESPONSE_BYTES = 4_096
MAX_SCANNER_OUTPUT_BYTES = 64 * 1024

DEFAULT_PROBE_TIMEOUT_SECONDS = MAX_PROBE_TIMEOUT_SECONDS
DEFAULT_RETRIES = 1

SUPPORTED_VPN_TYPES = frozenset({"ssl", "openvpn", "pptp", "ipsec"})
SUPPORTED_TRANSPORTS = frozenset({"tcp", "udp"})
SUPPORTED_PROBE_TYPES = frozenset({"tcp_connect", "ike", "openvpn_udp"})
OUTCOMES = frozenset({"reachable", "unreachable", "inconclusive"})
RESULT_FIELDS = (
    "vpn_id",
    "target_revision",
    "target_generation",
    "cycle_id",
    "lease_id",
    "probe_type",
    "outcome",
    "public_code",
    "latency_ms",
    "observed_at",
)

_REVISION_RE = re.compile(r"[0-9a-f]{64}\Z")
_HOSTNAME_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_PUBLIC_CODES = frozenset(
    {
        "tcp_accept",
        "tcp_unreachable",
        "ike_response",
        "ike_no_response",
        "openvpn_udp_response",
        "udp_port_unreachable",
        "udp_silent",
        "dns_failed",
        "dns_failure",
        "dns_timeout",
        "dns_no_answers",
        "dns_no_global_address",
        "private_or_reserved_destination",
        "probe_error",
        "unsupported_probe",
    }
)

# A small credential-free OpenVPN control packet.  It is not an authenticated
# handshake and contains no profile, username, password, key, or PSK material.
_OPENVPN_UDP_PROBE_PAYLOAD = b"\x07\x00" + (b"\x00" * 8)

_IKE_RESPONSE_PATTERNS = (
    re.compile(r"\bhandshake\s+returned\b", re.IGNORECASE),
    re.compile(r"\bnotify\s+(?:message|response)\b", re.IGNORECASE),
    re.compile(r"\bnotification\s+(?:message|response)\b", re.IGNORECASE),
    re.compile(r"\bikev?[12]?\s+(?:response|notify|notification)\b", re.IGNORECASE),
)


class _ResolutionProblem(Exception):
    """Internal, non-public DNS/policy classification."""

    def __init__(self, public_code: str):
        super().__init__()
        self.public_code = public_code


@dataclass(frozen=True)
class ProbeLimits:
    """Hard limits shared by every probe path."""

    timeout_seconds: float = DEFAULT_PROBE_TIMEOUT_SECONDS
    retries: int = DEFAULT_RETRIES
    max_latency_ms: int = MAX_LATENCY_MS

    def __post_init__(self) -> None:
        timeout = self.timeout_seconds
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise ValueError("timeout_seconds must be numeric.")
        if not math.isfinite(float(timeout)) or not 0 < float(timeout) <= MAX_PROBE_TIMEOUT_SECONDS:
            raise ValueError("timeout_seconds is outside the hard limit.")

        retries = self.retries
        if isinstance(retries, bool) or not isinstance(retries, int):
            raise ValueError("retries must be an integer.")
        if not 1 <= retries <= MAX_RETRIES:
            raise ValueError("retries is outside the hard limit.")

        latency = self.max_latency_ms
        if isinstance(latency, bool) or not isinstance(latency, int):
            raise ValueError("max_latency_ms must be an integer.")
        if not 0 <= latency <= MAX_LATENCY_MS:
            raise ValueError("max_latency_ms is outside the hard limit.")


class _SystemClock:
    @staticmethod
    def time() -> float:
        return time.time()

    @staticmethod
    def monotonic() -> float:
        return time.monotonic()


_SYSTEM_CLOCK = _SystemClock()


def _strict_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer.")
    if not minimum <= value <= maximum:
        raise ValueError(f"{label} is outside the accepted range.")
    return value


def _bounded_text(value: Any, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise ValueError(f"{label} is outside the accepted length.")
    if any(ord(character) < 33 or ord(character) == 127 for character in value):
        raise ValueError(f"{label} contains a forbidden character.")
    return value


def _normalize_host(value: Any) -> str:
    host = _bounded_text(value, "host", MAX_HOST_LENGTH).strip().lower()
    if host.endswith("."):
        host = host[:-1]
    if not host or len(host) > MAX_HOST_LENGTH or "%" in host:
        raise ValueError("host is invalid.")

    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        parsed = None

    if parsed is not None:
        mapped = getattr(parsed, "ipv4_mapped", None)
        return str(mapped or parsed)

    # Hostnames are deliberately ASCII-only.  The panel can provide an IDNA
    # normalized name; accepting arbitrary Unicode here would make the command
    # and resolver boundaries harder to audit.
    if not host.isascii() or ":" in host or "/" in host or "\\" in host or "@" in host:
        raise ValueError("host is invalid.")
    labels = host.split(".")
    if any(not label or len(label) > 63 or not _HOSTNAME_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("host is invalid.")
    return host


def _safe_revision(value: Any) -> str:
    if isinstance(value, str) and _REVISION_RE.fullmatch(value):
        return value
    return "0" * MAX_TARGET_REVISION_LENGTH


def _safe_vpn_id(value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= MAX_VPN_ID:
        return value
    return 0


def _raw_target_value(target: Any, key: str, default: Any = None) -> Any:
    if isinstance(target, Mapping):
        return target.get(key, default)
    return default


def validate_target(target: Any) -> dict[str, Any]:
    """Validate and copy the bounded, non-secret target contract.

    Unsupported VPN types remain structurally valid so the dispatcher can
    return ``unsupported_probe`` rather than raising or probing an unknown
    protocol.  The returned copy contains no input object references.
    """

    if not isinstance(target, Mapping):
        raise ValueError("target must be a mapping.")

    vpn_id = _strict_int(target.get("vpn_id"), "vpn_id", 1, MAX_VPN_ID)
    revision = target.get("target_revision")
    if not isinstance(revision, str) or not _REVISION_RE.fullmatch(revision):
        raise ValueError("target_revision is invalid.")
    target_generation = _strict_int(target.get("target_generation"), "target_generation", 0, MAX_TARGET_GENERATION)
    cycle_id = _strict_int(target.get("cycle_id"), "cycle_id", 0, MAX_CYCLE_ID)
    lease_id = target.get("lease_id")
    if not isinstance(lease_id, str) or not 1 <= len(lease_id) <= MAX_LEASE_ID_LENGTH or not lease_id.isascii():
        raise ValueError("lease_id is invalid.")

    vpn_type = _bounded_text(target.get("vpn_type"), "vpn_type", 32).lower()
    transport = _bounded_text(target.get("transport"), "transport", 16).lower()
    if transport not in SUPPORTED_TRANSPORTS:
        raise ValueError("transport is invalid.")

    host = _normalize_host(target.get("host"))
    port = _strict_int(target.get("port"), "port", MIN_PORT, MAX_PORT)

    normalized: dict[str, Any] = {
        "vpn_id": vpn_id,
        "target_revision": revision,
        "target_generation": target_generation,
        "cycle_id": cycle_id,
        "lease_id": lease_id,
        "vpn_type": vpn_type,
        "host": host,
        "port": port,
        "transport": transport,
    }

    if vpn_type == "ipsec":
        ike_version = target.get("ike_version", "ikev1")
        if not isinstance(ike_version, str) or ike_version.lower() not in {"ikev1", "ikev2"}:
            raise ValueError("ike_version is invalid.")
        aggressive = target.get("aggressive", False)
        nat_t = target.get("nat_t", target.get("nat_traversal", False))
        if not isinstance(aggressive, bool) or not isinstance(nat_t, bool):
            raise ValueError("IKE mode flags are invalid.")
        normalized.update(
            ike_version=ike_version.lower(),
            aggressive=aggressive if ike_version.lower() == "ikev1" else False,
            nat_t=nat_t,
        )

    return normalized


def _normalized_ip(value: Any) -> str | None:
    try:
        parsed = ipaddress.ip_address(value)
    except (TypeError, ValueError):
        return None
    mapped = getattr(parsed, "ipv4_mapped", None)
    return str(mapped or parsed)


def is_global_unicast(address: Any) -> bool:
    """Return whether an address is safe to probe as a public destination."""

    normalized = _normalized_ip(address)
    if normalized is None:
        return False
    parsed = ipaddress.ip_address(normalized)
    return bool(
        parsed.is_global
        and not parsed.is_loopback
        and not parsed.is_link_local
        and not parsed.is_private
        and not parsed.is_multicast
        and not parsed.is_unspecified
        and not parsed.is_reserved
    )


def _default_resolver(host: str, port: int, timeout_seconds: float) -> list[Any]:
    """Resolve in a daemon worker so the default resolver has a hard deadline."""

    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="vpn-dns")
    future = executor.submit(socket.getaddrinfo, host, port, 0, 0, 0)
    try:
        return future.result(timeout=timeout_seconds)
    except FutureTimeoutError as exc:
        future.cancel()
        raise socket.timeout() from exc
    finally:
        # A platform resolver may not be cancellable.  Do not let a stuck DNS
        # worker extend the probe deadline or block shutdown of this worker.
        executor.shutdown(wait=False, cancel_futures=True)


def _call_with_supported_arity(function: Callable[..., Any], args: tuple[Any, ...]) -> Any:
    """Call an injected function without swallowing its internal TypeErrors."""

    try:
        signature = inspect.signature(function)
    except (TypeError, ValueError):
        return function(*args)

    positional = [
        parameter
        for parameter in signature.parameters.values()
        if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
    ]
    has_varargs = any(
        parameter.kind == parameter.VAR_POSITIONAL
        for parameter in signature.parameters.values()
    )
    if has_varargs or len(positional) >= len(args):
        return function(*args)
    return function(*args[: len(positional)])


def _resolver_function(resolver: Any) -> Callable[..., Any]:
    if resolver is None:
        return _default_resolver
    if callable(resolver):
        return resolver
    for name in ("resolve", "getaddrinfo"):
        candidate = getattr(resolver, name, None)
        if callable(candidate):
            return candidate
    raise ValueError("resolver is not callable.")


def _address_from_answer(answer: Any) -> str | None:
    if isinstance(answer, str):
        return answer
    if isinstance(answer, Mapping):
        candidate = answer.get("address")
        return candidate if isinstance(candidate, str) else None
    if isinstance(answer, (tuple, list)):
        # socket.getaddrinfo records place the sockaddr at index 4.
        if len(answer) >= 5 and isinstance(answer[4], (tuple, list)) and answer[4]:
            candidate = answer[4][0]
            return candidate if isinstance(candidate, str) else None
        if answer and isinstance(answer[0], str):
            return answer[0]
    return None


def _resolve_global_addresses(
    host: str,
    port: int,
    *,
    resolver: Any,
    timeout_seconds: float,
) -> list[str]:
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        normalized = str(literal)
        if not is_global_unicast(normalized):
            raise _ResolutionProblem("private_or_reserved_destination")
        return [normalized]

    function = _resolver_function(resolver)
    try:
        answers = _call_with_supported_arity(function, (host, port, timeout_seconds))
    except (socket.timeout, TimeoutError):
        raise _ResolutionProblem("dns_timeout") from None
    except socket.gaierror:
        raise _ResolutionProblem("dns_failed") from None
    except OSError:
        raise _ResolutionProblem("dns_failure") from None
    except Exception:
        raise _ResolutionProblem("dns_failure") from None

    if answers is None:
        raise _ResolutionProblem("dns_no_answers")
    if isinstance(answers, (str, bytes, Mapping)):
        answers = [answers]
    try:
        iterable = list(answers)
    except (TypeError, ValueError):
        raise _ResolutionProblem("dns_failure") from None
    if len(iterable) > MAX_DNS_ANSWERS:
        # Do not let a malicious/custom resolver turn this worker into an
        # unbounded scanner.  A bounded prefix cannot prove all failures.
        raise _ResolutionProblem("dns_failure")
    if not iterable:
        raise _ResolutionProblem("dns_no_answers")

    eligible: list[str] = []
    seen: set[str] = set()
    for answer in iterable:
        candidate = _address_from_answer(answer)
        if candidate is None:
            continue
        normalized = _normalized_ip(candidate)
        if normalized is None:
            continue
        if is_global_unicast(normalized) and normalized not in seen:
            eligible.append(normalized)
            seen.add(normalized)

    if not eligible:
        raise _ResolutionProblem("private_or_reserved_destination")
    return eligible


def _eligible_supplied_addresses(addresses: Iterable[str]) -> list[str]:
    """Re-apply the global-unicast policy to injected/pre-resolved addresses."""

    if isinstance(addresses, (str, bytes)):
        raise _ResolutionProblem("private_or_reserved_destination")
    try:
        supplied = list(addresses)
    except (TypeError, ValueError):
        raise _ResolutionProblem("private_or_reserved_destination") from None
    if len(supplied) > MAX_DNS_ANSWERS:
        raise _ResolutionProblem("dns_failure")

    eligible: list[str] = []
    seen: set[str] = set()
    for candidate in supplied:
        if not isinstance(candidate, str):
            continue
        normalized = _normalized_ip(candidate)
        if normalized is None:
            continue
        if is_global_unicast(normalized) and normalized not in seen:
            eligible.append(normalized)
            seen.add(normalized)
    if not eligible:
        raise _ResolutionProblem("private_or_reserved_destination")
    return eligible


def resolve_global_addresses(
    host: Any,
    *,
    port: int = 0,
    resolver: Any = None,
    timeout_seconds: float = DEFAULT_PROBE_TIMEOUT_SECONDS,
) -> list[str]:
    """Resolve a host and return only de-duplicated global-unicast addresses."""

    normalized_host = _normalize_host(host)
    normalized_port = _strict_int(port, "port", 0, MAX_PORT)
    limits = ProbeLimits(timeout_seconds=timeout_seconds)
    return _resolve_global_addresses(
        normalized_host,
        normalized_port,
        resolver=resolver,
        timeout_seconds=float(limits.timeout_seconds),
    )


def _clock_time(clock: Any) -> float:
    source = _SYSTEM_CLOCK if clock is None else clock
    function = getattr(source, "time", None)
    if callable(function):
        return float(function())
    if callable(source):
        return float(source())
    raise ValueError("clock is not callable.")


def _clock_monotonic(clock: Any) -> float:
    source = _SYSTEM_CLOCK if clock is None else clock
    function = getattr(source, "monotonic", None)
    if callable(function):
        return float(function())
    return _clock_time(source)


def _safe_observed_at(clock: Any) -> int:
    try:
        value = _clock_time(clock)
    except Exception:
        return 0
    if not math.isfinite(value):
        return 0
    integer = int(value)
    if not 0 <= integer <= 253_402_300_799:
        return 0
    return integer


def _bounded_latency_ms(clock: Any, started: float, maximum: int) -> int | None:
    try:
        elapsed = _clock_monotonic(clock) - started
    except Exception:
        return None
    if not math.isfinite(elapsed) or elapsed < 0:
        return None
    latency = int(round(elapsed * 1000))
    if not 0 <= latency <= maximum:
        return None
    return latency


def _probe_type_for(target: Mapping[str, Any]) -> str | None:
    vpn_type = target.get("vpn_type")
    transport = target.get("transport")
    if vpn_type == "ipsec" and transport == "udp":
        return "ike"
    if vpn_type in {"ssl", "pptp"} and transport == "tcp":
        return "tcp_connect"
    if vpn_type == "openvpn" and transport == "tcp":
        return "tcp_connect"
    if vpn_type == "openvpn" and transport == "udp":
        return "openvpn_udp"
    return None


def _safe_probe_type(target: Any) -> str:
    if isinstance(target, Mapping):
        candidate = _probe_type_for(target)
        if candidate is not None:
            return candidate
        if target.get("vpn_type") == "ipsec":
            return "ike"
        if target.get("transport") == "udp" and target.get("vpn_type") == "openvpn":
            return "openvpn_udp"
    return "tcp_connect"


def _dto(
    target: Any,
    *,
    outcome: str,
    public_code: str,
    latency_ms: int | None,
    clock: Any,
    probe_type: str | None = None,
) -> dict[str, Any]:
    safe_outcome = outcome if outcome in OUTCOMES else "inconclusive"
    safe_code = public_code if public_code in _PUBLIC_CODES else "probe_error"
    safe_latency = latency_ms if isinstance(latency_ms, int) and not isinstance(latency_ms, bool) else None
    if safe_latency is not None and not 0 <= safe_latency <= MAX_LATENCY_MS:
        safe_latency = None
    return {
        "vpn_id": _safe_vpn_id(_raw_target_value(target, "vpn_id")),
        "target_revision": _safe_revision(_raw_target_value(target, "target_revision")),
        "target_generation": _strict_int(_raw_target_value(target, "target_generation", 0), "target_generation", 0, MAX_TARGET_GENERATION) if isinstance(_raw_target_value(target, "target_generation", 0), int) and not isinstance(_raw_target_value(target, "target_generation", 0), bool) and 0 <= _raw_target_value(target, "target_generation", 0) <= MAX_TARGET_GENERATION else 0,
        "cycle_id": _strict_int(_raw_target_value(target, "cycle_id", 0), "cycle_id", 0, MAX_CYCLE_ID) if isinstance(_raw_target_value(target, "cycle_id", 0), int) and not isinstance(_raw_target_value(target, "cycle_id", 0), bool) and 0 <= _raw_target_value(target, "cycle_id", 0) <= MAX_CYCLE_ID else 0,
        "lease_id": _raw_target_value(target, "lease_id", "") if isinstance(_raw_target_value(target, "lease_id", ""), str) and 1 <= len(_raw_target_value(target, "lease_id", "")) <= MAX_LEASE_ID_LENGTH and _raw_target_value(target, "lease_id", "").isascii() else "invalid",
        "probe_type": probe_type or _safe_probe_type(target),
        "outcome": safe_outcome,
        "public_code": safe_code,
        "latency_ms": safe_latency,
        "observed_at": _safe_observed_at(clock),
    }


def _connector_function(connector: Any) -> Callable[..., Any]:
    if connector is None:
        return socket.create_connection
    if callable(connector):
        return connector
    candidate = getattr(connector, "create_connection", None)
    if callable(candidate):
        return candidate
    raise ValueError("tcp connector is not callable.")


def _connect(connector: Any, address: str, port: int, timeout_seconds: float) -> Any:
    function = _connector_function(connector)
    if function is socket.create_connection:
        return function((address, port), timeout=timeout_seconds)
    try:
        signature = inspect.signature(function)
        positional = [
            parameter
            for parameter in signature.parameters.values()
            if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
        ]
        has_varargs = any(
            parameter.kind == parameter.VAR_POSITIONAL
            for parameter in signature.parameters.values()
        )
    except (TypeError, ValueError):
        positional = []
        has_varargs = True
    if has_varargs or len(positional) >= 3:
        return function(address, port, timeout_seconds)
    return function((address, port), timeout_seconds)


def probe_tcp(
    target: Mapping[str, Any],
    *,
    addresses: Iterable[str] | None = None,
    resolver: Any = None,
    tcp_connector: Any = None,
    socket_factory: Any = None,
    clock: Any = None,
    limits: ProbeLimits | None = None,
) -> dict[str, Any]:
    """Perform a TCP handshake only; never read an endpoint banner."""

    try:
        normalized = validate_target(target)
        active_limits = limits or ProbeLimits()
        if _probe_type_for(normalized) != "tcp_connect":
            return _dto(
                normalized,
                outcome="inconclusive",
                public_code="unsupported_probe",
                latency_ms=None,
                clock=clock,
                probe_type="tcp_connect",
            )
        eligible = _eligible_supplied_addresses(addresses) if addresses is not None else _resolve_global_addresses(
            normalized["host"],
            normalized["port"],
            resolver=resolver,
            timeout_seconds=float(active_limits.timeout_seconds),
        )
        if not eligible:
            raise _ResolutionProblem("dns_no_global_address")
    except _ResolutionProblem as problem:
        return _dto(
            target,
            outcome="inconclusive",
            public_code=problem.public_code,
            latency_ms=None,
            clock=clock,
            probe_type="tcp_connect",
        )
    except Exception:
        return _dto(
            target,
            outcome="inconclusive",
            public_code="probe_error",
            latency_ms=None,
            clock=clock,
            probe_type="tcp_connect",
        )

    connector = tcp_connector if tcp_connector is not None else socket_factory
    started = _clock_monotonic(clock)
    all_network_failures = True
    try:
        for address in eligible:
            try:
                stream = _connect(
                    connector,
                    address,
                    normalized["port"],
                    float(active_limits.timeout_seconds),
                )
                try:
                    return _dto(
                        normalized,
                        outcome="reachable",
                        public_code="tcp_accept",
                        latency_ms=_bounded_latency_ms(
                            clock, started, active_limits.max_latency_ms
                        ),
                        clock=clock,
                        probe_type="tcp_connect",
                    )
                finally:
                    close = getattr(stream, "close", None)
                    if callable(close):
                        close()
            except (ConnectionError, TimeoutError, socket.timeout, OSError):
                continue
            except Exception:
                all_network_failures = False
                break
    except Exception:
        all_network_failures = False

    if all_network_failures:
        code = "tcp_unreachable"
    else:
        code = "probe_error"
    return _dto(
        normalized,
        outcome="unreachable" if all_network_failures else "inconclusive",
        public_code=code,
        latency_ms=_bounded_latency_ms(clock, started, active_limits.max_latency_ms),
        clock=clock,
        probe_type="tcp_connect",
    )


def _format_timeout(timeout_seconds: float) -> str:
    value = float(timeout_seconds)
    if value.is_integer():
        return str(int(value))
    return f"{value:.3f}".rstrip("0").rstrip(".")


def build_ike_scan_argv(
    target: Mapping[str, Any],
    *,
    timeout_seconds: float = DEFAULT_PROBE_TIMEOUT_SECONDS,
    retries: int = DEFAULT_RETRIES,
) -> list[str]:
    """Build an allowlisted, credential-free ``ike-scan`` argv array."""

    normalized = validate_target(target)
    if normalized.get("vpn_type") != "ipsec" or normalized.get("transport") != "udp":
        raise ValueError("target is not an IPsec UDP endpoint.")
    limits = ProbeLimits(timeout_seconds=timeout_seconds, retries=retries)

    try:
        literal = ipaddress.ip_address(normalized["host"])
    except ValueError:
        raise ValueError("ike-scan requires a vetted numeric destination.") from None
    if getattr(literal, "ipv4_mapped", None) is not None:
        literal = literal.ipv4_mapped
    normalized = dict(normalized, host=str(literal))
    if not is_global_unicast(normalized["host"]):
        raise ValueError("ike-scan destination is not global.")

    destination_port = 4500 if normalized["nat_t"] else normalized["port"]
    argv = [
        "ike-scan",
        f"--retry={limits.retries}",
        f"--timeout={_format_timeout(limits.timeout_seconds)}",
        "--sport=0",
        f"--dport={destination_port}",
    ]
    if normalized["ike_version"] == "ikev2":
        argv.append("--ikev2")
    elif normalized["aggressive"]:
        argv.append("--aggressive")
    if normalized["nat_t"]:
        argv.append("--nat-t")
    argv.append(normalized["host"])
    return argv


def classify_ike_scan_output(
    stdout: Any,
    stderr: Any = "",
    *,
    returncode: int = 0,
) -> dict[str, str]:
    """Classify scanner output into public codes without returning the output."""

    if isinstance(returncode, bool) or not isinstance(returncode, int):
        return {"outcome": "inconclusive", "public_code": "probe_error"}
    if returncode != 0:
        return {"outcome": "inconclusive", "public_code": "probe_error"}

    def text(value: Any) -> str:
        if isinstance(value, bytes):
            return value[:MAX_SCANNER_OUTPUT_BYTES].decode("utf-8", errors="ignore")
        if isinstance(value, str):
            return value[:MAX_SCANNER_OUTPUT_BYTES]
        return ""

    combined = (text(stdout) + "\n" + text(stderr))[:MAX_SCANNER_OUTPUT_BYTES]
    if any(pattern.search(combined) for pattern in _IKE_RESPONSE_PATTERNS):
        return {"outcome": "reachable", "public_code": "ike_response"}
    return {"outcome": "unreachable", "public_code": "ike_no_response"}


def _runner_function(runner: Any) -> Callable[..., Any]:
    if runner is None:
        return subprocess.run
    if callable(runner):
        return runner
    candidate = getattr(runner, "run", None)
    if callable(candidate):
        return candidate
    raise ValueError("runner is not callable.")


def _runner_fields(completed: Any) -> tuple[int, Any, Any]:
    if isinstance(completed, Mapping):
        return (
            completed.get("returncode", 0),
            completed.get("stdout", ""),
            completed.get("stderr", ""),
        )
    return (
        getattr(completed, "returncode", 0),
        getattr(completed, "stdout", ""),
        getattr(completed, "stderr", ""),
    )


def _run_ike(runner: Any, argv: list[str], timeout_seconds: float) -> tuple[int, Any, Any]:
    function = _runner_function(runner)
    completed = function(
        argv,
        shell=False,
        timeout=timeout_seconds,
        capture_output=True,
        text=True,
        check=False,
    )
    return _runner_fields(completed)


def probe_ike(
    target: Mapping[str, Any],
    *,
    addresses: Iterable[str] | None = None,
    resolver: Any = None,
    runner: Any = None,
    clock: Any = None,
    limits: ProbeLimits | None = None,
) -> dict[str, Any]:
    """Run a bounded, allowlisted IKE scan against eligible addresses."""

    try:
        normalized = validate_target(target)
        active_limits = limits or ProbeLimits()
        if _probe_type_for(normalized) != "ike":
            return _dto(
                normalized,
                outcome="inconclusive",
                public_code="unsupported_probe",
                latency_ms=None,
                clock=clock,
                probe_type="ike",
            )
        eligible = _eligible_supplied_addresses(addresses) if addresses is not None else _resolve_global_addresses(
            normalized["host"],
            normalized["port"],
            resolver=resolver,
            timeout_seconds=float(active_limits.timeout_seconds),
        )
        if not eligible:
            raise _ResolutionProblem("dns_no_global_address")
    except _ResolutionProblem as problem:
        return _dto(
            target,
            outcome="inconclusive",
            public_code=problem.public_code,
            latency_ms=None,
            clock=clock,
            probe_type="ike",
        )
    except Exception:
        return _dto(
            target,
            outcome="inconclusive",
            public_code="probe_error",
            latency_ms=None,
            clock=clock,
            probe_type="ike",
        )

    started = _clock_monotonic(clock)
    saw_tool_failure = False
    for address in eligible:
        scan_target = dict(normalized, host=address)
        try:
            argv = build_ike_scan_argv(
                scan_target,
                timeout_seconds=float(active_limits.timeout_seconds),
                retries=active_limits.retries,
            )
            returncode, stdout, stderr = _run_ike(
                runner,
                argv,
                float(active_limits.timeout_seconds),
            )
            classification = classify_ike_scan_output(
                stdout,
                stderr,
                returncode=returncode,
            )
            if classification["public_code"] == "ike_response":
                return _dto(
                    normalized,
                    outcome="reachable",
                    public_code="ike_response",
                    latency_ms=_bounded_latency_ms(
                        clock, started, active_limits.max_latency_ms
                    ),
                    clock=clock,
                    probe_type="ike",
                )
            if classification["public_code"] == "probe_error":
                saw_tool_failure = True
        except (subprocess.TimeoutExpired, TimeoutError, socket.timeout):
            # For IKE only, bounded silence/timeout is a conclusive no-response.
            continue
        except Exception:
            saw_tool_failure = True

    if saw_tool_failure:
        outcome, code = "inconclusive", "probe_error"
    else:
        outcome, code = "unreachable", "ike_no_response"
    return _dto(
        normalized,
        outcome=outcome,
        public_code=code,
        latency_ms=_bounded_latency_ms(clock, started, active_limits.max_latency_ms),
        clock=clock,
        probe_type="ike",
    )


def _udp_factory_function(factory: Any) -> Callable[..., Any]:
    if factory is None:
        return socket.socket
    if callable(factory):
        return factory
    candidate = getattr(factory, "socket", None)
    if callable(candidate):
        return candidate
    raise ValueError("udp socket factory is not callable.")


def _make_udp_socket(factory: Any, family: int) -> Any:
    function = _udp_factory_function(factory)
    if function is socket.socket:
        return function(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    return _call_with_supported_arity(
        function,
        (family, socket.SOCK_DGRAM, socket.IPPROTO_UDP),
    )


def _is_udp_refused(error: BaseException) -> bool:
    if isinstance(error, ConnectionRefusedError):
        return True
    value = getattr(error, "errno", None)
    winerror = getattr(error, "winerror", None)
    return value == errno.ECONNREFUSED or winerror == 10061


def probe_openvpn_udp(
    target: Mapping[str, Any],
    *,
    addresses: Iterable[str] | None = None,
    resolver: Any = None,
    udp_socket_factory: Any = None,
    socket_factory: Any = None,
    clock: Any = None,
    limits: ProbeLimits | None = None,
) -> dict[str, Any]:
    """Send a credential-free UDP probe and preserve silence as inconclusive."""

    try:
        normalized = validate_target(target)
        active_limits = limits or ProbeLimits()
        if _probe_type_for(normalized) != "openvpn_udp":
            return _dto(
                normalized,
                outcome="inconclusive",
                public_code="unsupported_probe",
                latency_ms=None,
                clock=clock,
                probe_type="openvpn_udp",
            )
        eligible = _eligible_supplied_addresses(addresses) if addresses is not None else _resolve_global_addresses(
            normalized["host"],
            normalized["port"],
            resolver=resolver,
            timeout_seconds=float(active_limits.timeout_seconds),
        )
        if not eligible:
            raise _ResolutionProblem("dns_no_global_address")
    except _ResolutionProblem as problem:
        return _dto(
            target,
            outcome="inconclusive",
            public_code=problem.public_code,
            latency_ms=None,
            clock=clock,
            probe_type="openvpn_udp",
        )
    except Exception:
        return _dto(
            target,
            outcome="inconclusive",
            public_code="probe_error",
            latency_ms=None,
            clock=clock,
            probe_type="openvpn_udp",
        )

    factory = udp_socket_factory if udp_socket_factory is not None else socket_factory
    started = _clock_monotonic(clock)
    saw_refused = False
    saw_silence = False
    saw_tool_failure = False
    for address in eligible:
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        udp_socket = None
        try:
            udp_socket = _make_udp_socket(factory, family)
            settimeout = getattr(udp_socket, "settimeout", None)
            if not callable(settimeout):
                raise OSError()
            settimeout(float(active_limits.timeout_seconds))
            connect = getattr(udp_socket, "connect", None)
            send = getattr(udp_socket, "send", None)
            recv = getattr(udp_socket, "recv", None)
            if not all(callable(function) for function in (connect, send, recv)):
                raise OSError()
            connect((address, normalized["port"]))
            send(_OPENVPN_UDP_PROBE_PAYLOAD)
            response = recv(MAX_UDP_RESPONSE_BYTES)
            if isinstance(response, (bytes, bytearray)) and response:
                return _dto(
                    normalized,
                    outcome="reachable",
                    public_code="openvpn_udp_response",
                    latency_ms=_bounded_latency_ms(
                        clock, started, active_limits.max_latency_ms
                    ),
                    clock=clock,
                    probe_type="openvpn_udp",
                )
            saw_silence = True
        except (socket.timeout, TimeoutError):
            saw_silence = True
        except OSError as error:
            if _is_udp_refused(error):
                saw_refused = True
            else:
                saw_tool_failure = True
        except Exception:
            saw_tool_failure = True
        finally:
            close = getattr(udp_socket, "close", None)
            if callable(close):
                close()

    if saw_silence:
        outcome, code = "inconclusive", "udp_silent"
    elif saw_refused and not saw_tool_failure:
        outcome, code = "unreachable", "udp_port_unreachable"
    elif saw_tool_failure:
        outcome, code = "inconclusive", "probe_error"
    else:
        outcome, code = "inconclusive", "udp_silent"
    return _dto(
        normalized,
        outcome=outcome,
        public_code=code,
        latency_ms=_bounded_latency_ms(clock, started, active_limits.max_latency_ms),
        clock=clock,
        probe_type="openvpn_udp",
    )


def _limits_from_arguments(
    limits: ProbeLimits | None,
    timeout_seconds: float | None,
    retries: int | None,
) -> ProbeLimits:
    if limits is not None:
        if timeout_seconds is not None or retries is not None:
            raise ValueError("limits and scalar limit overrides cannot be combined.")
        if not isinstance(limits, ProbeLimits):
            raise ValueError("limits must be a ProbeLimits instance.")
        return limits
    return ProbeLimits(
        timeout_seconds=(
            DEFAULT_PROBE_TIMEOUT_SECONDS if timeout_seconds is None else timeout_seconds
        ),
        retries=DEFAULT_RETRIES if retries is None else retries,
    )


def dispatch_probe(
    target: Mapping[str, Any],
    *,
    resolver: Any = None,
    clock: Any = None,
    runner: Any = None,
    tcp_connector: Any = None,
    udp_socket_factory: Any = None,
    socket_factory: Any = None,
    limits: ProbeLimits | None = None,
    timeout_seconds: float | None = None,
    retries: int | None = None,
) -> dict[str, Any]:
    """Dispatch one target and always return the exact normalized DTO shape."""

    safe_probe_type = _safe_probe_type(target)
    try:
        active_limits = _limits_from_arguments(limits, timeout_seconds, retries)
        normalized = validate_target(target)
        probe_type = _probe_type_for(normalized)
        if probe_type is None:
            return _dto(
                normalized,
                outcome="inconclusive",
                public_code="unsupported_probe",
                latency_ms=None,
                clock=clock,
                probe_type=safe_probe_type,
            )

        addresses = _resolve_global_addresses(
            normalized["host"],
            normalized["port"],
            resolver=resolver,
            timeout_seconds=float(active_limits.timeout_seconds),
        )
        if probe_type == "tcp_connect":
            return probe_tcp(
                normalized,
                addresses=addresses,
                tcp_connector=tcp_connector,
                socket_factory=socket_factory,
                clock=clock,
                limits=active_limits,
            )
        if probe_type == "ike":
            return probe_ike(
                normalized,
                addresses=addresses,
                runner=runner,
                clock=clock,
                limits=active_limits,
            )
        return probe_openvpn_udp(
            normalized,
            addresses=addresses,
            udp_socket_factory=udp_socket_factory,
            socket_factory=socket_factory,
            clock=clock,
            limits=active_limits,
        )
    except _ResolutionProblem as problem:
        return _dto(
            target,
            outcome="inconclusive",
            public_code=problem.public_code,
            latency_ms=None,
            clock=clock,
            probe_type=safe_probe_type,
        )
    except Exception:
        # The dispatcher is the worker's public boundary.  Deliberately do not
        # include exception text, subprocess output, DNS answers, or addresses.
        return _dto(
            target,
            outcome="inconclusive",
            public_code="probe_error",
            latency_ms=None,
            clock=clock,
            probe_type=safe_probe_type,
        )


# Small descriptive aliases for callers that prefer the protocol names.
probe_udp = probe_openvpn_udp
build_ike_scan_command = build_ike_scan_argv
classify_ike_output = classify_ike_scan_output
dispatch = dispatch_probe


__all__ = [
    "DEFAULT_PROBE_TIMEOUT_SECONDS",
    "DEFAULT_RETRIES",
    "MAX_HOST_LENGTH",
    "MAX_LATENCY_MS",
    "MAX_PORT",
    "MAX_PROBE_TIMEOUT_SECONDS",
    "MAX_RETRIES",
    "ProbeLimits",
    "RESULT_FIELDS",
    "build_ike_scan_argv",
    "build_ike_scan_command",
    "classify_ike_scan_output",
    "classify_ike_output",
    "dispatch_probe",
    "dispatch",
    "is_global_unicast",
    "probe_ike",
    "probe_openvpn_udp",
    "probe_tcp",
    "probe_udp",
    "resolve_global_addresses",
    "validate_target",
]
