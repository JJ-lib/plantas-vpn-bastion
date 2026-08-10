import socket
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "panel-app"))

from vpn_endpoint_monitor import (  # noqa: E402
    MAX_HOST_LENGTH,
    MAX_LATENCY_MS,
    MAX_PORT,
    MAX_PROBE_TIMEOUT_SECONDS,
    ProbeLimits,
    build_ike_scan_argv,
    classify_ike_scan_output,
    dispatch_probe,
    is_global_unicast,
    validate_target,
)


REVISION = "a" * 64


class FakeClock:
    def __init__(self, wall=1_700_000_000, monotonic_values=(10.0, 10.025)):
        self.wall = wall
        self.monotonic_values = iter(monotonic_values)

    def time(self):
        return self.wall

    def monotonic(self):
        return next(self.monotonic_values)


class FakeResolver:
    def __init__(self, answers=None, error=None):
        self.answers = [] if answers is None else answers
        self.error = error
        self.calls = []

    def __call__(self, host, port, timeout):
        self.calls.append((host, port, timeout))
        if self.error is not None:
            raise self.error
        return self.answers


class FakeStream:
    def __init__(self):
        self.closed = False
        self.recv_called = False

    def close(self):
        self.closed = True

    def recv(self, *_args):
        self.recv_called = True
        raise AssertionError("TCP probe must not read a banner")


class FakeConnector:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []
        self.streams = []

    def __call__(self, address, timeout):
        self.calls.append((address, timeout))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        if isinstance(outcome, FakeStream):
            stream = outcome
        else:
            stream = FakeStream()
        self.streams.append(stream)
        return stream


class FakeUDPSocket:
    def __init__(self, recv_result=None, recv_error=None, send_error=None):
        self.recv_result = recv_result
        self.recv_error = recv_error
        self.send_error = send_error
        self.timeout = None
        self.connected = None
        self.sent = []
        self.closed = False

    def settimeout(self, value):
        self.timeout = value

    def connect(self, address):
        self.connected = address

    def send(self, payload):
        if self.send_error is not None:
            raise self.send_error
        self.sent.append(payload)
        return len(payload)

    def recv(self, _size):
        if self.recv_error is not None:
            raise self.recv_error
        return self.recv_result

    def close(self):
        self.closed = True


class FakeSocketFactory:
    def __init__(self, sock):
        self.sock = sock
        self.calls = []

    def __call__(self, family, sock_type, protocol=0):
        self.calls.append((family, sock_type, protocol))
        return self.sock


class DestinationPolicyTests(unittest.TestCase):
    def target(self, **changes):
        target = {
            "vpn_id": 7,
            "target_revision": REVISION,
            "vpn_type": "ssl",
            "host": "gateway.example.test",
            "port": 443,
            "transport": "tcp",
        }
        target.update(changes)
        return target

    def test_only_global_unicast_addresses_are_eligible(self):
        accepted = ("8.8.8.8", "2001:4860:4860::8888")
        rejected = (
            "127.0.0.1",
            "::1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "169.254.1.1",
            "fe80::1",
            "224.0.0.1",
            "ff02::1",
            "0.0.0.0",
            "::",
            "240.0.0.1",
        )
        for address in accepted:
            with self.subTest(address=address):
                self.assertTrue(is_global_unicast(address))
        for address in rejected:
            with self.subTest(address=address):
                self.assertFalse(is_global_unicast(address))

    def test_mixed_dns_answers_probe_only_deduplicated_global_addresses(self):
        resolver = FakeResolver(
            ["10.0.0.4", "8.8.8.8", "8.8.8.8", "::1", "2001:4860:4860::8888"]
        )
        connector = FakeConnector([FakeStream()])

        result = dispatch_probe(
            self.target(),
            resolver=resolver,
            tcp_connector=connector,
            clock=FakeClock(),
        )

        self.assertEqual(result["outcome"], "reachable")
        self.assertEqual(result["public_code"], "tcp_accept")
        self.assertEqual(
            [call[0] for call in connector.calls],
            [("8.8.8.8", 443)],
        )
        self.assertEqual(set(result), {
            "vpn_id",
            "target_revision",
            "probe_type",
            "outcome",
            "public_code",
            "latency_ms",
            "observed_at",
        })

    def test_dns_timeout_is_normalized_without_a_probe_call(self):
        resolver = FakeResolver(error=socket.timeout())
        connector = FakeConnector([])

        result = dispatch_probe(
            self.target(),
            resolver=resolver,
            tcp_connector=connector,
            clock=FakeClock(),
        )

        self.assertEqual(result["outcome"], "inconclusive")
        self.assertEqual(result["public_code"], "dns_timeout")
        self.assertEqual(connector.calls, [])

    def test_dns_failure_is_normalized_without_exposing_exception_text(self):
        resolver = FakeResolver(error=socket.gaierror("synthetic DNS detail"))
        result = dispatch_probe(
            self.target(),
            resolver=resolver,
            tcp_connector=FakeConnector([]),
            clock=FakeClock(),
        )

        self.assertEqual(result["outcome"], "inconclusive")
        self.assertEqual(result["public_code"], "dns_failed")
        self.assertNotIn("synthetic", repr(result))

    def test_non_global_literal_destination_is_rejected_before_any_probe(self):
        connector = FakeConnector([])
        result = dispatch_probe(
            self.target(host="192.168.50.10"),
            resolver=FakeResolver(["8.8.8.8"]),
            tcp_connector=connector,
            clock=FakeClock(),
        )

        self.assertEqual(result["outcome"], "inconclusive")
        self.assertEqual(result["public_code"], "private_or_reserved_destination")
        self.assertEqual(connector.calls, [])


class TargetLimitTests(unittest.TestCase):
    def target(self, **changes):
        target = {
            "vpn_id": 7,
            "target_revision": REVISION,
            "vpn_type": "ssl",
            "host": "gateway.example.test",
            "port": 443,
            "transport": "tcp",
        }
        target.update(changes)
        return target

    def test_target_validation_enforces_host_and_port_bounds(self):
        with self.assertRaises(ValueError):
            validate_target(self.target(host="h" * (MAX_HOST_LENGTH + 1)))
        with self.assertRaises(ValueError):
            validate_target(self.target(port=0))
        with self.assertRaises(ValueError):
            validate_target(self.target(port=MAX_PORT + 1))
        with self.assertRaises(ValueError):
            validate_target(self.target(port=True))

    def test_limits_reject_timeout_and_latency_values_outside_hard_bounds(self):
        with self.assertRaises(ValueError):
            ProbeLimits(timeout_seconds=MAX_PROBE_TIMEOUT_SECONDS + 0.001)
        with self.assertRaises(ValueError):
            ProbeLimits(timeout_seconds=0)
        with self.assertRaises(ValueError):
            ProbeLimits(max_latency_ms=MAX_LATENCY_MS + 1)
        with self.assertRaises(ValueError):
            ProbeLimits(max_latency_ms=-1)

    def test_dispatcher_returns_safe_dto_for_invalid_target_without_raising(self):
        result = dispatch_probe(
            self.target(host="h" * (MAX_HOST_LENGTH + 1)),
            resolver=FakeResolver(["8.8.8.8"]),
            tcp_connector=FakeConnector([]),
            clock=FakeClock(),
        )

        self.assertEqual(result["outcome"], "inconclusive")
        self.assertEqual(result["public_code"], "probe_error")
        self.assertEqual(set(result), {
            "vpn_id",
            "target_revision",
            "probe_type",
            "outcome",
            "public_code",
            "latency_ms",
            "observed_at",
        })

    def test_dispatcher_drops_latency_that_exceeds_the_hard_bound(self):
        connector = FakeConnector([FakeStream()])
        result = dispatch_probe(
            self.target(),
            resolver=FakeResolver(["8.8.8.8"]),
            tcp_connector=connector,
            clock=FakeClock(monotonic_values=(0.0, (MAX_LATENCY_MS / 1000) + 1.0)),
        )

        self.assertEqual(result["outcome"], "reachable")
        self.assertIsNone(result["latency_ms"])
        self.assertLessEqual(
            result["latency_ms"] or 0,
            MAX_LATENCY_MS,
        )


class TcpProbeTests(unittest.TestCase):
    def target(self, **changes):
        target = {
            "vpn_id": 8,
            "target_revision": REVISION,
            "vpn_type": "ssl",
            "host": "gateway.example.test",
            "port": 443,
            "transport": "tcp",
        }
        target.update(changes)
        return target

    def test_tcp_accept_closes_socket_and_never_reads_a_banner(self):
        stream = FakeStream()
        connector = FakeConnector([stream])
        result = dispatch_probe(
            self.target(),
            resolver=FakeResolver(["8.8.8.8"]),
            tcp_connector=connector,
            clock=FakeClock(),
        )

        self.assertEqual((result["outcome"], result["public_code"]), ("reachable", "tcp_accept"))
        self.assertTrue(stream.closed)
        self.assertFalse(stream.recv_called)
        self.assertEqual(connector.calls[0][1], MAX_PROBE_TIMEOUT_SECONDS)

    def test_tcp_refusal_timeout_and_unreachable_are_conclusive_failures(self):
        connector = FakeConnector(
            [ConnectionRefusedError(), socket.timeout(), OSError("synthetic network")]
        )
        result = dispatch_probe(
            self.target(),
            resolver=FakeResolver(["8.8.8.8", "2001:4860:4860::8888", "1.1.1.1"]),
            tcp_connector=connector,
            clock=FakeClock(),
        )

        self.assertEqual((result["outcome"], result["public_code"]), ("unreachable", "tcp_unreachable"))
        self.assertEqual(len(connector.calls), 3)

    def test_tcp_mapping_is_transport_aware_for_supported_vpn_types(self):
        for vpn_type in ("ssl", "openvpn", "pptp"):
            with self.subTest(vpn_type=vpn_type):
                target = self.target(vpn_type=vpn_type)
                result = dispatch_probe(
                    target,
                    resolver=FakeResolver(["8.8.8.8"]),
                    tcp_connector=FakeConnector([FakeStream()]),
                    clock=FakeClock(),
                )
                self.assertEqual(result["probe_type"], "tcp_connect")
                self.assertEqual(result["public_code"], "tcp_accept")


class IkeScanTests(unittest.TestCase):
    def target(self, **changes):
        target = {
            "vpn_id": 9,
            "target_revision": REVISION,
            "vpn_type": "ipsec",
            "host": "gateway.example.test",
            "port": 500,
            "transport": "udp",
            "ike_version": "ikev1",
            "aggressive": True,
            "nat_t": True,
        }
        target.update(changes)
        return target

    def test_ike_scan_argv_is_allowlisted_and_bounded(self):
        argv = build_ike_scan_argv(self.target(), timeout_seconds=3.0, retries=2)

        self.assertEqual(argv[0], "ike-scan")
        self.assertIn("--retry=2", argv)
        self.assertIn("--timeout=3", argv)
        self.assertIn("--sport=0", argv)
        self.assertIn("--nat-t", argv)
        self.assertIn("--aggressive", argv)
        self.assertIn("--dport=4500", argv)
        self.assertEqual(argv[-1], "gateway.example.test")
        self.assertNotIn("--psk", " ".join(argv).lower())
        self.assertNotIn("--username", " ".join(argv).lower())

        ikev2 = build_ike_scan_argv(
            self.target(ike_version="ikev2", aggressive=False, nat_t=False),
            timeout_seconds=1.5,
            retries=1,
        )
        self.assertIn("--ikev2", ikev2)
        self.assertNotIn("--aggressive", ikev2)
        self.assertIn("--dport=500", ikev2)

    def test_ike_scan_rejects_untrusted_host_and_unbounded_timeout(self):
        with self.assertRaises(ValueError):
            build_ike_scan_argv(self.target(host="gateway;touch-file"))
        with self.assertRaises(ValueError):
            build_ike_scan_argv(self.target(), timeout_seconds=MAX_PROBE_TIMEOUT_SECONDS + 1)
        with self.assertRaises(ValueError):
            build_ike_scan_argv(self.target(), retries=99)

    def test_ike_scan_classifies_handshake_and_notify_without_returning_raw_output(self):
        handshake = classify_ike_scan_output(
            "8.8.8.8 Main Mode Handshake returned\nHDR=(...)"
        )
        notify = classify_ike_scan_output(
            "8.8.8.8 Notify message: INVALID_KE_PAYLOAD\nraw responder bytes"
        )
        silence = classify_ike_scan_output("")

        self.assertEqual(handshake, {"outcome": "reachable", "public_code": "ike_response"})
        self.assertEqual(notify, {"outcome": "reachable", "public_code": "ike_response"})
        self.assertEqual(silence, {"outcome": "unreachable", "public_code": "ike_no_response"})
        self.assertNotIn("raw", repr(notify))

    def test_ike_probe_uses_shell_false_timeout_and_only_normalized_dto(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return SimpleNamespace(
                returncode=0,
                stdout="8.8.8.8 Main Mode Handshake returned\nPSK NEVER BELONGS IN DTO",
                stderr="",
            )

        result = dispatch_probe(
            self.target(),
            resolver=FakeResolver(["8.8.8.8"]),
            runner=runner,
            clock=FakeClock(),
        )

        self.assertEqual((result["outcome"], result["public_code"]), ("reachable", "ike_response"))
        self.assertEqual(set(result), {
            "vpn_id",
            "target_revision",
            "probe_type",
            "outcome",
            "public_code",
            "latency_ms",
            "observed_at",
        })
        self.assertNotIn("PSK", repr(result))
        self.assertEqual(len(calls), 1)
        argv, kwargs = calls[0]
        self.assertEqual(kwargs["shell"], False)
        self.assertLessEqual(kwargs["timeout"], MAX_PROBE_TIMEOUT_SECONDS)
        self.assertEqual(argv[0], "ike-scan")

    def test_ike_tool_failure_is_not_exposed_as_raw_exception(self):
        def runner(_argv, **_kwargs):
            raise RuntimeError("ike-scan secret/raw detail")

        result = dispatch_probe(
            self.target(),
            resolver=FakeResolver(["8.8.8.8"]),
            runner=runner,
            clock=FakeClock(),
        )

        self.assertEqual(result["outcome"], "inconclusive")
        self.assertEqual(result["public_code"], "probe_error")
        self.assertNotIn("secret", repr(result))


class OpenVpnUdpProbeTests(unittest.TestCase):
    def target(self, **changes):
        target = {
            "vpn_id": 10,
            "target_revision": REVISION,
            "vpn_type": "openvpn",
            "host": "gateway.example.test",
            "port": 1194,
            "transport": "udp",
        }
        target.update(changes)
        return target

    def dispatch_with_socket(self, sock):
        return dispatch_probe(
            self.target(),
            resolver=FakeResolver(["8.8.8.8"]),
            udp_socket_factory=FakeSocketFactory(sock),
            clock=FakeClock(),
        )

    def test_udp_protocol_response_is_reachable_and_socket_is_closed(self):
        sock = FakeUDPSocket(recv_result=b"openvpn-protocol-response")
        result = self.dispatch_with_socket(sock)

        self.assertEqual((result["outcome"], result["public_code"]), ("reachable", "openvpn_udp_response"))
        self.assertTrue(sock.sent)
        self.assertTrue(sock.closed)

    def test_udp_icmp_port_unreachable_is_unreachable(self):
        sock = FakeUDPSocket(recv_error=ConnectionRefusedError())
        result = self.dispatch_with_socket(sock)

        self.assertEqual((result["outcome"], result["public_code"]), ("unreachable", "udp_port_unreachable"))

    def test_udp_silence_is_inconclusive_not_unreachable(self):
        sock = FakeUDPSocket(recv_error=socket.timeout())
        result = self.dispatch_with_socket(sock)

        self.assertEqual((result["outcome"], result["public_code"]), ("inconclusive", "udp_silent"))


class DispatcherContractTests(unittest.TestCase):
    def test_unsupported_probe_is_normalized_and_has_no_raw_output(self):
        target = {
            "vpn_id": 11,
            "target_revision": REVISION,
            "vpn_type": "unsupported",
            "host": "gateway.example.test",
            "port": 1234,
            "transport": "tcp",
        }
        result = dispatch_probe(target, clock=FakeClock())

        self.assertEqual(result["outcome"], "inconclusive")
        self.assertEqual(result["public_code"], "unsupported_probe")
        self.assertEqual(set(result), {
            "vpn_id",
            "target_revision",
            "probe_type",
            "outcome",
            "public_code",
            "latency_ms",
            "observed_at",
        })


if __name__ == "__main__":
    unittest.main()
