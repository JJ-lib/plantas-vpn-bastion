import json
import socket
import sys
import unittest
from unittest import mock
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "panel-app"))

import vpn_endpoint_monitor as monitor  # noqa: E402
from vpn_endpoint_monitor import (
    MAX_HOST_LENGTH,
    MAX_LATENCY_MS,
    MAX_PORT,
    MAX_PROBE_TIMEOUT_SECONDS,
    ProbeLimits,
    build_ike_scan_argv,
    build_ike_scan_argvs,    classify_ike_scan_output,
    dispatch_probe,
    is_global_unicast,
    validate_target,
    DEFAULT_INTERVAL_SECONDS,
    MAX_WORKERS,
    MAX_HTTP_RESPONSE_BYTES,
    MAX_MONITOR_BATCH,
    PanelClient,
    bounded_jitter,
    load_monitor_token,
    run_cycle,
    run_worker,
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
            "target_generation": 4,
            "cycle_id": 9,
            "lease_id": "lease-9",
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
            "target_generation",
            "cycle_id",
            "lease_id",
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

    def test_ipv4_mapped_dns_answer_is_probed_as_numeric_ipv4(self):
        connector = FakeConnector([FakeStream()])
        dispatch_probe(
            self.target(),
            resolver=FakeResolver(["::ffff:8.8.8.8"]),
            tcp_connector=connector,
            clock=FakeClock(),
        )
        self.assertEqual(connector.calls[0][0][0], "8.8.8.8")


class TargetLimitTests(unittest.TestCase):
    def target(self, **changes):
        target = {
            "vpn_id": 7,
            "target_revision": REVISION,
            "target_generation": 4,
            "cycle_id": 9,
            "lease_id": "lease-9",
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
            "target_generation",
            "cycle_id",
            "lease_id",
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
            "target_generation": 4,
            "cycle_id": 9,
            "lease_id": "lease-9",
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
            "target_generation": 4,
            "cycle_id": 9,
            "lease_id": "lease-9",
            "vpn_type": "ipsec",
            "host": "8.8.8.8",
            "port": 4500,
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
        self.assertIn("--timeout=3000", argv)
        self.assertNotIn("--sport=0", argv)
        self.assertIn("--nat-t", argv)
        self.assertIn("--aggressive", argv)
        self.assertIn("--dport=4500", argv)
        self.assertEqual(argv[-1], "8.8.8.8")
        self.assertNotIn("--psk", " ".join(argv).lower())
        self.assertNotIn("--username", " ".join(argv).lower())

        ikev2 = build_ike_scan_argv(
            self.target(ike_version="ikev2", aggressive=False, nat_t=False, port=500),
            timeout_seconds=1.5,
            retries=1,
        )
        self.assertIn("--ikev2", ikev2)
        self.assertNotIn("--aggressive", ikev2)
        self.assertIn("--dport=500", ikev2)

    def test_ike_scan_rejects_non_ike_ports(self):
        with self.assertRaises(ValueError):
            build_ike_scan_argv(self.target(port=1234, nat_t=False))
        nat_t_500 = build_ike_scan_argv(self.target(port=500, nat_t=True))
        self.assertIn("--dport=500", nat_t_500)

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
        self.assertEqual(silence, {"outcome": "inconclusive", "public_code": "ike_no_response"})
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
            "target_generation",
            "cycle_id",
            "lease_id",
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

    def test_ipsec_production_path_checks_udp_500_and_nat_t_4500_without_raw_sockets(self):
        sock = FakeUDPSocket(recv_result=b"udp-response")
        factory = FakeSocketFactory(sock)
        result = dispatch_probe(
            self.target(),
            resolver=FakeResolver(["8.8.8.8"]),
            udp_socket_factory=factory,
            clock=FakeClock(),
        )

        self.assertEqual((result["probe_type"], result["outcome"], result["public_code"]), ("ike", "reachable", "udp_response"))
        self.assertEqual(len(factory.calls), 1)
        self.assertTrue(sock.sent)
        self.assertTrue(sock.closed)

    def test_ipsec_udp_silence_is_inconclusive_not_a_probe_error(self):
        sock = FakeUDPSocket(recv_error=socket.timeout())
        result = dispatch_probe(
            self.target(),
            resolver=FakeResolver(["8.8.8.8"]),
            udp_socket_factory=FakeSocketFactory(sock),
            clock=FakeClock(),
        )

        self.assertEqual((result["probe_type"], result["outcome"], result["public_code"]), ("ike", "inconclusive", "udp_silent"))


class OpenVpnUdpProbeTests(unittest.TestCase):
    def target(self, **changes):
        target = {
            "vpn_id": 10,
            "target_revision": REVISION,
            "target_generation": 4,
            "cycle_id": 9,
            "lease_id": "lease-9",
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
            "target_generation": 4,
            "cycle_id": 9,
            "lease_id": "lease-9",
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
            "target_generation",
            "cycle_id",
            "lease_id",
            "probe_type",
            "outcome",
            "public_code",
            "latency_ms",
            "observed_at",
        })


class WorkerContractTests(unittest.TestCase):
    def target(self, vpn_id=1, **changes):
        target = {
            "vpn_id": vpn_id,
            "target_revision": REVISION,
            "target_generation": 1,
            "cycle_id": 2,
            "lease_id": "lease-2",
            "vpn_type": "ssl",
            "host": "gateway.example.test",
            "port": 443,
            "transport": "tcp",
        }
        target.update(changes)
        return target

    def test_load_monitor_token_reads_trimmed_token_without_logging(self):
        with mock.patch("vpn_endpoint_monitor.Path") as path_type:
            path_type.return_value.read_bytes.return_value = b"  synthetic-token-0123456789abcdef  \n"
            path_type.return_value.is_file.return_value = True
            self.assertEqual(load_monitor_token("/run/secrets/token"), "synthetic-token-0123456789abcdef")
            path_type.return_value.read_bytes.assert_called_once_with()

    def test_main_prefers_panel_internal_url_environment_contract(self):
        import vpn_endpoint_monitor as monitor

        with mock.patch.dict(
            monitor.os.environ,
            {
                "PANEL_INTERNAL_URL": "http://internal-panel.test",
                "PANEL_URL": "http://legacy-panel.test",
            },
            clear=False,
        ), mock.patch.object(monitor, "load_monitor_token", return_value="token"), mock.patch.object(
            monitor, "PanelClient"
        ) as client_type, mock.patch.object(monitor, "run_worker"):
            self.assertEqual(monitor.main(["--once"]), 0)

        self.assertEqual(client_type.call_args.args[0], "http://internal-panel.test")

    def test_panel_client_uses_stdlib_http_and_bearer_token(self):
        requests = []

        def opener(request, timeout=None, **_kwargs):
            requests.append((request, timeout))
            return mock.Mock(
                __enter__=lambda self: self,
                __exit__=lambda *args: None,
                read=lambda self, size=-1: b'{"targets": []}',
            )

        client = PanelClient("http://panel.test", "synthetic-token-0123456789abcdef", opener=opener)
        self.assertEqual(client.fetch_targets(), [])
        request, timeout = requests[0]
        self.assertEqual(request.get_header("Authorization"), "Bearer synthetic-token-0123456789abcdef")
        self.assertEqual(request.method, "GET")
        self.assertLessEqual(timeout, 3.0)

    def test_panel_client_rejects_oversized_or_malformed_target_response(self):
        def oversized(_request, _timeout=None, **_kwargs):
            return mock.Mock(
                __enter__=lambda self: self, __exit__=lambda *args: None,
                read=lambda self, size=-1: b"x" * (MAX_HTTP_RESPONSE_BYTES + 1),
            )
        client = PanelClient("http://panel.test", "synthetic-token-0123456789abcdef", opener=oversized)
        with self.assertRaises(ValueError):
            client.fetch_targets()

        def malformed(_request, _timeout=None, **_kwargs):
            return mock.Mock(
                __enter__=lambda self: self, __exit__=lambda *args: None,
                read=lambda self, size=-1: b'{"targets": [{"host": "bad"}]}'
            )
        with self.assertRaises(ValueError):
            PanelClient("http://panel.test", "synthetic-token-0123456789abcdef", opener=malformed).fetch_targets()

    def test_panel_client_fetches_all_target_pages_over_500(self):
        requests = []
        pages = [
            {"targets": [self.target(index + 1) for index in range(MAX_MONITOR_BATCH)], "next_after_id": MAX_MONITOR_BATCH},
            {"targets": [self.target(MAX_MONITOR_BATCH + 1)]},
        ]
        def opener(request, _timeout=None, **_kwargs):
            requests.append(request.full_url)
            payload = pages.pop(0)
            return mock.Mock(__enter__=lambda self: self, __exit__=lambda *args: None,
                             read=lambda self, size=-1: json.dumps(payload).encode())
        client = PanelClient("http://panel.test", "synthetic-token-0123456789abcdef", opener=opener)
        targets = client.fetch_targets()
        self.assertEqual(len(targets), MAX_MONITOR_BATCH + 1)
        self.assertEqual(requests[1].split('?')[1], f"after_id={MAX_MONITOR_BATCH}&limit={MAX_MONITOR_BATCH}")

    def test_run_cycle_uses_at_most_four_workers_and_posts_normalized_results(self):
        targets = [self.target(index + 1) for index in range(7)]
        observed = []
        posted = []

        class Client:
            def fetch_targets(self):
                return targets
            def post_results(self, results):
                posted.append(results)

        def probe(target):
            observed.append(target["vpn_id"])
            return {"vpn_id": target["vpn_id"], "target_revision": REVISION,
                    "target_generation": 1, "cycle_id": 2, "lease_id": "lease-2",
                    "probe_type": "tcp_connect", "outcome": "reachable",
                    "public_code": "tcp_accept", "latency_ms": 1, "observed_at": 1}

        self.assertEqual(run_cycle(Client(), probe=probe), 7)
        self.assertEqual(len(posted[0]), 7)
        self.assertEqual(MAX_WORKERS, 4)

    def test_bounded_jitter_stays_within_configured_bounds(self):
        for value in (-1.0, 0.0, 1.0):
            jitter = bounded_jitter(300.0, random_value=value)
            self.assertGreaterEqual(jitter, -30.0)
            self.assertLessEqual(jitter, 30.0)

    def test_run_worker_once_is_immediate_and_default_interval_is_300(self):
        self.assertEqual(DEFAULT_INTERVAL_SECONDS, 300.0)
        calls = []
        class Client:
            def fetch_targets(self): return []
            def post_results(self, results): calls.append(results)
        self.assertEqual(run_worker(Client(), once=True, sleep=lambda seconds: calls.append(seconds)), 1)
        self.assertEqual(calls, [[]])

    def test_panel_failure_has_bounded_backoff_and_recovers_next_cycle(self):
        sleeps = []
        outcomes = [OSError("synthetic panel unavailable"), []]
        class Client:
            def fetch_targets(self):
                value = outcomes.pop(0)
                if isinstance(value, BaseException): raise value
                return value
            def post_results(self, results): pass
        def cycle(client, **kwargs):
            try:
                client.fetch_targets()
                return 0
            except OSError:
                return 0
        self.assertEqual(run_worker(Client(), once=False, max_cycles=2, cycle=cycle,
                                    sleep=sleeps.append, interval=300, jitter=lambda _interval: 0), 2)
        self.assertAlmostEqual(sleeps[0], 300.0, places=3)

    def test_target_selector_distinguishes_unset_all_targets_from_explicit_empty(self):
        self.assertIsNone(monitor.parse_target_selector(None))
        self.assertEqual(monitor.parse_target_selector(""), frozenset())
        self.assertEqual(monitor.parse_target_selector("7, 9,7"), frozenset({7, 9}))
        self.assertEqual(
            [target["vpn_id"] for target in monitor.select_targets(
                [self.target(7), self.target(8)], frozenset({8})
            )],
            [8],
        )

    def test_target_selector_rejects_non_numeric_or_non_positive_ids(self):
        for value in ("abc", "0", "1,-2", "1;2"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    monitor.parse_target_selector(value)

    def test_run_cycle_canary_only_probes_explicitly_selected_targets(self):
        targets = [self.target(7), self.target(8)]
        observed = []
        posted = []

        class Client:
            def fetch_targets(self): return targets
            def post_results(self, results): posted.append(results)

        def probe(target):
            observed.append(target["vpn_id"])
            return {"vpn_id": target["vpn_id"], "target_revision": REVISION,
                    "target_generation": 1, "cycle_id": 2, "lease_id": "lease-2",
                    "probe_type": "tcp_connect", "outcome": "reachable",
                    "public_code": "tcp_accept", "latency_ms": 1, "observed_at": 1}

        self.assertEqual(run_cycle(Client(), probe=probe, target_ids=frozenset({8})), 1)
        self.assertEqual(observed, [8])
        self.assertEqual([row["vpn_id"] for row in posted[0]], [8])


if __name__ == "__main__":
    unittest.main()
