import json
import socket
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "panel-app"))

import vpn_endpoint_monitor as monitor  # noqa: E402
from vpn_endpoint_monitor import (  # noqa: E402
    DEFAULT_INTERVAL_SECONDS,
    MAX_HOST_LENGTH,
    MAX_HTTP_RESPONSE_BYTES,
    MAX_LATENCY_MS,
    MAX_MONITOR_BATCH,
    MAX_PORT,
    MAX_PROBE_TIMEOUT_SECONDS,
    MAX_WORKERS,
    PanelClient,
    ProbeLimits,
    build_ike_scan_argv,
    build_ike_scan_argvs,
    classify_ike_scan_output,
    dispatch_probe,
    is_global_unicast,
    load_monitor_token,
    parse_target_selector,
    probe_icmp,
    probe_ike,
    probe_openvpn_udp,
    probe_target,
    probe_tcp,
    run_cycle,
    run_worker,
    select_targets,
    validate_target,
)


REVISION = "a" * 64


class ConstantClock:
    def __init__(self, wall=1_700_000_000):
        self.wall = wall

    def time(self):
        return self.wall

    def monotonic(self):
        return 10.0


class SequenceClock(ConstantClock):
    def __init__(self, values, wall=1_700_000_000):
        super().__init__(wall)
        self.values = iter(values)

    def monotonic(self):
        return next(self.values)


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
        stream = outcome if isinstance(outcome, FakeStream) else FakeStream()
        self.streams.append(stream)
        return stream


class FakeUDPSocket:
    def __init__(self, recv_result=None, recv_error=None):
        self.recv_result = recv_result
        self.recv_error = recv_error
        self.timeout = None
        self.connected = None
        self.sent = []
        self.closed = False

    def settimeout(self, value):
        self.timeout = value

    def connect(self, address):
        self.connected = address

    def send(self, payload):
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


def target(**changes):
    value = {
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
    value.update(changes)
    return value


class DestinationPolicyTests(unittest.TestCase):
    def test_only_global_unicast_addresses_are_eligible(self):
        for address in ("8.8.8.8", "2001:4860:4860::8888"):
            self.assertTrue(is_global_unicast(address))
        for address in (
            "127.0.0.1", "::1", "10.0.0.1", "192.168.1.1", "100.64.0.1",
            "169.254.1.1", "fe80::1", "224.0.0.1", "0.0.0.0", "::", "240.0.0.1",
        ):
            with self.subTest(address=address):
                self.assertFalse(is_global_unicast(address))

    def test_mixed_dns_answers_are_deduplicated_and_probed_once(self):
        resolver = FakeResolver(["10.0.0.4", "8.8.8.8", "8.8.8.8", "::1"])
        connector = FakeConnector([FakeStream()])
        result = probe_target(
            target(), resolver=resolver, icmp_runner=lambda *_a, **_k: SimpleNamespace(returncode=0),
            tcp_connector=connector, clock=ConstantClock(),
        )
        self.assertEqual(len(resolver.calls), 1)
        self.assertEqual([call[0] for call in connector.calls], [("8.8.8.8", 443)])
        self.assertEqual(set(result), {
            "vpn_id", "target_revision", "icmp_ok", "protocol_ok", "protocol_probe", "checked_at",
            "icmp_code", "protocol_code", "latency_ms", "target_generation", "cycle_id", "lease_id",
        })
        self.assertTrue(result["icmp_ok"])
        self.assertTrue(result["protocol_ok"])

    def test_dns_and_literal_policy_fail_before_any_probe(self):
        for resolver_error, host, code in (
            (socket.timeout(), "gateway.example.test", "dns_timeout"),
            (socket.gaierror("synthetic detail"), "gateway.example.test", "dns_failed"),
            (None, "192.168.50.10", "private_or_reserved_destination"),
        ):
            resolver = FakeResolver(["8.8.8.8"], error=resolver_error)
            pings = []
            result = probe_target(
                target(host=host), resolver=resolver,
                icmp_runner=lambda *_a, **_k: pings.append(True),
                tcp_connector=FakeConnector([]), clock=ConstantClock(),
            )
            self.assertFalse(result["icmp_ok"])
            self.assertFalse(result["protocol_ok"])
            self.assertEqual(result["icmp_code"], code)
            self.assertEqual(pings, [])
            self.assertNotIn("synthetic detail", repr(result))

    def test_ipv4_mapped_answer_is_normalized_to_numeric_ipv4(self):
        connector = FakeConnector([FakeStream()])
        probe_target(
            target(), resolver=FakeResolver(["::ffff:8.8.8.8"]),
            icmp_runner=lambda *_a, **_k: SimpleNamespace(returncode=0),
            tcp_connector=connector, clock=ConstantClock(),
        )
        self.assertEqual(connector.calls[0][0][0], "8.8.8.8")


class IcmpTests(unittest.TestCase):
    def test_two_attempts_and_one_success_are_icmp_ok(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return SimpleNamespace(returncode=0 if len(calls) == 2 else 1)

        result = probe_icmp(["8.8.8.8"], runner=runner, clock=ConstantClock())
        self.assertEqual(len(calls), 2)
        self.assertTrue(result["icmp_ok"])
        self.assertEqual(result["icmp_code"], "icmp_reply")
        for argv, kwargs in calls:
            self.assertEqual(argv[:6], ["ping", "-n", "-c", "1", "-W", "1"])
            self.assertFalse(kwargs["shell"])
            self.assertLessEqual(kwargs["timeout"], 1.0)
            self.assertFalse(kwargs["text"])

    def test_zero_replies_and_timeout_are_icmp_failures(self):
        def runner(*_args, **_kwargs):
            raise TimeoutError()

        result = probe_icmp(["8.8.8.8"], runner=runner, clock=ConstantClock())
        self.assertFalse(result["icmp_ok"])
        self.assertEqual(result["icmp_code"], "icmp_timeout")


class CombinedCycleTests(unittest.TestCase):
    def test_icmp_success_protocol_failure_is_accessible(self):
        result = probe_target(
            target(), resolver=FakeResolver(["8.8.8.8"]),
            icmp_runner=lambda *_a, **_k: SimpleNamespace(returncode=0),
            tcp_connector=FakeConnector([ConnectionRefusedError()]), clock=ConstantClock(),
        )
        self.assertTrue(result["icmp_ok"])
        self.assertFalse(result["protocol_ok"])
        self.assertEqual(result["protocol_probe"], "tcp")

    def test_protocol_success_icmp_failure_is_accessible(self):
        result = probe_target(
            target(), resolver=FakeResolver(["8.8.8.8"]),
            icmp_runner=lambda *_a, **_k: SimpleNamespace(returncode=1),
            tcp_connector=FakeConnector([FakeStream()]), clock=ConstantClock(),
        )
        self.assertFalse(result["icmp_ok"])
        self.assertTrue(result["protocol_ok"])

    def test_both_fail_are_not_reported_as_success(self):
        result = probe_target(
            target(), resolver=FakeResolver(["8.8.8.8"]),
            icmp_runner=lambda *_a, **_k: SimpleNamespace(returncode=1),
            tcp_connector=FakeConnector([ConnectionRefusedError()]), clock=ConstantClock(),
        )
        self.assertFalse(result["icmp_ok"] or result["protocol_ok"])

    def test_unsupported_target_does_not_resolve_or_probe(self):
        resolver = FakeResolver(["8.8.8.8"])
        result = probe_target(target(vpn_type="wireguard"), resolver=resolver, clock=ConstantClock())
        self.assertEqual(resolver.calls, [])
        self.assertEqual(result["protocol_code"], "unsupported_probe")
        self.assertFalse(result["icmp_ok"])
        self.assertFalse(result["protocol_ok"])


class TcpProbeTests(unittest.TestCase):
    def test_tcp_connect_closes_socket_and_never_reads_banner(self):
        stream = FakeStream()
        result = probe_tcp(
            target(), addresses=["8.8.8.8"], tcp_connector=FakeConnector([stream]), clock=ConstantClock()
        )
        self.assertEqual((result["outcome"], result["public_code"]), ("reachable", "tcp_accept"))
        self.assertTrue(stream.closed)
        self.assertFalse(stream.recv_called)

    def test_tcp_failures_are_conclusive_internal_protocol_evidence(self):
        result = probe_tcp(
            target(), addresses=["8.8.8.8", "1.1.1.1"],
            tcp_connector=FakeConnector([ConnectionRefusedError(), socket.timeout()]), clock=ConstantClock(),
        )
        self.assertEqual((result["outcome"], result["public_code"]), ("unreachable", "tcp_unreachable"))

    def test_supported_tcp_vpn_types_use_canonical_tcp_probe(self):
        for vpn_type in ("ssl", "openvpn", "pptp"):
            with self.subTest(vpn_type=vpn_type):
                result = probe_target(
                    target(vpn_type=vpn_type), resolver=FakeResolver(["8.8.8.8"]),
                    icmp_runner=lambda *_a, **_k: SimpleNamespace(returncode=1),
                    tcp_connector=FakeConnector([FakeStream()]), clock=ConstantClock(),
                )
                self.assertEqual(result["protocol_probe"], "tcp")
                self.assertTrue(result["protocol_ok"])


class OpenVpnUdpTests(unittest.TestCase):
    def test_response_is_protocol_ok_and_socket_is_closed(self):
        sock = FakeUDPSocket(recv_result=b"response")
        result = probe_openvpn_udp(
            target(vpn_type="openvpn", transport="udp", port=1194),
            addresses=["8.8.8.8"], udp_socket_factory=FakeSocketFactory(sock), clock=ConstantClock(),
        )
        self.assertEqual((result["outcome"], result["public_code"]), ("reachable", "openvpn_udp_response"))
        self.assertTrue(sock.sent)
        self.assertTrue(sock.closed)

    def test_refusal_and_silence_are_distinct_internal_diagnostics(self):
        refused = probe_openvpn_udp(
            target(vpn_type="openvpn", transport="udp", port=1194), addresses=["8.8.8.8"],
            udp_socket_factory=FakeSocketFactory(FakeUDPSocket(recv_error=ConnectionRefusedError())), clock=ConstantClock(),
        )
        silent = probe_openvpn_udp(
            target(vpn_type="openvpn", transport="udp", port=1194), addresses=["8.8.8.8"],
            udp_socket_factory=FakeSocketFactory(FakeUDPSocket(recv_error=socket.timeout())), clock=ConstantClock(),
        )
        self.assertEqual(refused["public_code"], "udp_port_unreachable")
        self.assertEqual(silent["public_code"], "udp_silent")

    def test_udp_silence_with_icmp_success_keeps_combined_cycle_accessible(self):
        sock = FakeUDPSocket(recv_error=socket.timeout())
        result = probe_target(
            target(vpn_type="openvpn", transport="udp", port=1194), resolver=FakeResolver(["8.8.8.8"]),
            icmp_runner=lambda *_a, **_k: SimpleNamespace(returncode=0),
            udp_socket_factory=FakeSocketFactory(sock), clock=ConstantClock(),
        )
        self.assertTrue(result["icmp_ok"])
        self.assertFalse(result["protocol_ok"])
        self.assertEqual(result["protocol_probe"], "openvpn_udp")


class IkeTests(unittest.TestCase):
    def ike_target(self, **changes):
        value = target(
            vpn_type="ipsec", host="8.8.8.8", port=4500, transport="udp",
            ike_version="ikev1", aggressive=True, nat_t=True,
        )
        value.update(changes)
        return value

    def test_argv_is_allowlisted_and_supports_aggressive_and_nat_t(self):
        argv = build_ike_scan_argv(self.ike_target(), timeout_seconds=3, retries=2)
        self.assertEqual(argv[0], "ike-scan")
        self.assertIn("--retry=2", argv)
        self.assertIn("--timeout=3000", argv)
        self.assertIn("--sport=0", argv)
        self.assertIn("--dport=4500", argv)
        self.assertIn("--aggressive", argv)
        self.assertIn("--nat-t", argv)
        self.assertNotIn("--psk", " ".join(argv).lower())
        self.assertNotIn("--username", " ".join(argv).lower())

    def test_nat_t_builds_both_udp_ports_and_ikev2_is_supported(self):
        argvs = build_ike_scan_argvs(self.ike_target())
        self.assertEqual({item for argv in argvs for item in argv if item.startswith("--dport=")}, {"--dport=500", "--dport=4500"})
        ikev2 = build_ike_scan_argv(self.ike_target(ike_version="ikev2", aggressive=False, nat_t=False, port=500))
        self.assertIn("--ikev2", ikev2)
        self.assertNotIn("--aggressive", ikev2)

    def test_ike_response_and_silence_are_normalized_without_raw_output(self):
        self.assertEqual(classify_ike_scan_output(b"Notify message: INVALID_KE_PAYLOAD"), {"outcome": "reachable", "public_code": "ike_response"})
        self.assertEqual(classify_ike_scan_output(b""), {"outcome": "inconclusive", "public_code": "ike_no_response"})

        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return SimpleNamespace(returncode=0, stdout=b"Notify message", stderr=b"raw secret must not return")

        result = probe_ike(self.ike_target(), addresses=["8.8.8.8"], runner=runner, clock=ConstantClock())
        self.assertEqual((result["outcome"], result["public_code"]), ("reachable", "ike_response"))
        self.assertNotIn("secret", repr(result))
        self.assertFalse(calls[0][1]["text"])
        self.assertFalse(calls[0][1]["shell"])

        silent_calls = []
        silent = probe_ike(
            self.ike_target(), addresses=["8.8.8.8"],
            runner=lambda argv, **kwargs: silent_calls.append((argv, kwargs)) or SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
            clock=ConstantClock(),
        )
        self.assertEqual(silent["public_code"], "ike_no_response")
        self.assertEqual({arg for argv, _kwargs in silent_calls for arg in argv if arg.startswith("--dport=")}, {"--dport=500", "--dport=4500"})


class ContractAndWorkerTests(unittest.TestCase):
    def test_dispatcher_returns_exact_canonical_contract(self):
        result = dispatch_probe(
            target(), resolver=FakeResolver(error=socket.gaierror()), clock=ConstantClock()
        )
        self.assertEqual(set(result), {
            "vpn_id", "target_revision", "icmp_ok", "protocol_ok", "protocol_probe", "checked_at",
            "icmp_code", "protocol_code", "latency_ms", "target_generation", "cycle_id", "lease_id",
        })
        self.assertNotIn("probe_type", result)
        self.assertNotIn("outcome", result)
        self.assertNotIn("public_code", result)
        self.assertNotIn("observed_at", result)

    def test_invalid_target_is_safe_and_does_not_expose_exception_text(self):
        result = dispatch_probe(target(host="h" * (MAX_HOST_LENGTH + 1)), clock=ConstantClock())
        self.assertEqual(result["protocol_code"], "probe_error")
        self.assertFalse(result["icmp_ok"])
        self.assertNotIn("h" * 20, repr(result))

    def test_validation_and_limits_are_bounded(self):
        with self.assertRaises(ValueError):
            validate_target(target(host="h" * (MAX_HOST_LENGTH + 1)))
        with self.assertRaises(ValueError):
            validate_target(target(port=0))
        with self.assertRaises(ValueError):
            validate_target(target(port=MAX_PORT + 1))
        with self.assertRaises(ValueError):
            ProbeLimits(timeout_seconds=MAX_PROBE_TIMEOUT_SECONDS + 0.1)
        with self.assertRaises(ValueError):
            ProbeLimits(max_latency_ms=MAX_LATENCY_MS + 1)

    def test_healthcheck_does_not_run_a_monitor_cycle(self):
        with mock.patch.object(monitor, "load_monitor_token", return_value="synthetic-token-0123456789abcdef"), mock.patch.object(monitor, "run_worker") as worker:
            self.assertEqual(monitor.main(["--healthcheck"]), 0)
        worker.assert_not_called()

    def test_panel_client_fetches_pages_and_posts_only_canonical_keys(self):
        requests = []
        pages = [
            {"targets": [target(vpn_id=index + 1) for index in range(MAX_MONITOR_BATCH)], "next_after_id": MAX_MONITOR_BATCH},
            {"targets": [target(vpn_id=MAX_MONITOR_BATCH + 1)]},
        ]

        def opener(request, timeout=None, **_kwargs):
            requests.append((request, timeout))
            payload = pages.pop(0)
            return mock.Mock(__enter__=lambda self: self, __exit__=lambda *args: None, read=lambda self, size=-1: json.dumps(payload).encode())

        client = PanelClient("http://panel.test", "synthetic-token-0123456789abcdef", opener=opener)
        self.assertEqual(len(client.fetch_targets()), MAX_MONITOR_BATCH + 1)
        self.assertIn("after_id=500&limit=500", requests[1][0].full_url)
        with self.assertRaises(ValueError):
            client.post_results([{"probe_type": "tcp"}])

    def test_run_cycle_and_selector_are_bounded(self):
        targets = [target(vpn_id=1), target(vpn_id=2)]
        posted = []

        class Client:
            def fetch_targets(self):
                return targets

            def post_results(self, results):
                posted.append(results)

        def probe(item):
            return {
                "vpn_id": item["vpn_id"], "target_revision": REVISION, "icmp_ok": True,
                "protocol_ok": False, "protocol_probe": "tcp", "checked_at": 1,
            }

        self.assertEqual(run_cycle(Client(), probe=probe, target_ids=frozenset({2})), 1)
        self.assertEqual([item["vpn_id"] for item in posted[0]], [2])
        self.assertEqual(parse_target_selector("2, 2"), frozenset({2}))
        self.assertIsNone(parse_target_selector(None))
        self.assertEqual(select_targets(targets, frozenset()), [])
        with self.assertRaises(ValueError):
            parse_target_selector("bad")

    def test_worker_runs_immediately_with_official_interval_and_bounded_backoff(self):
        self.assertEqual(DEFAULT_INTERVAL_SECONDS, 60.0)
        self.assertEqual(MAX_WORKERS, 4)
        calls = []

        class Client:
            def fetch_targets(self):
                return []

            def post_results(self, results):
                calls.append(results)

        self.assertEqual(run_worker(Client(), once=True, sleep=calls.append), 1)
        self.assertEqual(calls, [[]])
        sleeps = []
        self.assertEqual(run_worker(Client(), max_cycles=2, interval=60, sleep=sleeps.append, jitter=lambda _value: 0), 2)
        self.assertEqual(sleeps, [60.0])

    def test_token_loader_rejects_unbounded_or_invalid_secret_files(self):
        with mock.patch("vpn_endpoint_monitor.Path") as path_type:
            path_type.return_value.read_bytes.return_value = b"  synthetic-token-0123456789abcdef  \n"
            self.assertEqual(load_monitor_token("/run/secrets/token"), "synthetic-token-0123456789abcdef")
        with mock.patch("vpn_endpoint_monitor.Path") as path_type:
            path_type.return_value.read_bytes.return_value = b"short"
            with self.assertRaises(ValueError):
                load_monitor_token("/run/secrets/token")


if __name__ == "__main__":
    unittest.main()
