import json
import os
import socket
import tempfile
import threading
import unittest

from verdock_core import PolicyError
from verdock_core.egress import EgressGateway, allowed_hosts, parse_connect
from verdock_core.policy import loads_policy, policy_hash
from verdock_core.queue import HELD, RESUMED, HeldQueue
from verdock_core.receipts import ReceiptLog, create_seed, load_seed, verify_log

POLICY = """version: 1
operations:
  refund:
    level: Execute within Limits
egress:
  allow_hosts:
    - api-m.sandbox.paypal.com
"""


class Upstream:
    """A local echo server standing in for the provider, so the tests make no internet call."""

    def __init__(self):
        self.sock = socket.socket(); self.sock.bind(("127.0.0.1", 0)); self.sock.listen()
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            data = conn.recv(1024); conn.sendall(b"echo:" + data); conn.close()


class EgressTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        seed = os.path.join(self.tmp.name, "egress.seed"); create_seed(seed)
        self.log = ReceiptLog(os.path.join(self.tmp.name, "egress.ndjson"), load_seed(seed))
        self.upstream = Upstream()
        self.online = True

        def connect(host, port):
            if not self.online:
                raise OSError("network cut")
            return socket.create_connection(self.upstream.sock.getsockname(), timeout=5)
        self.gateway = EgressGateway(("127.0.0.1", 0), allowed_hosts(loads_policy(POLICY)), self.log, connect=connect, timeout=2)
        threading.Thread(target=self.gateway.serve_forever, daemon=True).start()

    def tearDown(self):
        self.gateway.shutdown(); self.gateway.server_close(); self.upstream.sock.close(); self.tmp.cleanup()

    def ask(self, target, payload=b""):
        with socket.create_connection(self.gateway.server_address, timeout=5) as conn:
            conn.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
            reply = conn.recv(1024)
            if payload and reply.startswith(b"HTTP/1.1 200"):
                conn.sendall(payload); reply += conn.recv(1024)
            return reply

    def receipts(self):
        with open(self.log.path, encoding="utf-8") as handle:
            return [json.loads(line) for line in handle]

    def test_allowlisted_host_is_tunnelled_and_receipted(self):
        reply = self.ask("api-m.sandbox.paypal.com:443", b"hello")
        self.assertTrue(reply.startswith(b"HTTP/1.1 200")); self.assertIn(b"echo:hello", reply)
        self.gateway.shutdown()
        last = self.receipts()[-1]
        self.assertEqual(last["action_id"], "verdock.egress.allowed")
        self.assertEqual((last["params"]["host"], last["params"]["sent"]), ("api-m.sandbox.paypal.com", 5))

    def test_a_host_off_the_allowlist_is_blocked_and_receipted(self):
        for target in ("api-m.paypal.com:443", "example.com:443", "api-m.sandbox.paypal.com:80"):
            self.assertTrue(self.ask(target).startswith(b"HTTP/1.1 403"))
        blocked = [r for r in self.receipts() if r["action_id"] == "verdock.egress.blocked"]
        self.assertEqual([r["params"]["host"] for r in blocked], ["api-m.paypal.com", "example.com", "api-m.sandbox.paypal.com"])
        self.assertTrue(all(r["success"] is False for r in blocked))

    def test_plain_http_requests_are_refused(self):
        with socket.create_connection(self.gateway.server_address, timeout=5) as conn:
            conn.sendall(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            self.assertTrue(conn.recv(1024).startswith(b"HTTP/1.1 405"))

    def test_network_cut_answers_502_before_anything_is_sent(self):
        self.online = False
        self.assertTrue(self.ask("api-m.sandbox.paypal.com:443").startswith(b"HTTP/1.1 502"))
        self.assertEqual(self.receipts()[-1]["action_id"], "verdock.egress.offline")

    def test_gateway_receipts_verify_with_no_network(self):
        self.ask("example.com:443"); self.ask("api-m.sandbox.paypal.com:443", b"x")
        self.gateway.shutdown()
        self.assertTrue(verify_log(self.log.path, self.log.public_key)["ok"])

    def test_parse_connect_rejects_odd_targets(self):
        self.assertEqual(parse_connect(b"CONNECT api-m.sandbox.paypal.com:443 HTTP/1.1\r\n\r\n"), ("api-m.sandbox.paypal.com", 443))
        for bad in (b"CONNECT 10.0.0.1:443 HTTP/1.1\r\n", b"CONNECT a b:443 HTTP/1.1\r\n", b"CONNECT host:99999 HTTP/1.1\r\n", b"\xff\r\n"):
            self.assertIsNone(parse_connect(bad))


class PolicyEgressTests(unittest.TestCase):
    def test_egress_allowlist_is_validated_and_hashed(self):
        policy = loads_policy(POLICY)
        self.assertEqual(allowed_hosts(policy), ("api-m.sandbox.paypal.com",))
        self.assertNotEqual(policy_hash(policy), policy_hash(loads_policy(POLICY.replace("api-m.sandbox", "api-m"))))
        self.assertEqual(allowed_hosts(loads_policy(POLICY.split("egress:")[0])), ())
        for bad in ("egress:\n  allow_hosts:\n    - https://x.com\n", "egress:\n  hosts:\n    - x.com\n"):
            with self.assertRaises(PolicyError):
                loads_policy(POLICY.split("egress:")[0] + bad)


class HeldQueueTests(unittest.TestCase):
    def test_held_actions_keep_their_request_id_and_close_once(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as folder:
            queue = HeldQueue(os.path.join(folder, "held.sqlite3"))
            first = queue.hold("refund:c1", "refund", "rid-1", {"amount_minor": 150})
            again = queue.hold("refund:c1", "refund", "rid-2", {"amount_minor": 999})
            self.assertEqual((first["state"], again["request_id"], again["params"]["amount_minor"]), (HELD, "rid-1", 150))
            self.assertEqual([e["key"] for e in queue.held()], ["refund:c1"])
            queue.close("refund:c1", RESUMED, "PayPal record read first")
            queue.close("refund:c1", "dropped")
            self.assertEqual((queue.get("refund:c1")["state"], queue.held()), (RESUMED, []))


if __name__ == "__main__":
    unittest.main()
