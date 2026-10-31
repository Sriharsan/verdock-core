import os
import tempfile
import unittest

from verdock_core.approvals import ApprovalStore
from verdock_core.errors import Refused


class Clock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.clock = Clock()
        self.store = ApprovalStore(os.path.join(self.tmp.name, "a.sqlite3"), clock=self.clock)

    def tearDown(self):
        self.tmp.cleanup()

    def _request(self, **kw):
        args = dict(operation="refund", action="refund order 42", subject="order-42",
                    amount_minor=2500, currency="USD", limit_minor=5000,
                    requested_by="agent-1", ttl_seconds=600)
        args.update(kw)
        return self.store.request(**args)

    def test_full_flow_and_record_fields(self):
        approval_id = self._request()
        self.assertEqual(self.store.get(approval_id)["status"], "pending")
        self.clock.now += 5
        self.store.approve(approval_id, "sri")
        record = self.store.require(approval_id, "refund", "order-42", 2500, "USD")
        self.assertEqual(record["approver"], "sri")
        self.assertEqual(record["requested_at"], 1000.0)
        self.assertEqual(record["decided_at"], 1005.0)
        self.assertEqual(record["limit_minor"], 5000)
        used = self.store.consume(approval_id)
        self.assertEqual(used["status"], "consumed")
        self.assertEqual([r["id"] for r in self.store.list("consumed")], [approval_id])

    def test_pending_cannot_be_used(self):
        approval_id = self._request()
        with self.assertRaises(Refused):
            self.store.require(approval_id, "refund", "order-42", 2500, "USD")
        with self.assertRaises(Refused):
            self.store.consume(approval_id)

    def test_requires_exact_match(self):
        approval_id = self._request()
        self.store.approve(approval_id, "sri")
        for args in (("capture", "order-42", 2500, "USD"),
                     ("refund", "order-43", 2500, "USD"),
                     ("refund", "order-42", 2501, "USD"),
                     ("refund", "order-42", 2499, "USD"),
                     ("refund", "order-42", 2500, "EUR")):
            with self.subTest(args=args):
                with self.assertRaises(Refused):
                    self.store.require(approval_id, *args)
        self.store.require(approval_id, "refund", "order-42", 2500, "USD")

    def test_expired_cannot_be_approved_or_used(self):
        late = self._request(ttl_seconds=10)
        self.clock.now += 11
        with self.assertRaises(Refused):
            self.store.approve(late, "sri")
        used_late = self._request(ttl_seconds=10)
        self.store.approve(used_late, "sri")
        self.clock.now += 11
        self.assertTrue(self.store.get(used_late)["expired"])
        with self.assertRaises(Refused):
            self.store.require(used_late, "refund", "order-42", 2500, "USD")
        with self.assertRaises(Refused):
            self.store.consume(used_late)

    def test_single_use(self):
        approval_id = self._request()
        self.store.approve(approval_id, "sri")
        self.store.consume(approval_id)
        with self.assertRaises(Refused):
            self.store.consume(approval_id)
        with self.assertRaises(Refused):
            self.store.require(approval_id, "refund", "order-42", 2500, "USD")

    def test_reject_and_decide_once(self):
        approval_id = self._request()
        self.store.reject(approval_id, "sri", "amount looks wrong")
        record = self.store.get(approval_id)
        self.assertEqual((record["status"], record["reason"]), ("rejected", "amount looks wrong"))
        with self.assertRaises(Refused):
            self.store.approve(approval_id, "sri")
        with self.assertRaises(Refused):
            self.store.require(approval_id, "refund", "order-42", 2500, "USD")

    def test_requester_cannot_approve(self):
        approval_id = self._request()
        with self.assertRaises(Refused):
            self.store.approve(approval_id, "agent-1")

    def test_unknown_and_invalid(self):
        with self.assertRaises(Refused):
            self.store.approve("nope", "sri")
        self.assertIsNone(self.store.get("nope"))
        with self.assertRaises(ValueError):
            self._request(amount_minor=-1)
        with self.assertRaises(ValueError):
            self._request(amount_minor=1.5)
        with self.assertRaises(ValueError):
            self.store.list("bogus")

    def test_list(self):
        a = self._request()
        b = self._request(subject="order-43")
        self.store.approve(b, "sri")
        self.assertEqual([r["id"] for r in self.store.list()], [a, b])
        self.assertEqual([r["id"] for r in self.store.list("pending")], [a])


if __name__ == "__main__":
    unittest.main()
