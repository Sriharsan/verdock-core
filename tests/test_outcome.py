import os
import tempfile
import unittest

from verdock_core.errors import Refused
from verdock_core.outcome import (
    MISMATCH,
    PENDING,
    UNKNOWN,
    VERIFIED,
    OutcomeLog,
    Reconciler,
    compare,
    may_retry,
)

EXPECTED = {"id": "r-1", "amount_minor": 2500, "currency": "USD", "status": "completed"}
FIELDS = ("id", "amount_minor", "currency", "status")


class FakeProvider:
    def __init__(self, records):
        self.records = records

    def reconcile(self, operation):
        return self.records.get(operation)


class CompareTests(unittest.TestCase):
    def test_states(self):
        self.assertEqual(compare(EXPECTED, dict(EXPECTED), FIELDS), VERIFIED)
        self.assertEqual(compare(EXPECTED, None, FIELDS), UNKNOWN)
        self.assertEqual(compare(EXPECTED, dict(EXPECTED, amount_minor=2600), FIELDS), MISMATCH)
        partial = {"id": "r-1", "amount_minor": 2500}
        self.assertEqual(compare(EXPECTED, partial, FIELDS), UNKNOWN)
        pending = dict(EXPECTED, status="processing")
        self.assertEqual(
            compare(EXPECTED, pending, FIELDS, status_field="status", pending_values=("processing",)),
            PENDING,
        )
        self.assertEqual(compare(EXPECTED, pending, FIELDS), MISMATCH)

    def test_type_strict(self):
        self.assertEqual(compare({"a": 1}, {"a": True}, ["a"]), MISMATCH)
        self.assertEqual(compare({"a": 1}, {"a": "1"}, ["a"]), MISMATCH)

    def test_field_must_be_expected(self):
        with self.assertRaises(ValueError):
            compare(EXPECTED, EXPECTED, ["missing"])

    def test_may_retry(self):
        self.assertFalse(may_retry(UNKNOWN))
        self.assertFalse(may_retry(VERIFIED))
        self.assertFalse(may_retry(PENDING))
        self.assertTrue(may_retry(MISMATCH))
        self.assertFalse(may_retry(MISMATCH, retry="never"))
        with self.assertRaises(ValueError):
            may_retry("DONE")

    def test_reconciler_protocol(self):
        provider = FakeProvider({"op-1": dict(EXPECTED)})
        reconciler: Reconciler = provider
        self.assertEqual(compare(EXPECTED, reconciler.reconcile("op-1"), FIELDS), VERIFIED)
        self.assertEqual(compare(EXPECTED, reconciler.reconcile("op-2"), FIELDS), UNKNOWN)


class OutcomeLogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.log = OutcomeLog(os.path.join(self.tmp.name, "o.sqlite3"))

    def tearDown(self):
        self.tmp.cleanup()

    def test_unknown_needs_matching_record_to_verify(self):
        self.log.expect("op-1", EXPECTED, FIELDS)
        self.log.record("op-1", UNKNOWN)
        with self.assertRaises(Refused):
            self.log.record("op-1", VERIFIED)
        with self.assertRaises(Refused):
            self.log.record("op-1", VERIFIED, dict(EXPECTED, amount_minor=1))
        with self.assertRaises(Refused):
            self.log.record("op-1", VERIFIED, {"id": "r-1"})
        self.assertEqual(self.log.latest("op-1"), UNKNOWN)
        self.log.record("op-1", VERIFIED, dict(EXPECTED))
        self.assertEqual([h["state"] for h in self.log.history("op-1")], [UNKNOWN, VERIFIED])
        self.assertEqual(self.log.history("op-1")[1]["observed"], EXPECTED)

    def test_unknown_without_expectation_cannot_verify(self):
        self.log.record("op-2", UNKNOWN)
        with self.assertRaises(Refused):
            self.log.record("op-2", VERIFIED, dict(EXPECTED))

    def test_pending_status_does_not_verify(self):
        self.log.expect("op-3", EXPECTED, FIELDS, status_field="status", pending_values=["processing"])
        self.log.record("op-3", PENDING, dict(EXPECTED, status="processing"))
        with self.assertRaises(Refused):
            self.log.record("op-3", VERIFIED, dict(EXPECTED, status="processing"))

    def test_expect_once_and_bad_state(self):
        self.log.expect("op-4", EXPECTED, FIELDS)
        with self.assertRaises(Refused):
            self.log.expect("op-4", EXPECTED, FIELDS)
        with self.assertRaises(ValueError):
            self.log.record("op-4", "DONE")
        self.assertIsNone(self.log.latest("never-seen"))


if __name__ == "__main__":
    unittest.main()
