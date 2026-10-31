import os
import tempfile
import threading
import unittest
import uuid

from verdock_core.errors import Refused
from verdock_core.invariants import Invariants


class Clock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


class InvariantTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.path = os.path.join(self.tmp.name, "inv.sqlite3")
        self.clock = Clock()
        self.inv = Invariants(self.path, clock=self.clock)

    def tearDown(self):
        self.tmp.cleanup()

    def test_split_within_cap_then_refused(self):
        self.inv.reserve("cap-1", 1000, 600, "cust", "2026-10-31")
        self.inv.reserve("cap-1", 1000, 400, "cust", "2026-10-31")
        with self.assertRaises(Refused):
            self.inv.reserve("cap-1", 1000, 1, "cust", "2026-10-31")

    def test_release_frees_amount_commit_keeps_it(self):
        a = self.inv.reserve("cap-1", 1000, 700, "cust", "d")
        self.inv.release(a)
        b = self.inv.reserve("cap-1", 1000, 1000, "cust", "d")
        self.inv.commit(b)
        self.assertEqual(self.inv.group_total("cap-1"), 1000)
        with self.assertRaises(Refused):
            self.inv.reserve("cap-1", 1000, 1, "cust", "d")
        with self.assertRaises(Refused):
            self.inv.release(b)
        with self.assertRaises(Refused):
            self.inv.commit(a)

    def test_cap_cannot_change(self):
        self.inv.reserve("cap-1", 1000, 100, "cust", "d")
        with self.assertRaises(Refused):
            self.inv.reserve("cap-1", 5000, 100, "cust", "d")

    def test_customer_day_cap(self):
        self.inv.reserve("g1", 10000, 800, "cust", "d1", per_customer_day_cap_minor=1000)
        with self.assertRaises(Refused):
            self.inv.reserve("g2", 10000, 300, "cust", "d1", per_customer_day_cap_minor=1000)
        self.inv.reserve("g2", 10000, 300, "cust", "d2", per_customer_day_cap_minor=1000)
        self.inv.reserve("g2", 10000, 300, "other", "d1", per_customer_day_cap_minor=1000)

    def test_concurrent_split_never_exceeds_cap(self):
        cap, part, workers = 1000, 70, 40
        results = []
        barrier = threading.Barrier(workers)

        def agent():
            store = Invariants(self.path)
            barrier.wait()
            try:
                results.append(store.reserve("capture-9", cap, part, "cust", "d"))
            except Refused:
                results.append(None)

        threads = [threading.Thread(target=agent) for _ in range(workers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        granted = [r for r in results if r]
        self.assertEqual(len(results), workers)
        self.assertEqual(len(granted), cap // part)
        self.assertLessEqual(self.inv.group_total("capture-9"), cap)

    def test_lock_exclusive_and_expiry(self):
        self.assertTrue(self.inv.lock("order-1", "a", 30))
        self.assertFalse(self.inv.lock("order-1", "b", 30))
        self.assertTrue(self.inv.lock("order-1", "a", 30))
        self.assertFalse(self.inv.unlock("order-1", "b"))
        self.clock.now += 31
        self.assertTrue(self.inv.lock("order-1", "b", 30))
        self.assertFalse(self.inv.lock("order-1", "a", 30))
        self.assertTrue(self.inv.unlock("order-1", "b"))
        self.assertTrue(self.inv.lock("order-1", "a", 30))

    def test_concurrent_lock_has_one_winner(self):
        winners = []
        barrier = threading.Barrier(20)

        def agent(name):
            store = Invariants(self.path)
            barrier.wait()
            if store.lock("shared", name, 60):
                winners.append(name)

        threads = [threading.Thread(target=agent, args=("w%d" % i,)) for i in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(winners), 1)

    def test_request_id_stable(self):
        first = self.inv.request_id("refund:order-42")
        self.assertEqual(uuid.UUID(first).version, 4)
        self.assertEqual(first, self.inv.request_id("refund:order-42"))
        self.assertEqual(first, Invariants(self.path).request_id("refund:order-42"))
        self.assertNotEqual(first, self.inv.request_id("refund:order-43"))

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):
            self.inv.reserve("g", 100, -5, "c", "d")
        with self.assertRaises(ValueError):
            self.inv.reserve("g", 100, 1.5, "c", "d")
        with self.assertRaises(ValueError):
            self.inv.lock("k", "o", 0)


if __name__ == "__main__":
    unittest.main()
