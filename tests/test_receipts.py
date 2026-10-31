import hashlib
import json
import os
import sys
import tempfile
import unittest

from verdock_core import ed25519
from verdock_core.receipts import (
    ReceiptError,
    ReceiptLog,
    build_line,
    canonical_bytes,
    create_seed,
    line_hash,
    load_seed,
    verify_log,
)

sys.path.insert(0, os.path.dirname(__file__))
from vectors import (  # noqa: E402
    PUBLIC_KEY, SEED, V1_CANONICAL, V1_LINE, V1_SHA256, V1_SIGNATURE,
    V2_CANONICAL, V2_LINE, V2_SIGNATURE,
)

ACTOR = {"agent": "claude-code", "user": "alice"}


def reasons(report):
    return [(f["line"], f["reason"]) for f in report["failures"]]


class Ed25519Tests(unittest.TestCase):
    def test_rfc8032_test_1(self):
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        self.assertEqual(ed25519.public_key(seed).hex(),
                         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        sig = ed25519.sign(seed, b"")
        self.assertEqual(sig.hex(),
                         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                         "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        self.assertTrue(ed25519.verify(ed25519.public_key(seed), b"", sig))

    def test_rejects_bad_signatures(self):
        pub = ed25519.public_key(SEED)
        sig = ed25519.sign(SEED, b"m")
        self.assertFalse(ed25519.verify(pub, b"n", sig))
        flipped = bytes([sig[0] ^ 1]) + sig[1:]
        self.assertFalse(ed25519.verify(pub, b"m", flipped))
        big_s = sig[:32] + (int.from_bytes(sig[32:], "little") + 2 ** 252
                            + 27742317777372353535851937790883648493).to_bytes(32, "little")
        self.assertFalse(ed25519.verify(pub, b"m", big_s))
        self.assertFalse(ed25519.verify(pub[:31], b"m", sig))


class VectorTests(unittest.TestCase):
    def test_public_key(self):
        self.assertEqual(ed25519.public_key(SEED).hex(), PUBLIC_KEY)

    def test_vector_1(self):
        receipt = json.loads(V1_LINE)
        self.assertEqual(canonical_bytes(receipt), V1_CANONICAL.encode("utf-8"))
        self.assertEqual(ed25519.sign(SEED, V1_CANONICAL.encode()).hex(), V1_SIGNATURE)
        line = build_line("01J8Z7QX9K", "kriya.gate.decision",
                          {"rule_id": "npm-publish", "tier": "approve", "class": "publish"},
                          True, 1755300000000, SEED, actor=ACTOR)
        self.assertEqual(line, V1_LINE)
        self.assertEqual(hashlib.sha256(line.encode()).hexdigest(), V1_SHA256)

    def test_vector_2(self):
        receipt = json.loads(V2_LINE)
        self.assertEqual(canonical_bytes(receipt), V2_CANONICAL.encode("utf-8"))
        line = build_line("01J8Z7QXB2", "kriya.gate.approval",
                          {"rule_id": "npm-publish", "approver": "alice", "decision": "approved"},
                          True, 1755300012000, SEED, actor=ACTOR, prev_hash=V1_SHA256)
        self.assertEqual(line, V2_LINE)
        self.assertEqual(json.loads(line)["signature"], V2_SIGNATURE)

    def test_vectors_verify(self):
        report = verify_log([V1_LINE, V2_LINE], PUBLIC_KEY)
        self.assertEqual(report, {"ok": True, "count": 2, "failures": []})

    def test_vector_3_tamper(self):
        tampered = V1_LINE.replace('"user":"alice"', '"user":"mallory"')
        report = verify_log([tampered, V2_LINE], PUBLIC_KEY)
        self.assertFalse(report["ok"])
        self.assertEqual(reasons(report), [(1, "signature invalid"), (2, "chain break")])


class CanonicalTests(unittest.TestCase):
    def _receipt(self, params):
        return {"step_id": "s", "action_id": "a", "params": params, "success": False, "ts_ms": 0}

    def test_recursive_sort_and_arrays(self):
        got = canonical_bytes(self._receipt({"b": [3, {"z": 1, "a": 2}], "a": None}))
        self.assertEqual(got, b'{"step_id":"s","action_id":"a","params":{"a":null,"b":[3,{"a":2,"z":1}]},'
                              b'"success":false,"ts_ms":0}')

    def test_code_point_order_and_escapes(self):
        params = {"\U0001F600": 1, "\uff61": 2, "a\nb": "\x01\u00e9\"\\/"}
        got = canonical_bytes(self._receipt(params)).decode("utf-8")
        self.assertIn('{"a\\nb":"\\u0001\u00e9\\"\\\\/","\uff61":2,"\U0001F600":1}', got)

    def test_rejects_floats_and_big_ints(self):
        with self.assertRaises(ReceiptError):
            canonical_bytes(self._receipt({"x": 1.0}))
        with self.assertRaises(ReceiptError):
            canonical_bytes(self._receipt({"x": 2 ** 53}))

    def test_actor_order_fixed(self):
        receipt = dict(self._receipt({}), actor={"user": "u", "agent": "g"})
        self.assertTrue(canonical_bytes(receipt).endswith(b'"actor":{"agent":"g","user":"u"}}'))


class LogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.path = os.path.join(self.tmp.name, "receipts.ndjson")
        self.seed_path = os.path.join(self.tmp.name, "agent.seed")

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, n=4):
        seed = create_seed(self.seed_path)
        log = ReceiptLog(self.path, seed)
        for i in range(n):
            log.append("step-%d" % i, "refund.create", {"amount_minor": 100 * i, "currency": "USD"},
                       True, actor={"agent": "refunds", "user": "sri"}, extra={"note": "n%d" % i})
        return log.public_key

    def _lines(self):
        with open(self.path, "rb") as handle:
            return handle.read().decode("utf-8").split("\n")[:-1]

    def test_seed_roundtrip_and_no_overwrite(self):
        seed = create_seed(self.seed_path)
        self.assertEqual(load_seed(self.seed_path), seed)
        with self.assertRaises(FileExistsError):
            create_seed(self.seed_path)

    def test_written_log_verifies_and_resumes(self):
        pub = self._write(3)
        log = ReceiptLog(self.path, load_seed(self.seed_path))
        log.append("step-3", "refund.create", {"amount_minor": 1}, False)
        lines = self._lines()
        self.assertEqual(len(lines), 4)
        self.assertNotIn("prev_hash", json.loads(lines[0]))
        self.assertEqual(json.loads(lines[3])["prev_hash"], line_hash(lines[2]))
        self.assertEqual(verify_log(self.path, pub), {"ok": True, "count": 4, "failures": []})
        with open(self.path, "rb") as handle:
            self.assertTrue(handle.read().endswith(b"}\n"))

    def test_extra_members_unsigned_but_chained(self):
        pub = self._write(3)
        lines = self._lines()
        lines[1] = lines[1].replace('"note":"n1"', '"note":"changed"')
        self.assertEqual(reasons(verify_log(lines, pub)), [(3, "chain break")])

    def test_reserved_extra_rejected(self):
        log = ReceiptLog(self.path, SEED)
        with self.assertRaises(ReceiptError):
            log.append("s", "a", {}, True, extra={"signature": "x"})
        with self.assertRaises(ReceiptError):
            log.append("s", "a", {"x": 0.5}, True)

    def test_tamper_cases(self):
        pub = self._write(4)
        lines = self._lines()

        edited = list(lines)
        edited[1] = edited[1].replace('"amount_minor":100', '"amount_minor":900')
        self.assertEqual(reasons(verify_log(edited, pub)), [(2, "signature invalid"), (3, "chain break")])

        deleted = lines[:1] + lines[2:]
        self.assertEqual(reasons(verify_log(deleted, pub)), [(2, "chain break")])

        first_deleted = lines[1:]
        self.assertEqual(reasons(verify_log(first_deleted, pub)), [(1, "unexpected prev_hash on first line")])

        inserted = lines[:2] + [lines[1]] + lines[2:]
        self.assertEqual(reasons(verify_log(inserted, pub)), [(3, "chain break")])

        reordered = [lines[0], lines[2], lines[1], lines[3]]
        self.assertEqual(reasons(verify_log(reordered, pub)),
                         [(2, "chain break"), (3, "chain break"), (4, "chain break")])

        wrong = verify_log(lines, PUBLIC_KEY)
        self.assertEqual(reasons(wrong), [(i, "untrusted public key") for i in range(1, 5)])

        junk = lines[:2] + ["this is not a receipt"] + lines[2:]
        self.assertEqual(reasons(verify_log(junk, pub)), [(3, "invalid JSON"), (4, "chain break")])

        unsigned = dict(json.loads(lines[1]))
        del unsigned["signature"]
        junk2 = lines[:2] + [json.dumps(unsigned, separators=(",", ":"))]
        self.assertEqual(reasons(verify_log(junk2, pub)), [(3, "missing member: signature")])

        blank = lines[:2] + [""] + lines[2:]
        self.assertEqual(reasons(verify_log(blank, pub)), [(3, "empty line"), (4, "chain break")])

    def test_type_and_hex_checks(self):
        base = json.loads(V1_LINE)
        cases = [
            (dict(base, success="true"), "wrong type: success"),
            (dict(base, ts_ms=1.5), "non-integer number"),
            (dict(base, ts_ms=2 ** 60), "integer out of range"),
            (dict(base, actor={"agent": "a", "role": "x"}), "wrong type: actor"),
            (dict(base, public_key=PUBLIC_KEY.upper()), "invalid hex: public_key"),
            (dict(base, signature=V1_SIGNATURE[:-2]), "invalid hex: signature"),
        ]
        for receipt, reason in cases:
            with self.subTest(reason=reason):
                line = json.dumps(receipt, separators=(",", ":"))
                self.assertIn(reason, [r for _, r in reasons(verify_log([line], PUBLIC_KEY))])
        self.assertEqual(reasons(verify_log(["[1,2]"], PUBLIC_KEY)), [(1, "not an object")])

    def test_empty_log_and_bad_anchor(self):
        self.assertEqual(verify_log([], PUBLIC_KEY), {"ok": True, "count": 0, "failures": []})
        with self.assertRaises(ValueError):
            verify_log([V1_LINE], "abc")


if __name__ == "__main__":
    unittest.main()
