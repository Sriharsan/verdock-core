import json
import os
import tempfile
import unittest

from verdock_core.errors import PolicyError
from verdock_core.policy import (
    LEVELS,
    decide,
    load_policy,
    loads_policy,
    parse_yaml_subset,
    policy_hash,
    validate_policy,
)

POLICY_YAML = """\
# refunds policy
version: 1
operations:
  refund:
    level: Execute within Limits
    max_amount_minor: 5000
    approval_above_minor: 2000   # ask a person above 20.00
    currency: USD
    retry: safe
  capture:
    level: Execute with Approval
    max_amount_minor: 100000
  reply:
    level: Draft
  lookup:
    level: "Assist"
caps:
  per_customer_per_day_minor: 10000
"""


class ParserTests(unittest.TestCase):
    def test_parses_subset(self):
        data = parse_yaml_subset(
            "a: 1\nb: 'it''s'\nc: \"q\\\"x\"\nd: true\ne:\n  - x\n  - 2\nf:\n- z\ng: plain text # note\n"
        )
        self.assertEqual(
            data,
            {"a": 1, "b": "it's", "c": 'q"x', "d": True, "e": ["x", 2], "f": ["z"], "g": "plain text"},
        )

    def test_hash_inside_quotes_is_not_a_comment(self):
        self.assertEqual(parse_yaml_subset('a: "x # y"\n'), {"a": "x # y"})

    def test_rejects_unsupported_syntax(self):
        bad = [
            "a: {b: 1}\n",
            "a: [1, 2]\n",
            "a: &anchor 1\n",
            "a: *anchor\n",
            "a: !tag x\n",
            "a: |\n  text\n",
            "a: >\n  text\n",
            "---\na: 1\n",
            "a: 1.5\n",
            "a: null\n",
            "a: yes\n",
            "a: True\n",
            "a: 007\n",
            "a:\n\t b: 1\n",
            "a: 1\na: 2\n",
            "a:\n  - b: 1\n",
            "a:\n  - - 1\n",
            "a:\n",
            "  a: 1\n",
            "a: 1\n   b: 2\n",
            "- 1\n",
            '"a": 1\n',
            "a:b\n",
            "a: 'open\n",
            'a: "bad \\n escape"\n',
            "a: b: c\n",
            "",
        ]
        for text in bad:
            with self.subTest(text=text):
                with self.assertRaises(PolicyError):
                    parse_yaml_subset(text)

    def test_error_names_line(self):
        with self.assertRaises(PolicyError) as ctx:
            parse_yaml_subset("a: 1\nb: [1]\n")
        self.assertIn("line 2", str(ctx.exception))


class ValidationTests(unittest.TestCase):
    def test_loads_yaml_and_json_equally(self):
        from_yaml = loads_policy(POLICY_YAML)
        from_json = loads_policy(json.dumps(parse_yaml_subset(POLICY_YAML)), "json")
        self.assertEqual(from_yaml, from_json)
        self.assertEqual(from_yaml["operations"]["reply"]["retry"], "never")

    def test_load_policy_from_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            yaml_path = os.path.join(tmp, "policy.yaml")
            json_path = os.path.join(tmp, "policy.json")
            with open(yaml_path, "w", encoding="utf-8") as handle:
                handle.write(POLICY_YAML)
            with open(json_path, "w", encoding="utf-8") as handle:
                json.dump(parse_yaml_subset(POLICY_YAML), handle)
            self.assertEqual(policy_hash(load_policy(yaml_path)), policy_hash(load_policy(json_path)))

    def test_rejects_invalid_policies(self):
        base = parse_yaml_subset(POLICY_YAML)
        cases = []

        def variant(mutate):
            data = json.loads(json.dumps(base))
            mutate(data)
            cases.append(data)

        variant(lambda d: d.update(extra=1))
        variant(lambda d: d.update(version=2))
        variant(lambda d: d.pop("version"))
        variant(lambda d: d.update(version=True))
        variant(lambda d: d["operations"]["refund"].update(level="Execute"))
        variant(lambda d: d["operations"]["refund"].update(max_amount_minor=-1))
        variant(lambda d: d["operations"]["refund"].update(max_amount_minor=True))
        variant(lambda d: d["operations"]["refund"].update(max_amount_minor="5"))
        variant(lambda d: d["operations"]["refund"].update(retry="always"))
        variant(lambda d: d["operations"]["refund"].update(currency="usd"))
        variant(lambda d: d["operations"]["refund"].update(note="x"))
        variant(lambda d: d["operations"]["refund"].pop("level"))
        variant(lambda d: d["caps"].update(per_day=1))
        variant(lambda d: d.update(caps=[]))
        variant(lambda d: d.update(operations=[]))
        for data in cases:
            with self.subTest(data=data):
                with self.assertRaises(PolicyError):
                    validate_policy(data)

    def test_json_rejects_floats(self):
        with self.assertRaises(PolicyError):
            loads_policy('{"version": 1, "operations": {"a": {"level": "Draft", "max_amount_minor": 1.0}}}', "json")

    def test_policy_edit_changes_hash(self):
        policy = loads_policy(POLICY_YAML)
        original = policy_hash(policy)
        self.assertRegex(original, r"^[0-9a-f]{64}$")
        self.assertEqual(original, policy_hash(loads_policy(POLICY_YAML)))
        edited = loads_policy(POLICY_YAML.replace("max_amount_minor: 5000", "max_amount_minor: 5001"))
        self.assertNotEqual(original, policy_hash(edited))
        relevel = loads_policy(POLICY_YAML.replace("level: Draft", "level: Assist"))
        self.assertNotEqual(original, policy_hash(relevel))

    def test_default_retry_hashes_like_explicit_never(self):
        a = loads_policy("version: 1\noperations:\n  x:\n    level: Draft\n")
        b = loads_policy("version: 1\noperations:\n  x:\n    level: Draft\n    retry: never\n")
        self.assertEqual(policy_hash(a), policy_hash(b))


class DecideTests(unittest.TestCase):
    def setUp(self):
        self.policy = loads_policy(POLICY_YAML)

    def test_levels_constant(self):
        self.assertEqual(LEVELS, ("Assist", "Draft", "Execute with Approval", "Execute within Limits"))

    def test_within_limits(self):
        d = decide(self.policy, "refund", 1500)
        self.assertTrue(d.allowed)
        self.assertFalse(d.needs_approval)
        self.assertEqual(d.limit_minor, 5000)
        self.assertEqual(d.level, "Execute within Limits")

    def test_approval_above_threshold(self):
        d = decide(self.policy, "refund", 2001)
        self.assertTrue(d.allowed)
        self.assertTrue(d.needs_approval)
        self.assertFalse(decide(self.policy, "refund", 2000).needs_approval)

    def test_refuses_above_limit(self):
        d = decide(self.policy, "refund", 5001)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "above limit")
        self.assertTrue(decide(self.policy, "refund", 5000).allowed)

    def test_execute_with_approval_level(self):
        d = decide(self.policy, "capture", 10)
        self.assertTrue(d.allowed)
        self.assertTrue(d.needs_approval)

    def test_draft_levels_never_execute(self):
        for op in ("reply", "lookup"):
            d = decide(self.policy, op, 0)
            self.assertFalse(d.allowed)
            self.assertEqual(d.reason, "draft only")

    def test_unknown_operation(self):
        d = decide(self.policy, "wire_everything", 1)
        self.assertFalse(d.allowed)
        self.assertIsNone(d.level)
        self.assertEqual(d.reason, "unknown operation")

    def test_invalid_amount_and_currency(self):
        self.assertFalse(decide(self.policy, "refund", -1).allowed)
        self.assertFalse(decide(self.policy, "refund", 10.0).allowed)
        self.assertFalse(decide(self.policy, "refund", True).allowed)
        self.assertEqual(decide(self.policy, "refund", 10, currency="EUR").reason, "currency mismatch")
        self.assertTrue(decide(self.policy, "refund", 10, currency="USD").allowed)


if __name__ == "__main__":
    unittest.main()
