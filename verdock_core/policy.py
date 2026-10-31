"""Action policies: load, validate, hash and decide.

A policy says, for each named operation, how far an agent may go on its own.
The model proposes an operation and an amount; decide() answers from the
policy alone. Nothing here reads free text.

Policy schema (version 1)::

    version: 1
    operations:
      refund:
        level: Execute within Limits     # one of LEVELS
        max_amount_minor: 5000           # optional, integer >= 0
        approval_above_minor: 2000       # optional, integer >= 0
        currency: USD                    # optional, three upper case letters
        retry: safe                      # optional, "never" (default) or "safe"
    caps:                                # optional
      per_customer_per_day_minor: 10000  # optional, integer >= 0
    egress:                              # optional; without it nothing may leave
      allow_hosts:                       # host names the egress gateway may reach
        - api-m.sandbox.paypal.com

Amounts are integers in minor units (cents for USD).

Policy files are JSON (.json) or a small YAML subset (any other suffix):

* block mappings ``key: value`` with keys made of letters, digits, ``_``,
  ``.`` and ``-`` (starting with a letter or ``_``);
* nested mappings by indentation with spaces (tabs are rejected);
* block lists of scalars ``- value``;
* scalars: integers without leading zeros, ``true`` and ``false``,
  double quoted strings (escapes ``\\"`` and ``\\\\`` only), single quoted
  strings (``''`` for a quote) and plain strings;
* ``#`` comments at the start of a line or after a space.

Anything else is rejected with a PolicyError that names the line: flow
collections (``{}``, ``[]``), anchors, tags, block scalars (``|``, ``>``),
multiple documents, floats, null and ambiguous words such as ``yes``,
``no``, ``on``, ``off``, ``True``.

policy_hash() is the SHA-256 hex digest of the validated policy encoded as
JSON with sorted keys, no whitespace (separators ``,`` and ``:``), UTF-8 and
non ASCII characters kept as is. Validation fills ``retry`` with its default
before hashing, so a file that omits ``retry`` hashes the same as one that
writes ``retry: never``. Any change to a level, limit, currency, retry rule
or cap changes the hash.
"""

import dataclasses
import hashlib
import json
import pathlib
import re

from .errors import PolicyError

LEVELS = ("Assist", "Draft", "Execute with Approval", "Execute within Limits")
RETRY_VALUES = ("never", "safe")

_OPERATION_KEYS = {"level", "max_amount_minor", "approval_above_minor", "currency", "retry"}
_CAP_KEYS = {"per_customer_per_day_minor"}
_TOP_KEYS = {"version", "operations", "caps", "egress"}
_EGRESS_KEYS = {"allow_hosts"}
_HOST_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
_CURRENCY_RE = re.compile(r"[A-Z]{3}")


# YAML subset parser

_KEY_LINE = re.compile(r"([A-Za-z_][A-Za-z0-9_.-]*):(?: +(.*))?")
_INT_RE = re.compile(r"-?(?:0|[1-9][0-9]*)")
_FLOAT_RE = re.compile(r"[-+]?(?:[0-9]+\.[0-9]*|\.[0-9]+|[0-9]+(?:\.[0-9]*)?[eE][-+]?[0-9]+)")
_AMBIGUOUS = {
    "yes", "no", "on", "off", "y", "n", "null", "none", "~",
    "true", "false", ".inf", "-.inf", ".nan",
}
_PLAIN_FORBIDDEN_START = set("[]{}&*!|>%@`'\",#?:-+")


class _Line:
    __slots__ = ("number", "indent", "text")

    def __init__(self, number, indent, text):
        self.number = number
        self.indent = indent
        self.text = text


def _error(number, message):
    return PolicyError("line %d: %s" % (number, message))


def _strip_comment(raw, number):
    quote = None
    for index, char in enumerate(raw):
        if quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            if index == 0 or raw[index - 1] in " :-":
                quote = char
        elif char == "#" and (index == 0 or raw[index - 1] == " "):
            return raw[:index]
    return raw


def _lines(text):
    result = []
    for number, raw in enumerate(text.split("\n"), 1):
        if raw.endswith("\r"):
            raw = raw[:-1]
        stripped_left = raw.lstrip(" ")
        if stripped_left.startswith("\t"):
            raise _error(number, "tabs are not allowed for indentation")
        content = _strip_comment(raw, number).rstrip(" \t")
        body = content.lstrip(" ")
        if not body:
            continue
        if body in ("---", "...") or body.startswith("%"):
            raise _error(number, "documents and directives are not supported")
        result.append(_Line(number, len(content) - len(body), body))
    return result


def _is_list_item(line):
    return line.text == "-" or line.text.startswith("- ")


def _scalar(text, number):
    if text.startswith('"'):
        if len(text) < 2 or not text.endswith('"'):
            raise _error(number, "unterminated double quoted string")
        out = []
        inner = text[1:-1]
        index = 0
        while index < len(inner):
            char = inner[index]
            if char == "\\":
                if index + 1 >= len(inner) or inner[index + 1] not in '"\\':
                    raise _error(number, 'only \\" and \\\\ escapes are supported')
                out.append(inner[index + 1])
                index += 2
                continue
            if char == '"':
                raise _error(number, "unexpected quote inside string")
            out.append(char)
            index += 1
        return "".join(out)
    if text.startswith("'"):
        if len(text) < 2 or not text.endswith("'"):
            raise _error(number, "unterminated single quoted string")
        inner = text[1:-1]
        if "'" in inner.replace("''", ""):
            raise _error(number, "unexpected quote inside string")
        return inner.replace("''", "'")
    if text == "true":
        return True
    if text == "false":
        return False
    if _INT_RE.fullmatch(text):
        return int(text)
    if re.fullmatch(r"[-+]?[0-9]+", text):
        raise _error(number, "integers must not have a sign of + or leading zeros")
    if _FLOAT_RE.fullmatch(text):
        raise _error(number, "floats are not supported; use integer minor units")
    if text.lower() in _AMBIGUOUS:
        raise _error(number, "ambiguous value %r; quote it if it is a string" % text)
    if text[0] in _PLAIN_FORBIDDEN_START:
        raise _error(number, "unsupported syntax %r; quote strings that start with symbols" % text[0])
    if ": " in text or text.endswith(":"):
        raise _error(number, "unexpected ':' in value; quote the string")
    if "\t" in text:
        raise _error(number, "tabs are not allowed in plain values")
    return text


def _list_item(line):
    if line.text == "-":
        raise _error(line.number, "empty or nested list items are not supported")
    item = line.text[2:].strip()
    if item == "-" or item.startswith("- "):
        raise _error(line.number, "nested lists are not supported")
    if _KEY_LINE.fullmatch(item):
        raise _error(line.number, "mappings inside lists are not supported")
    return _scalar(item, line.number)


def _parse_block(lines, index, indent):
    if _is_list_item(lines[index]):
        return _parse_list(lines, index, indent)
    return _parse_map(lines, index, indent)


def _parse_list(lines, index, indent):
    items = []
    while index < len(lines) and lines[index].indent == indent and _is_list_item(lines[index]):
        items.append(_list_item(lines[index]))
        index += 1
    if index < len(lines) and lines[index].indent > indent:
        raise _error(lines[index].number, "unexpected indentation")
    return items, index


def _parse_map(lines, index, indent):
    result = {}
    while index < len(lines):
        line = lines[index]
        if line.indent < indent:
            break
        if line.indent > indent:
            raise _error(line.number, "unexpected indentation")
        if _is_list_item(line):
            raise _error(line.number, "list item where a mapping key was expected")
        match = _KEY_LINE.fullmatch(line.text)
        if not match:
            raise _error(line.number, "expected 'key: value' with a plain key")
        key, rest = match.group(1), match.group(2)
        if key in result:
            raise _error(line.number, "duplicate key %r" % key)
        index += 1
        if rest:
            result[key] = _scalar(rest, line.number)
            continue
        if index < len(lines) and (
            lines[index].indent > indent
            or (lines[index].indent == indent and _is_list_item(lines[index]))
        ):
            value, index = _parse_block(lines, index, lines[index].indent)
            result[key] = value
        else:
            raise _error(line.number, "missing value for key %r" % key)
    return result, index


def parse_yaml_subset(text):
    """Parse text in the documented YAML subset and return a dict."""
    lines = _lines(text)
    if not lines:
        raise PolicyError("policy is empty")
    if lines[0].indent != 0:
        raise _error(lines[0].number, "unexpected indentation")
    if _is_list_item(lines[0]):
        raise _error(lines[0].number, "the top level must be a mapping")
    value, index = _parse_map(lines, 0, 0)
    if index != len(lines):
        raise _error(lines[index].number, "unexpected content")
    return value


# Validation

def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _non_negative_int(value, where):
    if not _is_int(value) or value < 0:
        raise PolicyError("%s must be a non negative integer" % where)
    return value


def _reject_unknown(mapping, allowed, where):
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise PolicyError("%s: unknown key %r" % (where, unknown[0]))


def validate_policy(raw):
    """Validate a policy mapping and return a normalized copy."""
    if not isinstance(raw, dict):
        raise PolicyError("policy must be a mapping")
    _reject_unknown(raw, _TOP_KEYS, "policy")
    if "version" not in raw:
        raise PolicyError("policy: missing 'version'")
    if not _is_int(raw["version"]) or raw["version"] != 1:
        raise PolicyError("policy: version must be 1")
    operations = raw.get("operations")
    if not isinstance(operations, dict):
        raise PolicyError("policy: 'operations' must be a mapping")
    normalized_ops = {}
    for name, spec in operations.items():
        where = "operations.%s" % name
        if not isinstance(name, str) or not name:
            raise PolicyError("operation names must be non empty strings")
        if not isinstance(spec, dict):
            raise PolicyError("%s must be a mapping" % where)
        _reject_unknown(spec, _OPERATION_KEYS, where)
        if "level" not in spec:
            raise PolicyError("%s: missing 'level'" % where)
        if spec["level"] not in LEVELS:
            raise PolicyError("%s.level must be one of %s" % (where, ", ".join(LEVELS)))
        op = {"level": spec["level"], "retry": spec.get("retry", "never")}
        if op["retry"] not in RETRY_VALUES:
            raise PolicyError("%s.retry must be 'never' or 'safe'" % where)
        for key in ("max_amount_minor", "approval_above_minor"):
            if key in spec:
                op[key] = _non_negative_int(spec[key], "%s.%s" % (where, key))
        if "currency" in spec:
            currency = spec["currency"]
            if not isinstance(currency, str) or not _CURRENCY_RE.fullmatch(currency):
                raise PolicyError("%s.currency must be three upper case letters" % where)
            op["currency"] = currency
        normalized_ops[name] = op
    policy = {"version": 1, "operations": normalized_ops}
    if "caps" in raw:
        caps = raw["caps"]
        if not isinstance(caps, dict):
            raise PolicyError("policy: 'caps' must be a mapping")
        _reject_unknown(caps, _CAP_KEYS, "caps")
        policy["caps"] = {
            key: _non_negative_int(value, "caps.%s" % key) for key, value in caps.items()
        }
    if "egress" in raw:
        egress = raw["egress"]
        if not isinstance(egress, dict):
            raise PolicyError("policy: 'egress' must be a mapping")
        _reject_unknown(egress, _EGRESS_KEYS, "egress")
        hosts = egress.get("allow_hosts", [])
        if not isinstance(hosts, list) or not all(isinstance(h, str) and _HOST_RE.fullmatch(h) for h in hosts):
            raise PolicyError("egress.allow_hosts must be a list of lower case host names")
        policy["egress"] = {"allow_hosts": sorted(set(hosts))}
    return policy


def _reject_float(text):
    raise PolicyError("floats are not supported; use integer minor units")


def loads_policy(text, fmt="yaml"):
    """Parse and validate policy text. fmt is "yaml" or "json"."""
    if fmt == "json":
        try:
            raw = json.loads(text, parse_float=_reject_float)
        except json.JSONDecodeError as exc:
            raise PolicyError("invalid JSON: %s" % exc) from None
    elif fmt == "yaml":
        raw = parse_yaml_subset(text)
    else:
        raise ValueError("fmt must be 'yaml' or 'json'")
    return validate_policy(raw)


def load_policy(path):
    """Read a policy file (.json, or the YAML subset otherwise) and validate it."""
    path = pathlib.Path(path)
    text = path.read_text(encoding="utf-8")
    return loads_policy(text, "json" if path.suffix.lower() == ".json" else "yaml")


def policy_hash(policy):
    """SHA-256 hex of the canonical JSON form of the validated policy."""
    normalized = validate_policy(policy)
    canonical = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# Decisions

@dataclasses.dataclass(frozen=True)
class Decision:
    operation: str
    level: object  # str, or None for an unknown operation
    allowed: bool
    needs_approval: bool
    reason: str
    limit_minor: object  # int or None


def decide(policy, operation, amount_minor, currency=None):
    """Decide whether an operation of this amount may execute.

    allowed is True only for the two Execute levels, within max_amount_minor
    and, when given, in the policy currency. needs_approval is True when the
    level is "Execute with Approval" or the amount is above
    approval_above_minor. The caller must still obtain that approval.
    """
    operations = policy.get("operations", {}) if isinstance(policy, dict) else {}
    spec = operations.get(operation) if isinstance(operation, str) else None
    if spec is None:
        return Decision(operation, None, False, False, "unknown operation", None)
    level = spec["level"]
    limit = spec.get("max_amount_minor")
    if not _is_int(amount_minor) or amount_minor < 0:
        return Decision(operation, level, False, False, "invalid amount", limit)
    if currency is not None and "currency" in spec and currency != spec["currency"]:
        return Decision(operation, level, False, False, "currency mismatch", limit)
    if level in ("Assist", "Draft"):
        return Decision(operation, level, False, False, "draft only", limit)
    if limit is not None and amount_minor > limit:
        return Decision(operation, level, False, False, "above limit", limit)
    above = spec.get("approval_above_minor")
    if level == "Execute with Approval":
        return Decision(operation, level, True, True, "approval required by level", limit)
    if above is not None and amount_minor > above:
        return Decision(operation, level, True, True, "approval required above threshold", limit)
    return Decision(operation, level, True, False, "within limits", limit)
