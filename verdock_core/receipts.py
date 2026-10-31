"""Signed, hash chained action receipts (draft-sahu-agent-action-receipts-00).

Each receipt is one line of newline delimited JSON with these members:

    step_id     string, required
    action_id   string, required
    params      any JSON value, required
    success     boolean, required
    ts_ms       integer milliseconds since the Unix epoch, required
    actor       object with string members agent and/or user, optional
    prev_hash   64 lowercase hex, absent on the first line, required after
    public_key  64 lowercase hex (Ed25519, 32 bytes), required
    signature   128 lowercase hex (Ed25519, 64 bytes), required

Other members may be present. They are not signed, but they are covered by
the next line's prev_hash because that digest is over the exact line bytes.

Signed bytes (draft section 4): compact JSON of the signed members in the
fixed order step_id, action_id, params, success, ts_ms, actor (agent then
user), prev_hash, omitting absent ones. Object keys inside params are
sorted by Unicode code point at every depth; arrays keep their order.
Strings use the shortest RFC 8259 form with lowercase \\u escapes. Numbers
must be integers within +/- (2**53 - 1); this package rejects any non
integer number token anywhere in a line, so the Python and browser
verifiers always agree.

Chain (draft section 6): prev_hash of line n is the SHA-256 hex digest of
the exact octets of line n - 1, without its newline.

Limits: there is no key management here; keep the seed file private. A log
whose newest lines were removed still verifies (draft section 9); detecting
that needs a head digest stored somewhere else.
"""

import hashlib
import json
import os
import re
import time

from . import ed25519

SIGNED_MEMBERS = ("step_id", "action_id", "params", "success", "ts_ms", "actor", "prev_hash")
RESERVED_MEMBERS = SIGNED_MEMBERS + ("public_key", "signature")
MAX_SAFE_INTEGER = 2 ** 53 - 1

_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX128 = re.compile(r"[0-9a-f]{128}")
_SURROGATE = re.compile("[\ud800-\udfff]")


class ReceiptError(ValueError):
    """A receipt value cannot be canonicalized or a log cannot be written."""


# Canonical form

def _canon_string(value):
    if _SURROGATE.search(value):
        raise ReceiptError("invalid string")
    return json.dumps(value, ensure_ascii=False)


def _canon(value):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ReceiptError("integer out of range")
        return str(value)
    if isinstance(value, float):
        raise ReceiptError("non-integer number")
    if isinstance(value, str):
        return _canon_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canon(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise ReceiptError("object keys must be strings")
        # Python orders str by code point, which is what the draft requires.
        return "{" + ",".join(
            _canon_string(key) + ":" + _canon(value[key]) for key in sorted(value)
        ) + "}"
    raise ReceiptError("unsupported value type %s" % type(value).__name__)


def _check_members(receipt):
    """Return a failure reason for missing or mistyped members, or None."""
    for name in ("step_id", "action_id", "params", "success", "ts_ms", "public_key", "signature"):
        if name not in receipt:
            return "missing member: %s" % name
    for name in ("step_id", "action_id", "public_key", "signature"):
        if not isinstance(receipt[name], str):
            return "wrong type: %s" % name
    if not isinstance(receipt["success"], bool):
        return "wrong type: success"
    ts_ms = receipt["ts_ms"]
    if not isinstance(ts_ms, int) or isinstance(ts_ms, bool):
        return "wrong type: ts_ms"
    if "actor" in receipt:
        actor = receipt["actor"]
        if not isinstance(actor, dict) or not set(actor) <= {"agent", "user"}:
            return "wrong type: actor"
        if not all(isinstance(v, str) for v in actor.values()):
            return "wrong type: actor"
    if "prev_hash" in receipt and not isinstance(receipt["prev_hash"], str):
        return "wrong type: prev_hash"
    return None


def canonical_bytes(receipt):
    """Return the signed byte sequence for a receipt mapping."""
    parts = []
    for name in SIGNED_MEMBERS:
        if name not in receipt:
            continue
        value = receipt[name]
        if name == "actor":
            encoded = "{" + ",".join(
                _canon_string(key) + ":" + _canon_string(value[key])
                for key in ("agent", "user") if key in value
            ) + "}"
        else:
            encoded = _canon(value)
        parts.append(_canon_string(name) + ":" + encoded)
    return ("{" + ",".join(parts) + "}").encode("utf-8")


def _serialize(value):
    """Compact JSON keeping the caller's key order (for the written line)."""
    _canon(value)  # same value rules as the signed form
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def build_line(step_id, action_id, params, success, ts_ms, seed, actor=None,
               prev_hash=None, extra=None):
    """Sign one receipt and return its line (no trailing newline)."""
    receipt = {"step_id": step_id, "action_id": action_id, "params": params,
               "success": success, "ts_ms": ts_ms}
    if actor is not None:
        receipt["actor"] = {key: actor[key] for key in ("agent", "user") if key in actor}
        if set(actor) - {"agent", "user"} or not receipt["actor"]:
            raise ReceiptError("actor must have agent and/or user only")
    if prev_hash is not None:
        receipt["prev_hash"] = prev_hash
    pub = ed25519.public_key(seed).hex()
    receipt["public_key"] = pub
    receipt["signature"] = "0" * 128
    reason = _check_members(receipt)
    if reason:
        raise ReceiptError(reason)
    if prev_hash is not None and not _HEX64.fullmatch(prev_hash):
        raise ReceiptError("prev_hash must be 64 lowercase hex characters")
    receipt["signature"] = ed25519.sign(seed, canonical_bytes(receipt)).hex()
    for key, value in (extra or {}).items():
        if key in RESERVED_MEMBERS:
            raise ReceiptError("extra member %r is reserved" % key)
        receipt[key] = value
    return "{" + ",".join(
        _canon_string(key) + ":" + _serialize(value) for key, value in receipt.items()
    ) + "}"


def line_hash(line):
    """SHA-256 hex of a line's octets (str is encoded as UTF-8)."""
    if isinstance(line, str):
        line = line.encode("utf-8")
    return hashlib.sha256(line).hexdigest()


# Seeds and the writer

def create_seed(path):
    """Create a new random 32 byte seed file (hex). Refuses to overwrite."""
    seed = os.urandom(32)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(seed.hex() + "\n")
    return seed


def load_seed(path):
    """Read a seed file written by create_seed and return 32 bytes."""
    with open(str(path), "r", encoding="ascii") as handle:
        text = handle.read().strip()
    if not _HEX64.fullmatch(text):
        raise ReceiptError("seed file must hold 64 lowercase hex characters")
    return bytes.fromhex(text)


class ReceiptLog:
    """Append signed receipts to an NDJSON file. One writer per file."""

    def __init__(self, path, seed, clock=time.time):
        self.path = str(path)
        self.seed = bytes(seed)
        self.public_key = ed25519.public_key(self.seed).hex()
        self._clock = clock
        self._prev_hash = None
        if os.path.exists(self.path):
            with open(self.path, "rb") as handle:
                data = handle.read()
            if data:
                if not data.endswith(b"\n"):
                    raise ReceiptError("log does not end with a newline; refusing to append")
                self._prev_hash = line_hash(data[:-1].split(b"\n")[-1])

    def append(self, step_id, action_id, params, success, actor=None, extra=None, ts_ms=None):
        """Sign, write and return one receipt line (without the newline)."""
        if ts_ms is None:
            ts_ms = int(self._clock() * 1000)
        line = build_line(step_id, action_id, params, success, ts_ms, self.seed,
                          actor=actor, prev_hash=self._prev_hash, extra=extra)
        encoded = line.encode("utf-8")
        with open(self.path, "ab") as handle:
            handle.write(encoded + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        self._prev_hash = line_hash(encoded)
        return line


# Verification (draft section 7)

class _NonInteger(Exception):
    pass


def _reject_float(text):
    raise _NonInteger()


def _reject_constant(text):
    raise ValueError("invalid constant")


def _numbers_ok(value):
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return True
    if isinstance(value, int):
        return abs(value) <= MAX_SAFE_INTEGER
    if isinstance(value, list):
        return all(_numbers_ok(item) for item in value)
    if isinstance(value, dict):
        return all(_numbers_ok(item) for item in value.values())
    return False


def _has_surrogate(value):
    if isinstance(value, str):
        return bool(_SURROGATE.search(value))
    if isinstance(value, list):
        return any(_has_surrogate(item) for item in value)
    if isinstance(value, dict):
        return any(_has_surrogate(k) or _has_surrogate(v) for k, v in value.items())
    return False


def _split(data):
    if data.endswith(b"\n"):
        data = data[:-1]
    if not data:
        return []
    return data.split(b"\n")


def _check_line(raw, index, prev_raw, anchor):
    """Return the list of failure reasons for one line."""
    if raw == b"":
        return ["empty line"]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return ["invalid UTF-8"]
    try:
        receipt = json.loads(text, parse_float=_reject_float, parse_constant=_reject_constant)
    except _NonInteger:
        # Report invalid JSON first if the rest of the line is also broken.
        try:
            json.loads(text, parse_constant=_reject_constant)
        except (ValueError, RecursionError):
            return ["invalid JSON"]
        return ["non-integer number"]
    except (ValueError, RecursionError):
        return ["invalid JSON"]
    if not _numbers_ok(receipt):
        return ["integer out of range"]
    if _has_surrogate(receipt):
        return ["invalid string"]
    if not isinstance(receipt, dict):
        return ["not an object"]
    reason = _check_members(receipt)
    if reason:
        return [reason]
    failures = []
    pub_ok = bool(_HEX64.fullmatch(receipt["public_key"]))
    sig_ok = bool(_HEX128.fullmatch(receipt["signature"]))
    if not pub_ok:
        failures.append("invalid hex: public_key")
    if not sig_ok:
        failures.append("invalid hex: signature")
    if "prev_hash" in receipt and not _HEX64.fullmatch(receipt["prev_hash"]):
        failures.append("invalid hex: prev_hash")
    if pub_ok and sig_ok:
        message = canonical_bytes(receipt)
        if not ed25519.verify(bytes.fromhex(receipt["public_key"]), message,
                              bytes.fromhex(receipt["signature"])):
            failures.append("signature invalid")
    if index == 0:
        if "prev_hash" in receipt:
            failures.append("unexpected prev_hash on first line")
    elif "prev_hash" not in receipt:
        failures.append("missing prev_hash")
    elif receipt["prev_hash"] != hashlib.sha256(prev_raw).hexdigest():
        failures.append("chain break")
    if pub_ok and receipt["public_key"] != anchor:
        failures.append("untrusted public key")
    return failures


def _normalize_anchor(trust_anchor_hex):
    if not isinstance(trust_anchor_hex, str):
        raise ValueError("trust anchor must be a hex string")
    anchor = trust_anchor_hex.strip().lower()
    if not _HEX64.fullmatch(anchor):
        raise ValueError("trust anchor must be 64 hex characters")
    return anchor


def verify_bytes(data, trust_anchor_hex):
    """Verify a whole log given as bytes. See verify_log for the result."""
    anchor = _normalize_anchor(trust_anchor_hex)
    lines = _split(bytes(data))
    failures = []
    prev_raw = None
    for index, raw in enumerate(lines):
        for reason in _check_line(raw, index, prev_raw, anchor):
            failures.append({"line": index + 1, "reason": reason})
        prev_raw = raw
    return {"ok": not failures, "count": len(lines), "failures": failures}


def verify_log(lines_or_path, trust_anchor_hex):
    """Verify a receipt log against a trust anchor (draft section 7).

    lines_or_path is a path (str or os.PathLike) or an iterable of lines
    (str or bytes, a trailing newline on each is allowed). Returns
    {"ok": bool, "count": number of lines, "failures": [{"line", "reason"}]}
    with 1 based line numbers. Every line is checked; a bad line is reported,
    never skipped, and ok is True only when there are no failures.
    """
    if isinstance(lines_or_path, (str, os.PathLike)):
        with open(lines_or_path, "rb") as handle:
            return verify_bytes(handle.read(), trust_anchor_hex)
    encoded = []
    for line in lines_or_path:
        if isinstance(line, str):
            try:
                line = line.encode("utf-8")
            except UnicodeEncodeError:
                line = b"\xff"  # reported as invalid UTF-8
        if line.endswith(b"\n"):
            line = line[:-1]
        encoded.append(line)
    return verify_bytes(b"\n".join(encoded) + (b"\n" if encoded else b""), trust_anchor_hex)
