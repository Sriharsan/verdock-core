"""Outcome checks: did the action really happen the way we expected?

After an agent calls a provider, the app reads the provider's record
(through a Reconciler) and compares it with what it expected:

* VERIFIED: every compared field matches.
* MISMATCH: at least one compared field differs.
* UNKNOWN: there is no observed record, or a compared field is missing.
  The action may or may not have happened, so it must not be retried.
* PENDING: the provider reports a status that is still in progress.

An UNKNOWN operation can only become VERIFIED in the OutcomeLog with an
observed record that compares VERIFIED against the stored expectation.
"""

import json
import time
import typing

from . import _db
from .errors import Refused

VERIFIED = "VERIFIED"
MISMATCH = "MISMATCH"
UNKNOWN = "UNKNOWN"
PENDING = "PENDING"
STATES = (VERIFIED, MISMATCH, UNKNOWN, PENDING)


def _same(a, b):
    # Type strict: 1 and True and 1.0 are different values here.
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def compare(expected, observed, fields, status_field=None, pending_values=()):
    """Compare expected and observed on the listed fields and return a state.

    observed None gives UNKNOWN. If status_field is given and the observed
    value of that field is in pending_values, the result is PENDING. Every
    field must be present in expected.
    """
    fields = list(fields)
    if not fields:
        raise ValueError("fields must not be empty")
    for field in fields:
        if field not in expected:
            raise ValueError("expected has no field %r" % field)
    if observed is None:
        return UNKNOWN
    if status_field is not None and observed.get(status_field) in tuple(pending_values):
        return PENDING
    missing = False
    for field in fields:
        if field not in observed:
            missing = True
        elif not _same(expected[field], observed[field]):
            return MISMATCH
    return UNKNOWN if missing else VERIFIED


def may_retry(state, retry="safe"):
    """True only for MISMATCH under a "safe" retry rule.

    VERIFIED is done, UNKNOWN may already have happened and PENDING is still
    in flight, so none of them may be retried.
    """
    if state not in STATES:
        raise ValueError("unknown state %r" % state)
    if retry not in ("never", "safe"):
        raise ValueError("retry must be 'never' or 'safe'")
    return retry == "safe" and state == MISMATCH


class Reconciler(typing.Protocol):
    """Reads the provider's record of an operation, or None if not found."""

    def reconcile(self, operation: str) -> typing.Optional[dict]:
        ...


_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS expectations (
        operation_id TEXT PRIMARY KEY,
        expected TEXT NOT NULL,
        fields TEXT NOT NULL,
        status_field TEXT,
        pending_values TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS outcomes (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        operation_id TEXT NOT NULL,
        state TEXT NOT NULL,
        observed TEXT,
        recorded_at REAL NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS outcomes_operation ON outcomes (operation_id, seq)",
)


class OutcomeLog:
    """Append only history of outcome states per operation, in SQLite."""

    def __init__(self, path, clock=time.time):
        self.path = str(path)
        self._clock = clock
        _db.init_schema(self.path, _SCHEMA)

    def expect(self, operation_id, expected, fields, status_field=None, pending_values=()):
        """Store what the operation should produce. Set once per operation."""
        fields = list(fields)
        compare(expected, None, fields)  # validates fields against expected
        with _db.immediate(self.path) as conn:
            row = conn.execute(
                "SELECT 1 FROM expectations WHERE operation_id = ?", (operation_id,)
            ).fetchone()
            if row is not None:
                raise Refused("expectation already recorded")
            conn.execute(
                "INSERT INTO expectations VALUES (?, ?, ?, ?, ?)",
                (operation_id, json.dumps(expected, sort_keys=True), json.dumps(fields),
                 status_field, json.dumps(list(pending_values))),
            )

    def record(self, operation_id, state, observed=None):
        """Append a state. Refuses VERIFIED that the stored expectation does not support.

        VERIFIED needs an observed record that compares VERIFIED against the
        expectation whenever one is stored, and an expectation is required
        when the operation was ever UNKNOWN.
        """
        if state not in STATES:
            raise ValueError("unknown state %r" % state)
        with _db.immediate(self.path) as conn:
            if state == VERIFIED:
                exp = conn.execute(
                    "SELECT * FROM expectations WHERE operation_id = ?", (operation_id,)
                ).fetchone()
                was_unknown = conn.execute(
                    "SELECT 1 FROM outcomes WHERE operation_id = ? AND state = ? LIMIT 1",
                    (operation_id, UNKNOWN),
                ).fetchone() is not None
                if exp is None and was_unknown:
                    raise Refused("operation was UNKNOWN and has no expectation to verify against")
                if exp is not None:
                    result = compare(
                        json.loads(exp["expected"]), observed, json.loads(exp["fields"]),
                        exp["status_field"], json.loads(exp["pending_values"]),
                    )
                    if result != VERIFIED:
                        raise Refused("observed record does not verify (%s)" % result)
            conn.execute(
                "INSERT INTO outcomes (operation_id, state, observed, recorded_at) VALUES (?, ?, ?, ?)",
                (operation_id, state, None if observed is None else json.dumps(observed, sort_keys=True),
                 self._clock()),
            )

    def history(self, operation_id):
        """Return the recorded states for an operation, oldest first."""
        conn = _db.connect(self.path)
        try:
            rows = conn.execute(
                "SELECT state, observed, recorded_at FROM outcomes WHERE operation_id = ? ORDER BY seq",
                (operation_id,),
            ).fetchall()
        finally:
            conn.close()
        return [
            {"state": row["state"],
             "observed": None if row["observed"] is None else json.loads(row["observed"]),
             "recorded_at": row["recorded_at"]}
            for row in rows
        ]

    def latest(self, operation_id):
        """Return the most recent state, or None."""
        items = self.history(operation_id)
        return items[-1]["state"] if items else None
