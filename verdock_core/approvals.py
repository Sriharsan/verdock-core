"""Approval records kept in SQLite.

An agent requests approval for one exact action. A person approves or
rejects it. Before executing, the app calls require() with the action it is
about to perform; it gets the record back only when the approval is
approved, unexpired, unused and matches the operation, subject, amount and
currency exactly. consume() then marks it used, once.

The person who requested an approval cannot approve or reject it.
"""

import time
import uuid

from . import _db
from .errors import Refused

PENDING = "pending"
APPROVED = "approved"
REJECTED = "rejected"
CONSUMED = "consumed"
STATUSES = (PENDING, APPROVED, REJECTED, CONSUMED)

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS approvals (
        id TEXT PRIMARY KEY,
        operation TEXT NOT NULL,
        action TEXT NOT NULL,
        subject TEXT NOT NULL,
        amount_minor INTEGER NOT NULL,
        currency TEXT NOT NULL,
        limit_minor INTEGER,
        requested_by TEXT NOT NULL,
        requested_at REAL NOT NULL,
        expires_at REAL NOT NULL,
        status TEXT NOT NULL,
        approver TEXT,
        decided_at REAL,
        reason TEXT,
        consumed_at REAL
    )""",
)


def _check_int(value, name, allow_none=False):
    if allow_none and value is None:
        return
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("%s must be a non negative integer" % name)


def _check_text(value, name):
    if not isinstance(value, str) or not value:
        raise ValueError("%s must be a non empty string" % name)


class ApprovalStore:
    """Approval requests and decisions in one SQLite file."""

    def __init__(self, path, clock=time.time):
        self.path = str(path)
        self._clock = clock
        _db.init_schema(self.path, _SCHEMA)

    def request(self, operation, action, subject, amount_minor, currency,
                limit_minor, requested_by, ttl_seconds):
        """Record a pending approval request and return its id."""
        for name, value in (("operation", operation), ("action", action), ("subject", subject),
                            ("currency", currency), ("requested_by", requested_by)):
            _check_text(value, name)
        _check_int(amount_minor, "amount_minor")
        _check_int(limit_minor, "limit_minor", allow_none=True)
        if not isinstance(ttl_seconds, (int, float)) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        approval_id = str(uuid.uuid4())
        now = self._clock()
        with _db.immediate(self.path) as conn:
            conn.execute(
                "INSERT INTO approvals (id, operation, action, subject, amount_minor, currency,"
                " limit_minor, requested_by, requested_at, expires_at, status)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (approval_id, operation, action, subject, amount_minor, currency, limit_minor,
                 requested_by, now, now + ttl_seconds, PENDING),
            )
        return approval_id

    def _decide(self, approval_id, approver, status, reason):
        _check_text(approver, "approver")
        now = self._clock()
        with _db.immediate(self.path) as conn:
            row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
            if row is None:
                raise Refused("unknown approval")
            if row["status"] != PENDING:
                raise Refused("approval already decided")
            if row["expires_at"] <= now:
                raise Refused("approval expired")
            if approver == row["requested_by"]:
                raise Refused("requester cannot decide their own approval")
            conn.execute(
                "UPDATE approvals SET status = ?, approver = ?, decided_at = ?, reason = ? WHERE id = ?",
                (status, approver, now, reason, approval_id),
            )

    def approve(self, approval_id, approver):
        self._decide(approval_id, approver, APPROVED, None)

    def reject(self, approval_id, approver, reason):
        _check_text(reason, "reason")
        self._decide(approval_id, approver, REJECTED, reason)

    def _record(self, row):
        record = dict(row)
        record["expired"] = record["expires_at"] <= self._clock()
        return record

    def get(self, approval_id):
        """Return the record as a dict (with an "expired" flag), or None."""
        conn = _db.connect(self.path)
        try:
            row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        finally:
            conn.close()
        return None if row is None else self._record(row)

    def list(self, status=None):
        """Return records, oldest first, optionally only those with a status."""
        if status is not None and status not in STATUSES:
            raise ValueError("unknown status %r" % status)
        conn = _db.connect(self.path)
        try:
            if status is None:
                rows = conn.execute("SELECT * FROM approvals ORDER BY rowid").fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM approvals WHERE status = ? ORDER BY rowid", (status,)
                ).fetchall()
        finally:
            conn.close()
        return [self._record(row) for row in rows]

    def require(self, approval_id, operation, subject, amount_minor, currency):
        """Return the record if it approves exactly this action, else raise Refused."""
        record = self.get(approval_id)
        if record is None:
            raise Refused("unknown approval")
        if record["status"] == CONSUMED:
            raise Refused("approval already used")
        if record["status"] != APPROVED:
            raise Refused("approval is %s" % record["status"])
        if record["expired"]:
            raise Refused("approval expired")
        expected = (record["operation"], record["subject"], record["amount_minor"], record["currency"])
        if (operation, subject, amount_minor, currency) != expected or isinstance(amount_minor, bool):
            raise Refused("approval does not match this action")
        return record

    def consume(self, approval_id):
        """Mark an approved, unexpired approval as used. Works once."""
        now = self._clock()
        with _db.immediate(self.path) as conn:
            cursor = conn.execute(
                "UPDATE approvals SET status = ?, consumed_at = ?"
                " WHERE id = ? AND status = ? AND expires_at > ?",
                (CONSUMED, now, approval_id, APPROVED, now),
            )
            if cursor.rowcount != 1:
                raise Refused("approval cannot be used")
        return self.get(approval_id)
