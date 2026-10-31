"""Invariants that hold across many agents: amount caps, locks, request ids.

Every check and write happens inside one SQLite BEGIN IMMEDIATE
transaction, so concurrent agents (threads or processes sharing the file)
are serialized and cannot pass a check together.

reserve() is how a group of agents cannot exceed a captured amount by
splitting it: each agent reserves its part against the group cap, and the
sum of reserved and committed parts never exceeds the cap. The first
reservation for a group fixes its cap; a later call with a different cap is
refused.
"""

import time
import uuid

from . import _db
from .errors import Refused

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS groups (
        group_id TEXT PRIMARY KEY,
        cap_minor INTEGER NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS reservations (
        id TEXT PRIMARY KEY,
        group_id TEXT NOT NULL,
        customer_id TEXT NOT NULL,
        day TEXT NOT NULL,
        amount_minor INTEGER NOT NULL,
        status TEXT NOT NULL,
        created_at REAL NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS reservations_group ON reservations (group_id, status)",
    "CREATE INDEX IF NOT EXISTS reservations_customer ON reservations (customer_id, day, status)",
    """CREATE TABLE IF NOT EXISTS locks (
        key TEXT PRIMARY KEY,
        owner TEXT NOT NULL,
        expires_at REAL NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS request_ids (
        key TEXT PRIMARY KEY,
        request_id TEXT NOT NULL
    )""",
)

_ACTIVE = ("reserved", "committed")


def _check_int(value, name):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("%s must be a non negative integer" % name)


def _check_text(value, name):
    if not isinstance(value, str) or not value:
        raise ValueError("%s must be a non empty string" % name)


class Invariants:
    """Caps, locks and stable request ids in one SQLite file."""

    def __init__(self, path, clock=time.time):
        self.path = str(path)
        self._clock = clock
        _db.init_schema(self.path, _SCHEMA)

    def reserve(self, group_id, cap_minor, amount_minor, customer_id, day,
                per_customer_day_cap_minor=None):
        """Reserve amount_minor against the group cap and the customer/day cap.

        Returns the reservation id, or raises Refused.
        """
        _check_text(group_id, "group_id")
        _check_text(customer_id, "customer_id")
        _check_text(day, "day")
        _check_int(cap_minor, "cap_minor")
        _check_int(amount_minor, "amount_minor")
        if per_customer_day_cap_minor is not None:
            _check_int(per_customer_day_cap_minor, "per_customer_day_cap_minor")
        reservation_id = str(uuid.uuid4())
        with _db.immediate(self.path) as conn:
            row = conn.execute("SELECT cap_minor FROM groups WHERE group_id = ?", (group_id,)).fetchone()
            if row is None:
                conn.execute("INSERT INTO groups (group_id, cap_minor) VALUES (?, ?)", (group_id, cap_minor))
            elif row["cap_minor"] != cap_minor:
                raise Refused("cap does not match the cap recorded for this group")
            used = conn.execute(
                "SELECT COALESCE(SUM(amount_minor), 0) FROM reservations"
                " WHERE group_id = ? AND status IN (?, ?)",
                (group_id,) + _ACTIVE,
            ).fetchone()[0]
            if used + amount_minor > cap_minor:
                raise Refused("group cap exceeded")
            if per_customer_day_cap_minor is not None:
                spent = conn.execute(
                    "SELECT COALESCE(SUM(amount_minor), 0) FROM reservations"
                    " WHERE customer_id = ? AND day = ? AND status IN (?, ?)",
                    (customer_id, day) + _ACTIVE,
                ).fetchone()[0]
                if spent + amount_minor > per_customer_day_cap_minor:
                    raise Refused("customer daily cap exceeded")
            conn.execute(
                "INSERT INTO reservations (id, group_id, customer_id, day, amount_minor, status, created_at)"
                " VALUES (?, ?, ?, ?, ?, 'reserved', ?)",
                (reservation_id, group_id, customer_id, day, amount_minor, self._clock()),
            )
        return reservation_id

    def _transition(self, reservation_id, new_status):
        with _db.immediate(self.path) as conn:
            cursor = conn.execute(
                "UPDATE reservations SET status = ? WHERE id = ? AND status = 'reserved'",
                (new_status, reservation_id),
            )
            if cursor.rowcount != 1:
                raise Refused("reservation is not open")

    def commit(self, reservation_id):
        """Mark a reservation as spent. It keeps counting against the caps."""
        self._transition(reservation_id, "committed")

    def release(self, reservation_id):
        """Give an open reservation back so its amount no longer counts."""
        self._transition(reservation_id, "released")

    def group_total(self, group_id):
        """Return committed plus reserved amount for a group."""
        conn = _db.connect(self.path)
        try:
            return conn.execute(
                "SELECT COALESCE(SUM(amount_minor), 0) FROM reservations"
                " WHERE group_id = ? AND status IN (?, ?)",
                (group_id,) + _ACTIVE,
            ).fetchone()[0]
        finally:
            conn.close()

    def lock(self, key, owner, ttl_seconds):
        """Take the lock for key. True if owner now holds it.

        The current owner can call again to extend it. An expired lock can be
        taken by anyone.
        """
        _check_text(key, "key")
        _check_text(owner, "owner")
        if not isinstance(ttl_seconds, (int, float)) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        now = self._clock()
        with _db.immediate(self.path) as conn:
            row = conn.execute("SELECT owner, expires_at FROM locks WHERE key = ?", (key,)).fetchone()
            if row is not None and row["owner"] != owner and row["expires_at"] > now:
                return False
            conn.execute(
                "INSERT INTO locks (key, owner, expires_at) VALUES (?, ?, ?)"
                " ON CONFLICT(key) DO UPDATE SET owner = excluded.owner, expires_at = excluded.expires_at",
                (key, owner, now + ttl_seconds),
            )
        return True

    def unlock(self, key, owner):
        """Release the lock if owner holds it. Returns True if it was released."""
        with _db.immediate(self.path) as conn:
            cursor = conn.execute("DELETE FROM locks WHERE key = ? AND owner = ?", (key, owner))
            return cursor.rowcount == 1

    def request_id(self, key):
        """Return the UUID4 string stored for key, creating it on first use."""
        _check_text(key, "key")
        with _db.immediate(self.path) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO request_ids (key, request_id) VALUES (?, ?)",
                (key, str(uuid.uuid4())),
            )
            return conn.execute("SELECT request_id FROM request_ids WHERE key = ?", (key,)).fetchone()[0]
