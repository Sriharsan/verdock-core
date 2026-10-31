"""Held queue: money actions that could not leave while the network was down.

An action is held only when the egress gateway refused it before any byte
reached the provider, so it is known not to have happened. It keeps its
stable request id. Nothing in here is ever sent by this module: the caller
reads the provider's record first (reconcile), then resumes each entry with
the same request id, so a provider that saw it anyway cannot apply it twice.
"""

import json

from contextlib import closing

from ._db import connect

HELD, RESUMED, DROPPED = "held, offline", "resumed", "dropped"


class HeldQueue:
    def __init__(self, path):
        self.path = path
        with closing(connect(path)) as db:
            db.execute("CREATE TABLE IF NOT EXISTS held(key TEXT PRIMARY KEY, operation TEXT NOT NULL, request_id TEXT NOT NULL,"
                       " params TEXT NOT NULL, state TEXT NOT NULL, note TEXT NOT NULL DEFAULT '')")

    def hold(self, key, operation, request_id, params):
        """Hold an action. Holding the same key again keeps the first entry and its request id."""
        with closing(connect(self.path)) as db:
            db.execute("INSERT OR IGNORE INTO held(key, operation, request_id, params, state) VALUES(?,?,?,?,?)",
                       (key, operation, request_id, json.dumps(params, sort_keys=True), HELD))
        return self.get(key)

    def get(self, key):
        with closing(connect(self.path)) as db:
            row = db.execute("SELECT key, operation, request_id, params, state, note FROM held WHERE key=?", (key,)).fetchone()
        return None if row is None else {"key": row[0], "operation": row[1], "request_id": row[2],
                                         "params": json.loads(row[3]), "state": row[4], "note": row[5]}

    def held(self):
        with closing(connect(self.path)) as db:
            keys = [row[0] for row in db.execute("SELECT key FROM held WHERE state=? ORDER BY rowid", (HELD,))]
        return [self.get(key) for key in keys]

    def close(self, key, state, note=""):
        if state not in (RESUMED, DROPPED):
            raise ValueError("state must be resumed or dropped")
        with closing(connect(self.path)) as db:
            db.execute("UPDATE held SET state=?, note=? WHERE key=? AND state=?", (state, note[:500], key, HELD))
