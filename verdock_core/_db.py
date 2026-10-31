"""Small SQLite helpers used by the stores in this package."""

import contextlib
import sqlite3


def connect(path):
    """Open a connection in autocommit mode so transactions are explicit."""
    conn = sqlite3.connect(str(path), timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


@contextlib.contextmanager
def immediate(path):
    """Yield a connection inside BEGIN IMMEDIATE; commit or roll back on exit.

    BEGIN IMMEDIATE takes the database write lock at the start, so a read
    followed by a write inside the block cannot interleave with another
    writer, in this process or another one.
    """
    conn = connect(path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")
    finally:
        conn.close()


def init_schema(path, statements):
    with immediate(path) as conn:
        for statement in statements:
            conn.execute(statement)
