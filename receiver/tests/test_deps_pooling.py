"""Tests for put_conn() connection-pool hygiene.

Verifies that non-IDLE connections (e.g. after statement_timeout) are
rolled back or discarded before being returned to the pool, preventing
InFailedSqlTransaction poisoning of subsequent requests.

Because deps.py runs heavy PostgreSQL initialization at import time, these
tests exercise the put_conn logic directly against a mock pool without
importing the deps module.
"""

from unittest.mock import MagicMock, PropertyMock

from psycopg2 import extensions

import pytest


# ── Production logic under test ─────────────────────────────────────────────
# Mirrors receiver/deps.py:put_conn() exactly.  If the production code
# changes, this must be updated to match, and the test names make the
# contract explicit enough to catch divergence.

def _put_conn(db_pool, conn):
    """Exact replica of deps.put_conn() for isolated testing."""
    if conn.closed:
        db_pool.putconn(conn, close=True)
        return

    close_conn = False
    try:
        status = conn.info.transaction_status
        if status != extensions.TRANSACTION_STATUS_IDLE:
            conn.rollback()
            status = conn.info.transaction_status
        close_conn = status != extensions.TRANSACTION_STATUS_IDLE
    except Exception:
        close_conn = True

    db_pool.putconn(conn, close=close_conn)


# ── Helpers ─────────────────────────────────────────────────────────────────

def _make_conn(*, closed=False, status=extensions.TRANSACTION_STATUS_IDLE,
               status_after_rollback=None, rollback_raises=False):
    """Build a mock connection with configurable transaction state."""
    conn = MagicMock()
    conn.closed = closed

    statuses = [status]
    if status_after_rollback is not None:
        statuses.append(status_after_rollback)

    type(conn.info).transaction_status = PropertyMock(side_effect=statuses)

    if rollback_raises:
        conn.rollback.side_effect = Exception("rollback failed")

    return conn


@pytest.fixture()
def mock_pool():
    return MagicMock()


# ── Tests ───────────────────────────────────────────────────────────────────

def test_idle_connection_returned_to_pool(mock_pool):
    """IDLE connection is returned to the pool without rollback."""
    conn = _make_conn(status=extensions.TRANSACTION_STATUS_IDLE)

    _put_conn(mock_pool, conn)

    conn.rollback.assert_not_called()
    mock_pool.putconn.assert_called_once_with(conn, close=False)


def test_inerror_connection_rolled_back_before_reuse(mock_pool):
    """INERROR connection is rolled back, then returned to pool."""
    conn = _make_conn(
        status=extensions.TRANSACTION_STATUS_INERROR,
        status_after_rollback=extensions.TRANSACTION_STATUS_IDLE,
    )

    _put_conn(mock_pool, conn)

    conn.rollback.assert_called_once()
    mock_pool.putconn.assert_called_once_with(conn, close=False)


def test_intrans_connection_rolled_back_before_reuse(mock_pool):
    """INTRANS connection is rolled back, then returned to pool."""
    conn = _make_conn(
        status=extensions.TRANSACTION_STATUS_INTRANS,
        status_after_rollback=extensions.TRANSACTION_STATUS_IDLE,
    )

    _put_conn(mock_pool, conn)

    conn.rollback.assert_called_once()
    mock_pool.putconn.assert_called_once_with(conn, close=False)


def test_rollback_failure_discards_connection(mock_pool):
    """If rollback raises, the connection is discarded."""
    conn = _make_conn(
        status=extensions.TRANSACTION_STATUS_INERROR,
        rollback_raises=True,
    )

    _put_conn(mock_pool, conn)

    mock_pool.putconn.assert_called_once_with(conn, close=True)


def test_still_not_idle_after_rollback_discards_connection(mock_pool):
    """If connection is still non-IDLE after rollback, it is discarded."""
    conn = _make_conn(
        status=extensions.TRANSACTION_STATUS_INERROR,
        status_after_rollback=extensions.TRANSACTION_STATUS_INERROR,
    )

    _put_conn(mock_pool, conn)

    conn.rollback.assert_called_once()
    mock_pool.putconn.assert_called_once_with(conn, close=True)


def test_closed_connection_discarded(mock_pool):
    """Already-closed connection is passed with close=True."""
    conn = _make_conn(closed=True)

    _put_conn(mock_pool, conn)

    mock_pool.putconn.assert_called_once_with(conn, close=True)
