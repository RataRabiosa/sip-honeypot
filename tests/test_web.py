import datetime

import pymysql.err
import pytest

from web.app import create_app

TOTAL_ROWS = [{"n": 42}]
WINDOW_ROWS = [{"n": 7}]
DISTINCT_ROWS = [{"n": 3}]
STATUS_ROWS = [{"status": "blocked", "n": 2}, {"status": "failed", "n": 1}]
BUCKET_ROWS = []
METHOD_ROWS = [{"method": "OPTIONS", "n": 5}, {"method": "INVITE", "n": 2}]

_NOW = datetime.datetime(2026, 1, 1, 12, 0, 0)

TOP_IPS_ROWS = [
    {
        "src_ip": "203.0.113.50",
        "request_count": 10,
        "first_seen": _NOW,
        "last_seen": _NOW,
        "block_status": "blocked",
    }
]
BLOCKED_ROWS = [
    {
        "src_ip": "203.0.113.50",
        "status": "blocked",
        "attempts": 1,
        "first_attempt_at": _NOW,
        "last_attempt_at": _NOW,
        "blocked_at": _NOW,
        "last_http_status": 204,
        "last_error": None,
    }
]


def _rows_for(sql):
    if "GROUP BY status" in sql:
        return STATUS_ROWS
    if "GROUP BY bucket" in sql:
        return BUCKET_ROWS
    if "GROUP BY method" in sql:
        return METHOD_ROWS
    if "LEFT JOIN blocked_ips" in sql:
        return TOP_IPS_ROWS
    if "ORDER BY COALESCE" in sql:
        return BLOCKED_ROWS
    if "FROM source_ips" in sql:
        return DISTINCT_ROWS
    if "WHERE" in sql:
        return WINDOW_ROWS
    if "SELECT 1" in sql:
        return [{"1": 1}]
    return TOTAL_ROWS


class FakeCursor:
    def __init__(self, calls):
        self._calls = calls
        self._rows = []

    def execute(self, sql, params=None):
        self._calls.append((sql, params))
        self._rows = _rows_for(sql)

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return self._rows

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeConnection:
    def __init__(self):
        self.calls = []
        self.closed = False

    def cursor(self):
        return FakeCursor(self.calls)

    def close(self):
        self.closed = True


@pytest.fixture
def app_with_fake_db(monkeypatch):
    monkeypatch.setenv("MYSQL_HOST", "fake-host")
    monkeypatch.setenv("MYSQL_USER", "fake-user")
    monkeypatch.setenv("MYSQL_PASSWORD", "fake-pass")
    monkeypatch.setenv("MYSQL_DATABASE", "fake-db")
    app = create_app()
    conn = FakeConnection()
    app.config["DB_CONNECT"] = lambda: conn
    return app, conn


def test_index_returns_200_with_canned_data(app_with_fake_db):
    app, conn = app_with_fake_db
    client = app.test_client()
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "203.0.113.50" in html
    assert "blocked" in html


def test_index_invalid_hours_defaults_to_24(app_with_fake_db):
    app, conn = app_with_fake_db
    client = app.test_client()
    resp = client.get("/?hours=abc")
    assert resp.status_code == 200
    window_calls = [c for c in conn.calls if c[0].strip().startswith("SELECT COUNT(*) AS n FROM request_events WHERE")]
    assert window_calls
    assert window_calls[0][1] == (24,)


def test_index_out_of_range_hours_clamps_to_720(app_with_fake_db):
    app, conn = app_with_fake_db
    client = app.test_client()
    resp = client.get("/?hours=99999")
    assert resp.status_code == 200
    window_calls = [c for c in conn.calls if c[0].strip().startswith("SELECT COUNT(*) AS n FROM request_events WHERE")]
    assert window_calls
    assert window_calls[0][1] == (720,)


def test_index_shows_error_banner_on_db_error(monkeypatch):
    monkeypatch.setenv("MYSQL_HOST", "fake-host")
    monkeypatch.setenv("MYSQL_USER", "fake-user")
    monkeypatch.setenv("MYSQL_PASSWORD", "fake-pass")
    monkeypatch.setenv("MYSQL_DATABASE", "fake-db")
    app = create_app()

    def _raise():
        raise pymysql.err.OperationalError("connection refused")

    app.config["DB_CONNECT"] = _raise
    client = app.test_client()
    resp = client.get("/")
    assert resp.status_code == 200
    assert "connection refused" in resp.get_data(as_text=True)


def test_healthz_ok(app_with_fake_db):
    app, conn = app_with_fake_db
    client = app.test_client()
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json() == {"ok": True}


def test_healthz_failure(monkeypatch):
    monkeypatch.setenv("MYSQL_HOST", "fake-host")
    monkeypatch.setenv("MYSQL_USER", "fake-user")
    monkeypatch.setenv("MYSQL_PASSWORD", "fake-pass")
    monkeypatch.setenv("MYSQL_DATABASE", "fake-db")
    app = create_app()

    def _raise():
        raise pymysql.err.OperationalError("connection refused")

    app.config["DB_CONNECT"] = _raise
    client = app.test_client()
    resp = client.get("/healthz")
    assert resp.status_code == 503
    body = resp.get_json()
    assert body["ok"] is False
