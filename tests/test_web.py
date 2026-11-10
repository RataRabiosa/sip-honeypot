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
BLOCKED_COUNT_ROWS = [{"n": 1}]


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
    if "COUNT(*) AS n FROM blocked_ips" in sql:
        return BLOCKED_COUNT_ROWS
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
    monkeypatch.setenv("WEB_BASIC_AUTH_ENABLED", "false")
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


def test_index_date_range_short_span_uses_hourly_window(app_with_fake_db):
    app, conn = app_with_fake_db
    client = app.test_client()
    resp = client.get("/?start=2026-01-01&end=2026-01-02")
    assert resp.status_code == 200
    window_calls = [c for c in conn.calls if c[0].strip().startswith("SELECT COUNT(*) AS n FROM request_events WHERE")]
    assert window_calls
    expected_start = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    expected_end = datetime.datetime(2026, 1, 3, tzinfo=datetime.timezone.utc)
    assert window_calls[0][1] == (expected_start, expected_end)
    bucket_calls = [c for c in conn.calls if "GROUP BY bucket" in c[0]]
    assert bucket_calls
    assert "%%Y-%%m-%%d %%H:00" in bucket_calls[0][0]


def test_index_date_range_long_span_uses_daily_buckets(app_with_fake_db):
    app, conn = app_with_fake_db
    client = app.test_client()
    resp = client.get("/?start=2026-01-01&end=2026-02-01")
    assert resp.status_code == 200
    bucket_calls = [c for c in conn.calls if "GROUP BY bucket" in c[0]]
    assert bucket_calls
    assert "%%Y-%%m-%%d')" in bucket_calls[0][0]
    assert "%%H:00" not in bucket_calls[0][0]


def test_index_date_range_reversed_dates_are_swapped(app_with_fake_db):
    app, conn = app_with_fake_db
    client = app.test_client()
    resp = client.get("/?start=2026-02-01&end=2026-01-01")
    assert resp.status_code == 200
    window_calls = [c for c in conn.calls if c[0].strip().startswith("SELECT COUNT(*) AS n FROM request_events WHERE")]
    assert window_calls
    expected_start = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    expected_end = datetime.datetime(2026, 2, 2, tzinfo=datetime.timezone.utc)
    assert window_calls[0][1] == (expected_start, expected_end)


def test_index_invalid_date_range_falls_back_to_hours_mode(app_with_fake_db):
    app, conn = app_with_fake_db
    client = app.test_client()
    resp = client.get("/?start=not-a-date&end=2026-01-02")
    assert resp.status_code == 200
    window_calls = [c for c in conn.calls if c[0].strip().startswith("SELECT COUNT(*) AS n FROM request_events WHERE")]
    assert window_calls
    assert window_calls[0][1] == (24,)


def test_index_missing_end_date_falls_back_to_hours_mode(app_with_fake_db):
    app, conn = app_with_fake_db
    client = app.test_client()
    resp = client.get("/?start=2026-01-01")
    assert resp.status_code == 200
    window_calls = [c for c in conn.calls if c[0].strip().startswith("SELECT COUNT(*) AS n FROM request_events WHERE")]
    assert window_calls
    assert window_calls[0][1] == (24,)


def test_index_shows_error_banner_on_db_error(monkeypatch):
    monkeypatch.setenv("MYSQL_HOST", "fake-host")
    monkeypatch.setenv("MYSQL_USER", "fake-user")
    monkeypatch.setenv("MYSQL_PASSWORD", "fake-pass")
    monkeypatch.setenv("MYSQL_DATABASE", "fake-db")
    monkeypatch.setenv("WEB_BASIC_AUTH_ENABLED", "false")
    app = create_app()

    def _raise():
        raise pymysql.err.OperationalError("connection refused")

    app.config["DB_CONNECT"] = _raise
    client = app.test_client()
    resp = client.get("/")
    assert resp.status_code == 200
    assert "connection refused" in resp.get_data(as_text=True)


def test_index_blocked_search_filters_by_ip(app_with_fake_db):
    app, conn = app_with_fake_db
    client = app.test_client()
    resp = client.get("/?q=203.0.113")
    assert resp.status_code == 200
    blocked_calls = [c for c in conn.calls if "ORDER BY COALESCE" in c[0]]
    assert blocked_calls
    sql, params = blocked_calls[0]
    assert "LIKE" in sql
    assert params[0] == "%203.0.113%"


def test_index_blocked_search_escapes_like_wildcards(app_with_fake_db):
    app, conn = app_with_fake_db
    client = app.test_client()
    resp = client.get("/?q=1.2.3%")
    assert resp.status_code == 200
    blocked_calls = [c for c in conn.calls if "ORDER BY COALESCE" in c[0]]
    assert blocked_calls
    sql, params = blocked_calls[0]
    assert "LIKE" in sql
    assert params[0] == "%1.2.3\\%%"


def test_index_status_totals_include_unblocking_and_expired(app_with_fake_db, monkeypatch):
    app, conn = app_with_fake_db
    monkeypatch.setitem(
        globals(),
        "STATUS_ROWS",
        [
            {"status": "blocked", "n": 2},
            {"status": "failed", "n": 1},
            {"status": "pending", "n": 3},
            {"status": "unblocking", "n": 5},
            {"status": "expired", "n": 7},
        ],
    )
    client = app.test_client()
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert '<div class="n">5</div><div class="l">Unblocking (TTL)</div>' in html
    assert '<div class="n">7</div><div class="l">Expired (TTL)</div>' in html


def test_index_blocked_page_param_used_for_offset(app_with_fake_db, monkeypatch):
    app, conn = app_with_fake_db
    # Give a big enough total that page 2 is in range (2 of 4 pages at 25/page).
    monkeypatch.setitem(globals(), "BLOCKED_COUNT_ROWS", [{"n": 100}])
    client = app.test_client()
    resp = client.get("/?page=2")
    assert resp.status_code == 200
    blocked_calls = [c for c in conn.calls if "ORDER BY COALESCE" in c[0]]
    assert blocked_calls
    sql, params = blocked_calls[0]
    assert params[-2:] == (25, 25)


def test_index_invalid_page_defaults_to_1(app_with_fake_db):
    app, conn = app_with_fake_db
    client = app.test_client()
    resp = client.get("/?page=abc")
    assert resp.status_code == 200
    blocked_calls = [c for c in conn.calls if "ORDER BY COALESCE" in c[0]]
    assert blocked_calls
    assert blocked_calls[0][1][-1] == 0

    conn.calls.clear()
    resp = client.get("/?page=-5")
    assert resp.status_code == 200
    blocked_calls = [c for c in conn.calls if "ORDER BY COALESCE" in c[0]]
    assert blocked_calls
    assert blocked_calls[0][1][-1] == 0


def test_index_page_beyond_total_clamps_to_last_page(app_with_fake_db):
    app, conn = app_with_fake_db
    client = app.test_client()
    resp = client.get("/?page=50")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Page 1 of 1" in html


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
    monkeypatch.setenv("WEB_BASIC_AUTH_ENABLED", "false")
    app = create_app()

    def _raise():
        raise pymysql.err.OperationalError("connection refused")

    app.config["DB_CONNECT"] = _raise
    client = app.test_client()
    resp = client.get("/healthz")
    assert resp.status_code == 503
    body = resp.get_json()
    assert body["ok"] is False


def test_index_and_healthz_work_without_auth_header_when_auth_disabled(app_with_fake_db):
    app, conn = app_with_fake_db
    client = app.test_client()
    assert client.get("/").status_code == 200
    assert client.get("/healthz").status_code == 200


@pytest.fixture
def app_with_fake_db_and_auth(monkeypatch):
    monkeypatch.setenv("MYSQL_HOST", "fake-host")
    monkeypatch.setenv("MYSQL_USER", "fake-user")
    monkeypatch.setenv("MYSQL_PASSWORD", "fake-pass")
    monkeypatch.setenv("MYSQL_DATABASE", "fake-db")
    monkeypatch.setenv("WEB_BASIC_AUTH_ENABLED", "true")
    monkeypatch.setenv("WEB_BASIC_AUTH_USERNAME", "admin")
    monkeypatch.setenv("WEB_BASIC_AUTH_PASSWORD", "secret-pass")
    app = create_app()
    conn = FakeConnection()
    app.config["DB_CONNECT"] = lambda: conn
    return app, conn


def test_index_and_healthz_with_correct_credentials_return_200(app_with_fake_db_and_auth):
    app, conn = app_with_fake_db_and_auth
    client = app.test_client()
    resp = client.get("/", auth=("admin", "secret-pass"))
    assert resp.status_code == 200
    resp = client.get("/healthz", auth=("admin", "secret-pass"))
    assert resp.status_code == 200
    assert resp.get_json() == {"ok": True}


def test_index_and_healthz_without_auth_header_return_401(app_with_fake_db_and_auth):
    app, conn = app_with_fake_db_and_auth
    client = app.test_client()
    resp = client.get("/")
    assert resp.status_code == 401
    assert "Basic" in resp.headers.get("WWW-Authenticate", "")

    resp = client.get("/healthz")
    assert resp.status_code == 401
    assert "Basic" in resp.headers.get("WWW-Authenticate", "")


def test_index_and_healthz_with_wrong_credentials_return_401(app_with_fake_db_and_auth):
    app, conn = app_with_fake_db_and_auth
    client = app.test_client()
    resp = client.get("/", auth=("admin", "wrong-pass"))
    assert resp.status_code == 401

    resp = client.get("/healthz", auth=("wrong-user", "secret-pass"))
    assert resp.status_code == 401


def test_create_app_raises_when_auth_enabled_without_username(monkeypatch):
    monkeypatch.setenv("MYSQL_HOST", "fake-host")
    monkeypatch.setenv("MYSQL_USER", "fake-user")
    monkeypatch.setenv("MYSQL_PASSWORD", "fake-pass")
    monkeypatch.setenv("MYSQL_DATABASE", "fake-db")
    monkeypatch.setenv("WEB_BASIC_AUTH_ENABLED", "true")
    # Explicitly set to an empty string (rather than delenv) so this test does not
    # depend on whether a local .env file happens to provide a fallback value.
    monkeypatch.setenv("WEB_BASIC_AUTH_USERNAME", "")
    monkeypatch.setenv("WEB_BASIC_AUTH_PASSWORD", "secret-pass")
    with pytest.raises(RuntimeError):
        create_app()


def test_create_app_raises_when_auth_enabled_without_password(monkeypatch):
    monkeypatch.setenv("MYSQL_HOST", "fake-host")
    monkeypatch.setenv("MYSQL_USER", "fake-user")
    monkeypatch.setenv("MYSQL_PASSWORD", "fake-pass")
    monkeypatch.setenv("MYSQL_DATABASE", "fake-db")
    monkeypatch.setenv("WEB_BASIC_AUTH_ENABLED", "true")
    monkeypatch.setenv("WEB_BASIC_AUTH_USERNAME", "admin")
    # Explicitly set to an empty string (rather than delenv) so this test does not
    # depend on whether a local .env file happens to provide a fallback value.
    monkeypatch.setenv("WEB_BASIC_AUTH_PASSWORD", "")
    with pytest.raises(RuntimeError):
        create_app()
