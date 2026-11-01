import datetime
import hmac
import os

import pymysql
import pymysql.cursors
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

from web.queries import dashboard_data

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _get_bool(raw, default: bool) -> bool:
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _empty_data(hours: int, start=None, end=None) -> dict:
    mode = "range" if start is not None and end is not None else "hours"
    return {
        "mode": mode,
        "hours": None if mode == "range" else hours,
        "start": start.isoformat() if start is not None else None,
        "end": end.isoformat() if end is not None else None,
        "totals": {
            "requests_total": 0,
            "requests_window": 0,
            "distinct_ips": 0,
            "blocked": 0,
            "failed": 0,
            "pending": 0,
        },
        "timeseries": {"labels": [], "values": []},
        "methods": [],
        "top_ips": [],
        "blocked": [],
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


def _clamp_hours(raw) -> int:
    try:
        hours = int(raw)
    except (TypeError, ValueError):
        return 24
    if hours < 1:
        return 1
    if hours > 720:
        return 720
    return hours


def _parse_date_range(start_raw, end_raw):
    if not start_raw or not end_raw:
        return None
    try:
        start_date = datetime.date.fromisoformat(start_raw)
        end_date = datetime.date.fromisoformat(end_raw)
    except ValueError:
        return None
    if start_date > end_date:
        start_date, end_date = end_date, start_date
    if (end_date - start_date).days > 3650:
        end_date = start_date + datetime.timedelta(days=3650)
    return start_date, end_date


def create_app() -> Flask:
    load_dotenv(os.path.join(_REPO_ROOT, ".env"), override=False)

    mysql_host = os.environ.get("MYSQL_HOST")
    mysql_user = os.environ.get("MYSQL_USER")
    if not mysql_host or not mysql_user:
        raise RuntimeError("MYSQL_HOST and MYSQL_USER must be set for the web dashboard")

    mysql_port = int(os.environ.get("MYSQL_PORT", "3306"))
    mysql_database = os.environ.get("MYSQL_DATABASE", "sip_honeypot")
    mysql_password = os.environ.get("MYSQL_PASSWORD", "")

    basic_auth_enabled = _get_bool(os.environ.get("WEB_BASIC_AUTH_ENABLED"), False)
    basic_auth_username = os.environ.get("WEB_BASIC_AUTH_USERNAME")
    basic_auth_password = os.environ.get("WEB_BASIC_AUTH_PASSWORD")
    if basic_auth_enabled and (not basic_auth_username or not basic_auth_password):
        raise RuntimeError(
            "WEB_BASIC_AUTH_USERNAME and WEB_BASIC_AUTH_PASSWORD must be set when WEB_BASIC_AUTH_ENABLED is true"
        )

    app = Flask(__name__)

    if basic_auth_enabled:

        @app.before_request
        def _require_basic_auth():
            auth = request.authorization
            valid = (
                auth is not None
                and auth.username is not None
                and auth.password is not None
                and hmac.compare_digest(auth.username.encode("utf-8"), basic_auth_username.encode("utf-8"))
                and hmac.compare_digest(auth.password.encode("utf-8"), basic_auth_password.encode("utf-8"))
            )
            if not valid:
                return (
                    "Authentication required",
                    401,
                    {"WWW-Authenticate": 'Basic realm="SIP Honeypot Dashboard"'},
                )

    def _connect():
        return pymysql.connect(
            host=mysql_host,
            port=mysql_port,
            user=mysql_user,
            password=mysql_password,
            database=mysql_database,
            charset="utf8mb4",
            autocommit=True,
            connect_timeout=5,
            read_timeout=10,
            cursorclass=pymysql.cursors.DictCursor,
        )

    app.config["DB_CONNECT"] = _connect

    @app.route("/")
    def index():
        date_range = _parse_date_range(request.args.get("start"), request.args.get("end"))
        if date_range is not None:
            start_date, end_date = date_range
            hours = 24
        else:
            start_date = end_date = None
            hours = _clamp_hours(request.args.get("hours"))
        conn = None
        try:
            conn = app.config["DB_CONNECT"]()
            data = dashboard_data(conn, hours=hours, start=start_date, end=end_date)
            return render_template("index.html", data=data, db_error=None)
        except pymysql.err.Error as e:
            return render_template(
                "index.html", data=_empty_data(hours, start=start_date, end=end_date), db_error=str(e)
            )
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    @app.route("/healthz")
    def healthz():
        conn = None
        try:
            conn = app.config["DB_CONNECT"]()
            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.fetchone()
            return jsonify({"ok": True}), 200
        except pymysql.err.Error as e:
            return jsonify({"ok": False, "error": type(e).__name__}), 503
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    return app


app = create_app()
