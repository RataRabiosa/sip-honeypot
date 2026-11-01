import datetime
import os

import pymysql
import pymysql.cursors
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

from web.queries import dashboard_data

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _empty_data(hours: int) -> dict:
    return {
        "hours": hours,
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


def create_app() -> Flask:
    load_dotenv(os.path.join(_REPO_ROOT, ".env"), override=False)

    mysql_host = os.environ.get("MYSQL_HOST")
    mysql_user = os.environ.get("MYSQL_USER")
    if not mysql_host or not mysql_user:
        raise RuntimeError("MYSQL_HOST and MYSQL_USER must be set for the web dashboard")

    mysql_port = int(os.environ.get("MYSQL_PORT", "3306"))
    mysql_database = os.environ.get("MYSQL_DATABASE", "sip_honeypot")
    mysql_password = os.environ.get("MYSQL_PASSWORD", "")

    app = Flask(__name__)

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
        hours = _clamp_hours(request.args.get("hours"))
        conn = None
        try:
            conn = app.config["DB_CONNECT"]()
            data = dashboard_data(conn, hours)
            return render_template("index.html", data=data, db_error=None)
        except pymysql.err.Error as e:
            return render_template("index.html", data=_empty_data(hours), db_error=str(e))
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
