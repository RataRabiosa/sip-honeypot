import datetime

import pymysql
import pymysql.cursors


def _to_naive_utc(ts: float) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).replace(tzinfo=None)


class MetricsDB:
    def __init__(self, host, port, user, password, database, connect_timeout=5.0):
        self._host = host
        self._port = port
        self._user = user
        self._password = password
        self._database = database
        self._connect_timeout = connect_timeout
        self._conn = None

    def connect(self):
        self._conn = pymysql.connect(
            host=self._host,
            port=self._port,
            user=self._user,
            password=self._password,
            database=self._database,
            charset="utf8mb4",
            autocommit=True,
            connect_timeout=self._connect_timeout,
            read_timeout=10,
            write_timeout=10,
            cursorclass=pymysql.cursors.DictCursor,
        )

    def close(self):
        try:
            if self._conn is not None:
                self._conn.close()
        except Exception:
            pass
        finally:
            self._conn = None

    @property
    def connected(self) -> bool:
        return self._conn is not None

    def insert_event(self, ev: dict) -> None:
        method = (ev.get("method") or "")[:32]
        user_agent = ev.get("user_agent")
        if user_agent is not None:
            user_agent = user_agent[:255]
        from_uri = ev.get("from_uri")
        if from_uri is not None:
            from_uri = from_uri[:255]
        to_uri = ev.get("to_uri")
        if to_uri is not None:
            to_uri = to_uri[:255]
        call_id = ev.get("call_id")
        if call_id is not None:
            call_id = call_id[:255]
        ts = _to_naive_utc(ev["ts"])
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO request_events "
                "(ts, src_ip, src_port, dst_host, dst_port, method, user_agent, from_uri, to_uri, call_id) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    ts,
                    ev["src_ip"],
                    ev["src_port"],
                    ev["dst_host"],
                    ev["dst_port"],
                    method,
                    user_agent,
                    from_uri,
                    to_uri,
                    call_id,
                ),
            )

    def upsert_source_ip(self, ip: str, ts: float) -> None:
        when = _to_naive_utc(ts)
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO source_ips (src_ip, first_seen, last_seen, request_count) "
                "VALUES (%s,%s,%s,1) AS new "
                "ON DUPLICATE KEY UPDATE last_seen = new.last_seen, "
                "request_count = source_ips.request_count + 1",
                (ip, when, when),
            )

    def load_blocked_ips(self) -> set:
        with self._conn.cursor() as cur:
            cur.execute("SELECT src_ip FROM blocked_ips WHERE status='blocked'")
            rows = cur.fetchall()
        return {row["src_ip"] for row in rows}

    def get_block_state(self, ip: str):
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT status, attempts, last_attempt_at FROM blocked_ips WHERE src_ip=%s",
                (ip,),
            )
            row = cur.fetchone()
        if not row:
            return None
        return {
            "status": row["status"],
            "attempts": row["attempts"],
            "last_attempt_at": row["last_attempt_at"],
        }

    def mark_block_pending(self, ip: str, ts: float, firewall_id: str) -> None:
        when = _to_naive_utc(ts)
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO blocked_ips (src_ip, status, attempts, first_attempt_at, last_attempt_at, firewall_id) "
                "VALUES (%s,'pending',1,%s,%s,%s) AS new "
                "ON DUPLICATE KEY UPDATE status='pending', attempts = blocked_ips.attempts + 1, "
                "last_attempt_at = new.last_attempt_at, firewall_id = new.firewall_id",
                (ip, when, when, firewall_id),
            )

    def mark_block_result(self, ip: str, ts: float, ok: bool, http_status, error) -> None:
        when = _to_naive_utc(ts)
        with self._conn.cursor() as cur:
            if ok:
                cur.execute(
                    "UPDATE blocked_ips SET status='blocked', blocked_at=%s, last_http_status=%s, "
                    "last_error=NULL WHERE src_ip=%s",
                    (when, http_status, ip),
                )
            else:
                if error is not None:
                    error = error[:512]
                cur.execute(
                    "UPDATE blocked_ips SET status='failed', last_http_status=%s, last_error=%s WHERE src_ip=%s",
                    (http_status, error, ip),
                )

    def count_blocked(self) -> int:
        with self._conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM blocked_ips WHERE status='blocked'")
            row = cur.fetchone()
        return int(row["n"]) if row else 0
