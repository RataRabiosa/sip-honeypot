import datetime
import math

BLOCKED_PAGE_SIZE = 25


def _escape_like(term: str) -> str:
    """Escape MySQL LIKE wildcards in ``term`` using the default ``\\`` escape char."""
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _fetch_blocked(cur, blocked_page: int, blocked_search):
    """Run the paginated/search-filtered Blocked IPs query.

    Returns a dict with ``blocked``, ``blocked_total``, ``blocked_page`` (clamped),
    ``blocked_pages``, and ``blocked_search`` (original, unescaped term or None).
    """
    where = ""
    params = []
    if blocked_search:
        where = "WHERE src_ip LIKE %s "
        params.append("%" + _escape_like(blocked_search) + "%")

    if params:
        cur.execute(f"SELECT COUNT(*) AS n FROM blocked_ips {where}".rstrip(), tuple(params))
    else:
        cur.execute("SELECT COUNT(*) AS n FROM blocked_ips")
    blocked_total = cur.fetchone()["n"]
    blocked_pages = max(1, math.ceil(blocked_total / BLOCKED_PAGE_SIZE))
    page = min(max(1, blocked_page), blocked_pages)

    row_params = params + [BLOCKED_PAGE_SIZE, (page - 1) * BLOCKED_PAGE_SIZE]
    cur.execute(
        "SELECT src_ip, status, attempts, first_attempt_at, last_attempt_at, blocked_at, last_http_status, last_error "
        f"FROM blocked_ips {where}ORDER BY COALESCE(blocked_at, last_attempt_at) DESC LIMIT %s OFFSET %s",
        tuple(row_params),
    )
    blocked = [
        {
            "src_ip": row["src_ip"],
            "status": row["status"],
            "attempts": row["attempts"],
            "first_attempt_at": row["first_attempt_at"],
            "last_attempt_at": row["last_attempt_at"],
            "blocked_at": row["blocked_at"],
            "last_http_status": row["last_http_status"],
            "last_error": row["last_error"],
        }
        for row in cur.fetchall()
    ]

    return {
        "blocked": blocked,
        "blocked_total": blocked_total,
        "blocked_page": page,
        "blocked_pages": blocked_pages,
        "blocked_search": blocked_search,
    }


def _hourly_labels(hours: int):
    now = datetime.datetime.now(datetime.timezone.utc)
    start = (now - datetime.timedelta(hours=hours)).replace(minute=0, second=0, microsecond=0)
    return _hourly_labels_from(start, hours)


def _hourly_labels_from(start: datetime.datetime, hours: int):
    labels = []
    for i in range(hours + 1):
        bucket = start + datetime.timedelta(hours=i)
        labels.append(bucket.strftime("%Y-%m-%d %H:00"))
    return labels


def _daily_labels(start_date: datetime.date, end_date: datetime.date):
    labels = []
    day = start_date
    while day <= end_date:
        labels.append(day.strftime("%Y-%m-%d"))
        day += datetime.timedelta(days=1)
    return labels


def _range_dashboard_data(
    conn, start: datetime.date, end: datetime.date, blocked_page: int = 1, blocked_search=None
) -> dict:
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) AS n FROM request_events")
    requests_total = cur.fetchone()["n"]

    window_start = datetime.datetime.combine(start, datetime.time.min, tzinfo=datetime.timezone.utc)
    window_end = datetime.datetime.combine(end, datetime.time.min, tzinfo=datetime.timezone.utc) + datetime.timedelta(
        days=1
    )

    cur.execute(
        "SELECT COUNT(*) AS n FROM request_events WHERE ts >= %s AND ts < %s",
        (window_start, window_end),
    )
    requests_window = cur.fetchone()["n"]

    cur.execute("SELECT COUNT(*) AS n FROM source_ips")
    distinct_ips = cur.fetchone()["n"]

    cur.execute("SELECT status, COUNT(*) AS n FROM blocked_ips GROUP BY status")
    status_counts = {"blocked": 0, "failed": 0, "pending": 0, "unblocking": 0, "expired": 0}
    for row in cur.fetchall():
        if row["status"] in status_counts:
            status_counts[row["status"]] = row["n"]

    if (end - start).days <= 3:
        cur.execute(
            "SELECT DATE_FORMAT(ts, '%%Y-%%m-%%d %%H:00') AS bucket, COUNT(*) AS n "
            "FROM request_events WHERE ts >= %s AND ts < %s GROUP BY bucket ORDER BY bucket",
            (window_start, window_end),
        )
        bucket_counts = {row["bucket"]: row["n"] for row in cur.fetchall()}
        span_hours = int((window_end - window_start).total_seconds() // 3600) - 1
        labels = _hourly_labels_from(window_start, span_hours)
    else:
        cur.execute(
            "SELECT DATE_FORMAT(ts, '%%Y-%%m-%%d') AS bucket, COUNT(*) AS n "
            "FROM request_events WHERE ts >= %s AND ts < %s GROUP BY bucket ORDER BY bucket",
            (window_start, window_end),
        )
        bucket_counts = {row["bucket"]: row["n"] for row in cur.fetchall()}
        labels = _daily_labels(start, end)

    values = [bucket_counts.get(label, 0) for label in labels]

    cur.execute(
        "SELECT method, COUNT(*) AS n FROM request_events "
        "WHERE ts >= %s AND ts < %s GROUP BY method ORDER BY n DESC LIMIT 15",
        (window_start, window_end),
    )
    methods = [{"method": row["method"], "n": row["n"]} for row in cur.fetchall()]

    cur.execute(
        "SELECT s.src_ip, s.request_count, s.first_seen, s.last_seen, b.status AS block_status "
        "FROM source_ips s LEFT JOIN blocked_ips b ON b.src_ip = s.src_ip "
        "ORDER BY s.request_count DESC, s.last_seen DESC LIMIT 20"
    )
    top_ips = [
        {
            "src_ip": row["src_ip"],
            "request_count": row["request_count"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "block_status": row["block_status"],
        }
        for row in cur.fetchall()
    ]

    blocked_result = _fetch_blocked(cur, blocked_page, blocked_search)

    return {
        "mode": "range",
        "hours": None,
        "start": start.isoformat(),
        "end": end.isoformat(),
        "totals": {
            "requests_total": requests_total,
            "requests_window": requests_window,
            "distinct_ips": distinct_ips,
            "blocked": status_counts["blocked"],
            "failed": status_counts["failed"],
            "pending": status_counts["pending"],
            "unblocking": status_counts["unblocking"],
            "expired": status_counts["expired"],
        },
        "timeseries": {"labels": labels, "values": values},
        "methods": methods,
        "top_ips": top_ips,
        "blocked": blocked_result["blocked"],
        "blocked_total": blocked_result["blocked_total"],
        "blocked_page": blocked_result["blocked_page"],
        "blocked_pages": blocked_result["blocked_pages"],
        "blocked_search": blocked_result["blocked_search"],
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


def dashboard_data(conn, hours: int = 24, start=None, end=None, blocked_page: int = 1, blocked_search=None) -> dict:
    if start is not None and end is not None:
        return _range_dashboard_data(conn, start, end, blocked_page=blocked_page, blocked_search=blocked_search)

    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) AS n FROM request_events")
    requests_total = cur.fetchone()["n"]

    cur.execute("SELECT COUNT(*) AS n FROM request_events WHERE ts >= UTC_TIMESTAMP(3) - INTERVAL %s HOUR", (hours,))
    requests_window = cur.fetchone()["n"]

    cur.execute("SELECT COUNT(*) AS n FROM source_ips")
    distinct_ips = cur.fetchone()["n"]

    cur.execute("SELECT status, COUNT(*) AS n FROM blocked_ips GROUP BY status")
    status_counts = {"blocked": 0, "failed": 0, "pending": 0, "unblocking": 0, "expired": 0}
    for row in cur.fetchall():
        if row["status"] in status_counts:
            status_counts[row["status"]] = row["n"]

    cur.execute(
        "SELECT DATE_FORMAT(ts, '%%Y-%%m-%%d %%H:00') AS bucket, COUNT(*) AS n "
        "FROM request_events WHERE ts >= UTC_TIMESTAMP(3) - INTERVAL %s HOUR GROUP BY bucket ORDER BY bucket",
        (hours,),
    )
    bucket_counts = {row["bucket"]: row["n"] for row in cur.fetchall()}

    labels = _hourly_labels(hours)
    values = [bucket_counts.get(label, 0) for label in labels]

    cur.execute(
        "SELECT method, COUNT(*) AS n FROM request_events "
        "WHERE ts >= UTC_TIMESTAMP(3) - INTERVAL %s HOUR GROUP BY method ORDER BY n DESC LIMIT 15",
        (hours,),
    )
    methods = [{"method": row["method"], "n": row["n"]} for row in cur.fetchall()]

    cur.execute(
        "SELECT s.src_ip, s.request_count, s.first_seen, s.last_seen, b.status AS block_status "
        "FROM source_ips s LEFT JOIN blocked_ips b ON b.src_ip = s.src_ip "
        "ORDER BY s.request_count DESC, s.last_seen DESC LIMIT 20"
    )
    top_ips = [
        {
            "src_ip": row["src_ip"],
            "request_count": row["request_count"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "block_status": row["block_status"],
        }
        for row in cur.fetchall()
    ]

    blocked_result = _fetch_blocked(cur, blocked_page, blocked_search)

    return {
        "mode": "hours",
        "hours": hours,
        "start": None,
        "end": None,
        "totals": {
            "requests_total": requests_total,
            "requests_window": requests_window,
            "distinct_ips": distinct_ips,
            "blocked": status_counts["blocked"],
            "failed": status_counts["failed"],
            "pending": status_counts["pending"],
            "unblocking": status_counts["unblocking"],
            "expired": status_counts["expired"],
        },
        "timeseries": {"labels": labels, "values": values},
        "methods": methods,
        "top_ips": top_ips,
        "blocked": blocked_result["blocked"],
        "blocked_total": blocked_result["blocked_total"],
        "blocked_page": blocked_result["blocked_page"],
        "blocked_pages": blocked_result["blocked_pages"],
        "blocked_search": blocked_result["blocked_search"],
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
