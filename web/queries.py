import datetime


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


def _range_dashboard_data(conn, start: datetime.date, end: datetime.date) -> dict:
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
    status_counts = {"blocked": 0, "failed": 0, "pending": 0}
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

    cur.execute(
        "SELECT src_ip, status, attempts, first_attempt_at, last_attempt_at, blocked_at, last_http_status, last_error "
        "FROM blocked_ips ORDER BY COALESCE(blocked_at, last_attempt_at) DESC LIMIT 200"
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
        },
        "timeseries": {"labels": labels, "values": values},
        "methods": methods,
        "top_ips": top_ips,
        "blocked": blocked,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


def dashboard_data(conn, hours: int = 24, start=None, end=None) -> dict:
    if start is not None and end is not None:
        return _range_dashboard_data(conn, start, end)

    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) AS n FROM request_events")
    requests_total = cur.fetchone()["n"]

    cur.execute("SELECT COUNT(*) AS n FROM request_events WHERE ts >= UTC_TIMESTAMP(3) - INTERVAL %s HOUR", (hours,))
    requests_window = cur.fetchone()["n"]

    cur.execute("SELECT COUNT(*) AS n FROM source_ips")
    distinct_ips = cur.fetchone()["n"]

    cur.execute("SELECT status, COUNT(*) AS n FROM blocked_ips GROUP BY status")
    status_counts = {"blocked": 0, "failed": 0, "pending": 0}
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

    cur.execute(
        "SELECT src_ip, status, attempts, first_attempt_at, last_attempt_at, blocked_at, last_http_status, last_error "
        "FROM blocked_ips ORDER BY COALESCE(blocked_at, last_attempt_at) DESC LIMIT 200"
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
        },
        "timeseries": {"labels": labels, "values": values},
        "methods": methods,
        "top_ips": top_ips,
        "blocked": blocked,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
