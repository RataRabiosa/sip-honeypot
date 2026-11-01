import datetime


def _hourly_labels(hours: int):
    now = datetime.datetime.now(datetime.timezone.utc)
    start = (now - datetime.timedelta(hours=hours)).replace(minute=0, second=0, microsecond=0)
    labels = []
    for i in range(hours + 1):
        bucket = start + datetime.timedelta(hours=i)
        labels.append(bucket.strftime("%Y-%m-%d %H:00"))
    return labels


def dashboard_data(conn, hours: int) -> dict:
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
        "hours": hours,
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
