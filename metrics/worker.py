import datetime
import queue
import threading
import time
from collections import OrderedDict

import pymysql.err

from metrics.policy import is_blockable


class MetricsWorker:
    _STOP = object()

    # Cap on the number of distinct source IPs tracked in the dedup helper
    # structures below. Without a bound, a honeypot with long uptime against
    # an effectively unlimited number of distinct scanner IPs would grow
    # these structures without bound. Oldest entries are evicted first.
    _MAX_DEDUP_ENTRIES = 50000

    def __init__(self, settings, db, firewall, log_fn, clock=time.time):
        self._settings = settings
        self._db = db
        self._firewall = firewall  # may be None if DO blocking disabled
        self._log = log_fn
        self._clock = clock
        self._queue = queue.Queue(maxsize=settings.metrics_queue_size)
        self._thread = None
        self._next_db_connect_at = 0.0
        self._known_blocked = set()
        self._policy_skipped = OrderedDict()
        self._next_attempt_at = OrderedDict()
        self._cooldown_until = 0.0
        self._blocked_count = 0
        self.submitted = 0
        self.processed = 0
        self.dropped = 0
        self.db_errors = 0
        self.blocks_ok = 0
        self.blocks_failed = 0

    def start(self):
        self._thread = threading.Thread(target=self._run, name="metrics-worker", daemon=True)
        self._thread.start()

    def stop(self, timeout=5.0):
        if self._thread is None:
            return
        try:
            self._queue.put_nowait(self._STOP)
        except queue.Full:
            pass
        self._thread.join(timeout)

    def submit(self, event) -> bool:
        self.submitted += 1
        try:
            self._queue.put_nowait(event)
            return True
        except queue.Full:
            self.dropped += 1
            return False

    def _run(self):
        while True:
            item = self._queue.get()
            if item is self._STOP:
                break
            try:
                self._process(item)
                self.processed += 1
            except Exception as e:
                self._log(f"METRICS_WORKER_ERROR - {type(e).__name__}: {e}")
        try:
            self._db.close()
        except Exception:
            pass

    def _ensure_db(self):
        if not self._db.connected and self._clock() >= self._next_db_connect_at:
            try:
                self._db.connect()
                self._log("METRICS_DB - connected")
                self._known_blocked = self._db.load_blocked_ips()
                self._blocked_count = len(self._known_blocked)
            except Exception as e:
                self._next_db_connect_at = self._clock() + 5.0
                self.db_errors += 1
                self._log(f"METRICS_DB - connect failed: {type(e).__name__}: {e}")

        if not self._db.connected:
            self.dropped += 1
            if self.dropped == 1 or self.dropped % 1000 == 0:
                self._log(f"METRICS_DB - unavailable, dropped={self.dropped}")
            return False
        return True

    def _process(self, event):
        if not self._ensure_db():
            return

        try:
            self._db.insert_event(event)
            self._db.upsert_source_ip(event["src_ip"], event["ts"])
        except (pymysql.err.OperationalError, pymysql.err.InterfaceError) as e:
            self._db.close()
            self._next_db_connect_at = self._clock() + 5.0
            self.db_errors += 1
            self._log(f"METRICS_DB - error: {type(e).__name__}: {e}")
            return
        except pymysql.err.Error as e:
            self._log(f"METRICS_DB - error: {type(e).__name__}: {e}")

        try:
            self._maybe_block(event["src_ip"], self._clock())
        except Exception as e:
            self._log(f"METRICS_WORKER_ERROR - {type(e).__name__}: {e}")

    def _bounded_set_add(self, ordered_dict, key):
        """Insert key into an OrderedDict used as an ordered set, evicting the
        oldest entry first if the structure would exceed _MAX_DEDUP_ENTRIES."""
        if key in ordered_dict:
            return
        if len(ordered_dict) >= self._MAX_DEDUP_ENTRIES:
            ordered_dict.popitem(last=False)
        ordered_dict[key] = True

    def _bounded_dict_set(self, ordered_dict, key, value):
        """Set ordered_dict[key] = value, evicting the oldest entry first if
        the structure would exceed _MAX_DEDUP_ENTRIES."""
        if key in ordered_dict:
            del ordered_dict[key]
        elif len(ordered_dict) >= self._MAX_DEDUP_ENTRIES:
            ordered_dict.popitem(last=False)
        ordered_dict[key] = value

    def _maybe_block(self, ip, now):
        if self._firewall is None:
            return
        if ip in self._known_blocked:
            return
        if not is_blockable(ip, self._settings.do_never_block):
            if ip not in self._policy_skipped:
                self._bounded_set_add(self._policy_skipped, ip)
                self._log(f"DO_BLOCK - skip {ip} (policy)")
            return
        if now < self._next_attempt_at.get(ip, 0):
            return
        if now < self._cooldown_until:
            return

        state = self._db.get_block_state(ip)
        if state and state["status"] == "blocked":
            self._known_blocked.add(ip)
            return
        if state:
            last_attempt_ts = state["last_attempt_at"].replace(tzinfo=datetime.timezone.utc).timestamp()
            if now - last_attempt_ts < self._settings.do_retry_interval:
                self._bounded_dict_set(self._next_attempt_at, ip, last_attempt_ts + self._settings.do_retry_interval)
                return

        if self._blocked_count >= self._settings.do_max_blocked_ips:
            self._db.mark_block_pending(ip, now, self._settings.do_firewall_id)
            self._db.mark_block_result(ip, now, False, None, "LOCAL_CAP_REACHED")
            self._bounded_dict_set(self._next_attempt_at, ip, now + self._settings.do_retry_interval)
            self._log(f"DO_BLOCK - cap reached ({self._blocked_count}), not calling API for {ip}")
            return

        self._db.mark_block_pending(ip, now, self._settings.do_firewall_id)
        res = self._firewall.add_deny_rule(ip)
        self._db.mark_block_result(ip, self._clock(), res.ok, res.http_status, res.error)

        if res.ok:
            self._known_blocked.add(ip)
            self._blocked_count += 1
            self.blocks_ok += 1
            self._log(f"DO_BLOCK - blocked {ip} (HTTP {res.http_status})")
        else:
            self.blocks_failed += 1
            self._cooldown_until = now + self._settings.do_failure_cooldown
            self._bounded_dict_set(self._next_attempt_at, ip, now + self._settings.do_retry_interval)
            self._log(f"DO_BLOCK - FAILED {ip} status={res.http_status} error={(res.error or '')[:200]}")
