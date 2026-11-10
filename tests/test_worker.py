import datetime
import time
import types

import pytest

from metrics.dofirewall import DOResult
from metrics.worker import MetricsWorker


def _utc(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).replace(tzinfo=None)


class FakeDB:
    """In-memory stand-in for MetricsDB implementing only what MetricsWorker calls."""

    def __init__(self, initially_blocked=None):
        self._connected = False
        self.events = []
        self.upserts = []
        self.blocked_ips = set(initially_blocked or [])
        self.state = {}  # ip -> dict(status, attempts, last_attempt_at)

    def connect(self):
        self._connected = True

    def close(self):
        self._connected = False

    @property
    def connected(self):
        return self._connected

    def insert_event(self, ev):
        self.events.append(ev)

    def upsert_source_ip(self, ip, ts):
        self.upserts.append((ip, ts))

    def load_blocked_ips(self):
        return set(self.blocked_ips)

    def get_block_state(self, ip):
        return self.state.get(ip)

    def mark_block_pending(self, ip, ts, firewall_id):
        st = self.state.setdefault(ip, {"status": "pending", "attempts": 0, "last_attempt_at": _utc(ts)})
        st["status"] = "pending"
        st["attempts"] += 1
        st["last_attempt_at"] = _utc(ts)

    def mark_block_result(self, ip, ts, ok, http_status, error, firewall_id=None):
        st = self.state.setdefault(ip, {"status": "pending", "attempts": 1, "last_attempt_at": _utc(ts)})
        if ok:
            st["status"] = "blocked"
            if firewall_id is not None:
                st["firewall_id"] = firewall_id
            self.blocked_ips.add(ip)
        else:
            st["status"] = "failed"

    def count_blocked(self):
        return len(self.blocked_ips)

    def list_failed_ips_for_retry(self, before_ts, limit):
        cutoff = _utc(before_ts)
        candidates = [
            (ip, st["last_attempt_at"])
            for ip, st in self.state.items()
            if st["status"] == "failed" and st["last_attempt_at"] <= cutoff
        ]
        candidates.sort(key=lambda pair: pair[1])
        return [ip for ip, _ in candidates[:limit]]


class FakeFirewall:
    def __init__(self, result=None):
        self.calls = []
        self._result = result or DOResult(True, 204, None)

    def add_deny_rule(self, ip):
        self.calls.append(ip)
        return self._result


def _settings(**overrides):
    base = dict(
        metrics_queue_size=100,
        do_never_block=(),
        do_retry_interval=300,
        do_failure_cooldown=60,
        do_max_blocked_ips=1000,
        do_firewall_id="fw-1",
    )
    base.update(overrides)
    return types.SimpleNamespace(**base)


def make_event(ip, ts):
    return {
        "ts": ts,
        "src_ip": ip,
        "src_port": 5060,
        "dst_host": "0.0.0.0",
        "dst_port": 5060,
        "method": "OPTIONS",
        "user_agent": None,
        "from_uri": None,
        "to_uri": None,
        "call_id": None,
    }


def test_sharded_blocker_result_records_actual_firewall_id_not_configured_primary():
    db = FakeDB()
    # Simulates a ShardedFirewallBlocker that spilled past the configured
    # primary firewall ("fw-1") to a third shard ("fw-3").
    fw = FakeFirewall(result=DOResult(True, 200, None, "fw-3"))
    logs = []
    worker = MetricsWorker(_settings(do_firewall_id="fw-1"), db, fw, log_fn=logs.append, clock=lambda: 1000.0)

    worker._process(make_event("1.1.1.1", 1000.0))

    assert fw.calls == ["1.1.1.1"]
    assert db.state["1.1.1.1"]["status"] == "blocked"
    assert db.state["1.1.1.1"]["firewall_id"] == "fw-3"


def test_event_is_inserted_and_upserted():
    db = FakeDB()
    fw = FakeFirewall()
    logs = []
    worker = MetricsWorker(_settings(), db, fw, log_fn=logs.append, clock=lambda: 1000.0)

    worker._process(make_event("203.0.113.1", 1000.0))

    assert len(db.events) == 1
    assert db.upserts == [("203.0.113.1", 1000.0)]


def test_new_global_ip_triggers_single_block_call():
    db = FakeDB()
    fw = FakeFirewall()
    logs = []
    worker = MetricsWorker(_settings(), db, fw, log_fn=logs.append, clock=lambda: 1000.0)

    worker._process(make_event("1.1.1.1", 1000.0))
    assert fw.calls == ["1.1.1.1"]
    assert db.state["1.1.1.1"]["status"] == "blocked"

    # second event from same IP: no additional firewall calls
    worker._process(make_event("1.1.1.1", 1001.0))
    assert fw.calls == ["1.1.1.1"]


def test_private_ip_never_triggers_a_call():
    db = FakeDB()
    fw = FakeFirewall()
    logs = []
    worker = MetricsWorker(_settings(), db, fw, log_fn=logs.append, clock=lambda: 1000.0)

    worker._process(make_event("10.0.0.5", 1000.0))
    assert fw.calls == []
    assert "10.0.0.5" not in db.state


def test_failure_triggers_cooldown_and_retry_interval():
    db = FakeDB()
    fw = FakeFirewall(result=DOResult(False, 500, "boom"))
    logs = []
    clock_value = [1000.0]
    worker = MetricsWorker(
        _settings(do_retry_interval=300, do_failure_cooldown=60),
        db,
        fw,
        log_fn=logs.append,
        clock=lambda: clock_value[0],
    )

    worker._process(make_event("1.1.1.1", clock_value[0]))
    assert fw.calls == ["1.1.1.1"]
    assert db.state["1.1.1.1"]["status"] == "failed"

    # a different new IP within the cooldown window must not be called
    clock_value[0] = 1010.0  # within 60s cooldown
    worker._process(make_event("8.8.8.8", clock_value[0]))
    assert fw.calls == ["1.1.1.1"]

    # the same failed IP retried too soon (before retry interval) -> no call
    clock_value[0] = 1070.0  # past cooldown (60s), but before retry_interval (300s)
    worker._process(make_event("1.1.1.1", clock_value[0]))
    assert fw.calls == ["1.1.1.1"]

    # after the retry interval has elapsed, the same IP may be retried
    clock_value[0] = 1000.0 + 301.0
    worker._process(make_event("1.1.1.1", clock_value[0]))
    assert fw.calls == ["1.1.1.1", "1.1.1.1"]


def test_ip_already_in_known_blocked_set_is_never_called():
    db = FakeDB(initially_blocked={"1.1.1.1"})
    fw = FakeFirewall()
    logs = []
    worker = MetricsWorker(_settings(), db, fw, log_fn=logs.append, clock=lambda: 1000.0)
    worker._ensure_db()  # populates _known_blocked from load_blocked_ips()

    worker._process(make_event("1.1.1.1", 1000.0))
    assert fw.calls == []


def test_cap_reached_records_local_cap_without_firewall_call():
    db = FakeDB()
    fw = FakeFirewall()
    logs = []
    worker = MetricsWorker(_settings(do_max_blocked_ips=1), db, fw, log_fn=logs.append, clock=lambda: 1000.0)

    worker._process(make_event("1.1.1.1", 1000.0))
    assert fw.calls == ["1.1.1.1"]
    assert worker._blocked_count == 1

    worker._process(make_event("8.8.8.8", 1000.0))
    assert fw.calls == ["1.1.1.1"]
    assert db.state["8.8.8.8"]["status"] == "failed"


def test_submit_returns_false_and_increments_dropped_when_queue_full():
    db = FakeDB()
    fw = FakeFirewall()
    logs = []
    worker = MetricsWorker(_settings(metrics_queue_size=100), db, fw, log_fn=logs.append)
    # queue maxsize comes from settings.metrics_queue_size; shrink it for the test
    import queue

    worker._queue = queue.Queue(maxsize=1)
    assert worker.submit({"a": 1}) is True
    assert worker.submit({"a": 2}) is False
    assert worker.dropped == 1


def test_policy_skipped_and_next_attempt_at_are_bounded():
    db = FakeDB()
    fw = FakeFirewall()
    logs = []
    clock_value = [1000.0]
    worker = MetricsWorker(
        _settings(do_failure_cooldown=0),
        db,
        fw,
        log_fn=logs.append,
        clock=lambda: clock_value[0],
    )
    worker._MAX_DEDUP_ENTRIES = 5

    # Drive _policy_skipped growth via private (non-global) IPs, which are
    # never blockable and so only touch _policy_skipped.
    for i in range(20):
        worker._maybe_block(f"10.0.0.{i}", clock_value[0])
    assert len(worker._policy_skipped) <= worker._MAX_DEDUP_ENTRIES

    # Drive _next_attempt_at growth via repeated firewall failures across
    # many distinct globally-routable IPs. do_failure_cooldown=0 ensures the
    # global cooldown gate never blocks each new IP's first attempt.
    fw._result = DOResult(False, 500, "boom")
    for i in range(20):
        clock_value[0] += 1.0
        worker._maybe_block(f"1.1.{i}.1", clock_value[0])
    assert len(worker._next_attempt_at) <= worker._MAX_DEDUP_ENTRIES


def test_stop_returns_without_hanging():
    db = FakeDB()
    fw = FakeFirewall()
    logs = []
    worker = MetricsWorker(_settings(), db, fw, log_fn=logs.append)
    worker.start()
    worker.stop(timeout=5.0)
    assert not worker._thread.is_alive()


def test_sweep_retries_failed_ip_once_retry_interval_has_elapsed():
    db = FakeDB()
    fw = FakeFirewall(result=DOResult(False, 500, "boom"))
    logs = []
    clock_value = [1000.0]
    worker = MetricsWorker(
        _settings(do_retry_interval=300, do_failure_cooldown=0),
        db,
        fw,
        log_fn=logs.append,
        clock=lambda: clock_value[0],
    )

    worker._process(make_event("1.1.1.1", clock_value[0]))
    assert fw.calls == ["1.1.1.1"]
    assert db.state["1.1.1.1"]["status"] == "failed"

    # Before the retry interval has elapsed, a sweep must not retry the IP.
    clock_value[0] = 1000.0 + 299.0
    worker._next_sweep_at = 0.0  # force the sweep to be due regardless of cadence
    worker._maybe_sweep_failed_blocks()
    assert fw.calls == ["1.1.1.1"]

    # Once the retry interval has elapsed, the sweep retries it without any
    # new inbound traffic for that IP.
    clock_value[0] = 1000.0 + 301.0
    worker._next_sweep_at = 0.0
    worker._maybe_sweep_failed_blocks()
    assert fw.calls == ["1.1.1.1", "1.1.1.1"]


def test_sweep_is_noop_when_firewall_disabled():
    db = FakeDB()
    logs = []
    clock_value = [1000.0]
    worker = MetricsWorker(
        _settings(do_retry_interval=300),
        db,
        None,
        log_fn=logs.append,
        clock=lambda: clock_value[0],
    )

    called = []
    db.list_failed_ips_for_retry = lambda *a, **k: called.append(1) or []

    worker._next_sweep_at = 0.0
    worker._maybe_sweep_failed_blocks()

    assert called == []
    assert not db.connected


def test_sweep_does_not_rerun_until_next_sweep_at_elapses():
    db = FakeDB()
    fw = FakeFirewall(result=DOResult(False, 500, "boom"))
    logs = []
    clock_value = [1000.0]
    worker = MetricsWorker(
        _settings(do_retry_interval=300, do_failure_cooldown=0),
        db,
        fw,
        log_fn=logs.append,
        clock=lambda: clock_value[0],
    )

    worker._process(make_event("1.1.1.1", clock_value[0]))
    assert fw.calls == ["1.1.1.1"]

    clock_value[0] = 1000.0 + 301.0
    worker._next_sweep_at = 0.0
    worker._maybe_sweep_failed_blocks()
    assert fw.calls == ["1.1.1.1", "1.1.1.1"]

    # A second call at the same `now`, without advancing past the newly set
    # _next_sweep_at, must not run the sweep again.
    worker._maybe_sweep_failed_blocks()
    assert fw.calls == ["1.1.1.1", "1.1.1.1"]
