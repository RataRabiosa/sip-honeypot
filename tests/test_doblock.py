from metrics.doapi import DOResult
from metrics.doblock import FanoutBlocker, ShardedFirewallBlocker


class FakeFirewall:
    def __init__(self, result=None, firewall_id=None, remove_result=None):
        self.calls = []
        self.remove_calls = []
        self.firewall_id = firewall_id
        self._result = result or DOResult(True, 204, None)
        self._remove_result = remove_result

    def add_deny_rule(self, ip):
        self.calls.append(ip)
        return self._result

    def remove_deny_rule(self, ip, firewall_id=None):
        self.remove_calls.append((ip, firewall_id))
        return self._remove_result if self._remove_result is not None else self._result


class FakeLoadBalancer:
    def __init__(self, lb_id, result=None):
        self.lb_id = lb_id
        self.calls = []
        self.remove_calls = []
        self._result = result or DOResult(True, 200, None)

    def add_deny_rule(self, ip):
        self.calls.append(ip)
        return self._result

    def remove_deny_rule(self, ip):
        self.remove_calls.append(ip)
        return self._result


def test_firewall_first_ordering_all_succeed():
    firewall = FakeFirewall(result=DOResult(True, 204, None))
    lb1 = FakeLoadBalancer("lb-1", result=DOResult(True, 200, None))
    lb2 = FakeLoadBalancer("lb-2", result=DOResult(True, 200, None))
    blocker = FanoutBlocker(firewall, [lb1, lb2])

    result = blocker.add_deny_rule("198.51.100.7")

    assert firewall.calls == ["198.51.100.7"]
    assert lb1.calls == ["198.51.100.7"]
    assert lb2.calls == ["198.51.100.7"]
    assert result is firewall._result
    assert result == DOResult(True, 204, None)


def test_firewall_failure_zero_lb_calls():
    firewall_result = DOResult(False, 500, "boom")
    firewall = FakeFirewall(result=firewall_result)
    lb1 = FakeLoadBalancer("lb-1")
    lb2 = FakeLoadBalancer("lb-2")
    blocker = FanoutBlocker(firewall, [lb1, lb2])

    result = blocker.add_deny_rule("198.51.100.7")

    assert firewall.calls == ["198.51.100.7"]
    assert lb1.calls == []
    assert lb2.calls == []
    assert result is firewall_result
    assert result == firewall_result


def test_first_lb_failure_stops_fanout():
    firewall = FakeFirewall(result=DOResult(True, 204, None))
    lb1_result = DOResult(False, 422, "invalid firewall entry")
    lb1 = FakeLoadBalancer("lb-1", result=lb1_result)
    lb2 = FakeLoadBalancer("lb-2")
    blocker = FanoutBlocker(firewall, [lb1, lb2])

    result = blocker.add_deny_rule("198.51.100.7")

    assert lb1.calls == ["198.51.100.7"]
    assert lb2.calls == []
    assert result == DOResult(False, 422, "LB lb-1: invalid firewall entry")


def test_firewall_already_present_still_triggers_lb_fanout():
    firewall = FakeFirewall(result=DOResult(True, 200, None))
    lb1 = FakeLoadBalancer("lb-1")
    blocker = FanoutBlocker(firewall, [lb1])

    result = blocker.add_deny_rule("198.51.100.7")

    assert lb1.calls == ["198.51.100.7"]
    assert result == DOResult(True, 200, None)


def test_empty_load_balancers_behaves_like_bare_firewall():
    firewall_result = DOResult(True, 204, None)
    firewall = FakeFirewall(result=firewall_result)
    blocker = FanoutBlocker(firewall, [])

    result = blocker.add_deny_rule("198.51.100.7")

    assert result is firewall_result


def test_second_lb_never_called_after_first_lb_failure_values_preserved():
    firewall = FakeFirewall(result=DOResult(True, 204, None))
    lb1 = FakeLoadBalancer("lb-1", result=DOResult(False, None, "ConnectionRefusedError: boom"))
    lb2 = FakeLoadBalancer("lb-2", result=DOResult(True, 200, None))
    blocker = FanoutBlocker(firewall, [lb1, lb2])

    result = blocker.add_deny_rule("198.51.100.9")

    assert result.ok is False
    assert result.http_status is None
    assert result.error == "LB lb-1: ConnectionRefusedError: boom"
    assert lb2.calls == []


def test_sharded_blocker_shard_zero_succeeds_shard_one_never_called():
    shard0 = FakeFirewall(result=DOResult(True, 200, None, "fw-0"), firewall_id="fw-0")
    shard1 = FakeFirewall(firewall_id="fw-1")
    blocker = ShardedFirewallBlocker([shard0, shard1])

    result = blocker.add_deny_rule("198.51.100.7")

    assert shard0.calls == ["198.51.100.7"]
    assert shard1.calls == []
    assert result == DOResult(True, 200, None, "fw-0")


def test_sharded_blocker_cap_reached_spills_to_shard_one():
    shard0 = FakeFirewall(
        result=DOResult(False, None, "REMOTE_CAP_REACHED: firewall has 1000 deny addresses (limit 1000)", "fw-0"),
        firewall_id="fw-0",
    )
    shard1 = FakeFirewall(result=DOResult(True, 200, None, "fw-1"), firewall_id="fw-1")
    blocker = ShardedFirewallBlocker([shard0, shard1])

    result = blocker.add_deny_rule("198.51.100.7")

    assert shard0.calls == ["198.51.100.7"]
    assert shard1.calls == ["198.51.100.7"]
    assert result == DOResult(True, 200, None, "fw-1")


def test_sharded_blocker_all_shards_cap_reached_returns_last_result():
    shard0 = FakeFirewall(result=DOResult(False, None, "REMOTE_CAP_REACHED: shard 0 full", "fw-0"), firewall_id="fw-0")
    shard1 = FakeFirewall(result=DOResult(False, None, "REMOTE_CAP_REACHED: shard 1 full", "fw-1"), firewall_id="fw-1")
    blocker = ShardedFirewallBlocker([shard0, shard1])

    result = blocker.add_deny_rule("198.51.100.7")

    assert shard0.calls == ["198.51.100.7"]
    assert shard1.calls == ["198.51.100.7"]
    assert result == DOResult(False, None, "REMOTE_CAP_REACHED: shard 1 full", "fw-1")


def test_sharded_blocker_non_cap_failure_stops_immediately():
    shard0_result = DOResult(False, 500, "boom", "fw-0")
    shard0 = FakeFirewall(result=shard0_result, firewall_id="fw-0")
    shard1 = FakeFirewall(firewall_id="fw-1")
    blocker = ShardedFirewallBlocker([shard0, shard1])

    result = blocker.add_deny_rule("198.51.100.7")

    assert shard0.calls == ["198.51.100.7"]
    assert shard1.calls == []
    assert result == shard0_result


def test_sharded_blocker_single_shard_behaves_like_bare_shard():
    shard_result = DOResult(True, 204, None, "fw-0")
    shard = FakeFirewall(result=shard_result, firewall_id="fw-0")
    blocker = ShardedFirewallBlocker([shard])

    result = blocker.add_deny_rule("198.51.100.7")

    assert shard.calls == ["198.51.100.7"]
    assert result == shard_result


def test_fanout_remove_deny_rule_firewall_first_all_succeed():
    firewall = FakeFirewall(remove_result=DOResult(True, 204, None))
    lb1 = FakeLoadBalancer("lb-1", result=DOResult(True, 200, None))
    lb2 = FakeLoadBalancer("lb-2", result=DOResult(True, 200, None))
    blocker = FanoutBlocker(firewall, [lb1, lb2])

    result = blocker.remove_deny_rule("198.51.100.7", firewall_id="fw-1")

    assert firewall.remove_calls == [("198.51.100.7", "fw-1")]
    assert lb1.remove_calls == ["198.51.100.7"]
    assert lb2.remove_calls == ["198.51.100.7"]
    assert result.ok is True


def test_fanout_remove_deny_rule_firewall_failure_zero_lb_calls():
    firewall_result = DOResult(False, 500, "boom")
    firewall = FakeFirewall(remove_result=firewall_result)
    lb1 = FakeLoadBalancer("lb-1")
    lb2 = FakeLoadBalancer("lb-2")
    blocker = FanoutBlocker(firewall, [lb1, lb2])

    result = blocker.remove_deny_rule("198.51.100.7")

    assert firewall.remove_calls == [("198.51.100.7", None)]
    assert lb1.remove_calls == []
    assert lb2.remove_calls == []
    assert result is firewall_result


def test_fanout_remove_deny_rule_first_lb_failure_stops_fanout():
    firewall = FakeFirewall(remove_result=DOResult(True, 204, None))
    lb1_result = DOResult(False, 422, "invalid firewall entry")
    lb1 = FakeLoadBalancer("lb-1", result=lb1_result)
    lb2 = FakeLoadBalancer("lb-2")
    blocker = FanoutBlocker(firewall, [lb1, lb2])

    result = blocker.remove_deny_rule("198.51.100.7")

    assert lb1.remove_calls == ["198.51.100.7"]
    assert lb2.remove_calls == []
    assert result == DOResult(False, 422, "LB lb-1: invalid firewall entry")


def test_sharded_blocker_remove_dispatches_to_correct_shard():
    shard0 = FakeFirewall(firewall_id="fw-0", remove_result=DOResult(True, 200, None, "fw-0"))
    shard1 = FakeFirewall(firewall_id="fw-1", remove_result=DOResult(True, 200, None, "fw-1"))
    blocker = ShardedFirewallBlocker([shard0, shard1])

    result = blocker.remove_deny_rule("198.51.100.7", firewall_id="fw-1")

    assert shard0.remove_calls == []
    assert shard1.remove_calls == [("198.51.100.7", "fw-1")]
    assert result == DOResult(True, 200, None, "fw-1")


def test_sharded_blocker_remove_unknown_firewall_id_no_shard_called():
    shard0 = FakeFirewall(firewall_id="fw-0")
    shard1 = FakeFirewall(firewall_id="fw-1")
    blocker = ShardedFirewallBlocker([shard0, shard1])

    result = blocker.remove_deny_rule("198.51.100.7", firewall_id="fw-unknown")

    assert shard0.remove_calls == []
    assert shard1.remove_calls == []
    assert result.ok is False
    assert result.error.startswith("UNKNOWN_FIREWALL_ID")


def test_sharded_blocker_remove_missing_firewall_id_no_shard_called():
    shard0 = FakeFirewall(firewall_id="fw-0")
    blocker = ShardedFirewallBlocker([shard0])

    result = blocker.remove_deny_rule("198.51.100.7")

    assert shard0.remove_calls == []
    assert result.ok is False
    assert result.error.startswith("UNKNOWN_FIREWALL_ID")
