from metrics.doapi import DOResult
from metrics.doblock import FanoutBlocker


class FakeFirewall:
    def __init__(self, result=None):
        self.calls = []
        self._result = result or DOResult(True, 204, None)

    def add_deny_rule(self, ip):
        self.calls.append(ip)
        return self._result


class FakeLoadBalancer:
    def __init__(self, lb_id, result=None):
        self.lb_id = lb_id
        self.calls = []
        self._result = result or DOResult(True, 200, None)

    def add_deny_rule(self, ip):
        self.calls.append(ip)
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
