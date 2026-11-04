from metrics.doapi import DOResult


class FanoutBlocker:
    """Duck-type compatible with DOFirewallClient for the worker.

    Exposes add_deny_rule(ip) -> DOResult. No logging, no state beyond its
    constructor args.
    """

    def __init__(self, firewall, load_balancers):
        """
        firewall: object with add_deny_rule(ip) -> DOResult (a DOFirewallClient).
        load_balancers: a sequence of objects with .lb_id and
        add_deny_rule(ip) -> DOResult (DOLoadBalancerClient instances),
        called in the given sequence order.
        """
        self._firewall = firewall
        self._load_balancers = load_balancers

    def add_deny_rule(self, ip: str) -> DOResult:
        res = self._firewall.add_deny_rule(ip)
        if not res.ok:
            return res
        for lb in self._load_balancers:
            lb_res = lb.add_deny_rule(ip)
            if not lb_res.ok:
                return DOResult(False, lb_res.http_status, f"LB {lb.lb_id}: {lb_res.error}")
        return res
