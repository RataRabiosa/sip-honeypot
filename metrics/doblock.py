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


class ShardedFirewallBlocker:
    """Duck-type compatible with DOFirewallClient for the worker.

    Wraps an ordered list of DOFirewallClient "shards". Every call starts
    probing from shard 0 — no "active shard index" is remembered, since a
    full shard stays full, so re-probing it costs one cheap GET before
    moving on. Only a REMOTE_CAP_REACHED error advances to the next shard;
    any other failure (network, malformed response, non-cap HTTP error) is
    returned immediately without trying further shards.
    """

    def __init__(self, shards):
        self._shards = list(shards)

    def add_deny_rule(self, ip: str) -> DOResult:
        result = None
        for shard in self._shards:
            result = shard.add_deny_rule(ip)
            if result.ok:
                return result
            if result.error and result.error.startswith("REMOTE_CAP_REACHED"):
                continue
            return result
        return result
