import collections
import copy
import ipaddress
from typing import Optional, Tuple

from metrics.doapi import USER_AGENT, DOResult
from metrics.doapi import parse_object
from metrics.doapi import request as _do_request

LBUpdatePlan = collections.namedtuple("LBUpdatePlan", "payload added error")


class DOLoadBalancerClient:
    USER_AGENT = USER_AGENT
    READ_ONLY_FIELDS = ("id", "ip", "ipv6", "status", "created_at")
    MALFORMED = "MALFORMED_LOAD_BALANCER_RESPONSE"

    def __init__(self, token, lb_id, base_url="https://api.digitalocean.com", timeout=10.0):
        self._token = token
        self.lb_id = lb_id
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    @staticmethod
    def deny_entry(address: str) -> str:
        """Return the DigitalOcean load balancer deny-list entry for an address.

        Validates `address` with ipaddress.ip_network(address, strict=False);
        a ValueError propagates to the caller. The address string is used
        verbatim (no normalization).
        """
        ipaddress.ip_network(address, strict=False)
        if "/" in address:
            return f"cidr:{address}"
        return f"ip:{address}"

    @staticmethod
    def plan_update(load_balancer: dict, addresses) -> "LBUpdatePlan":
        if not isinstance(load_balancer, dict):
            return LBUpdatePlan(None, (), "MALFORMED_LOAD_BALANCER_RESPONSE: load balancer is not an object")

        name = load_balancer.get("name")
        if not isinstance(name, str) or not name:
            return LBUpdatePlan(None, (), "MALFORMED_LOAD_BALANCER_RESPONSE: missing or invalid 'name'")

        if not isinstance(load_balancer.get("forwarding_rules"), list):
            return LBUpdatePlan(None, (), "MALFORMED_LOAD_BALANCER_RESPONSE: missing or invalid 'forwarding_rules'")

        region = load_balancer.get("region")
        if isinstance(region, dict):
            slug = region.get("slug")
            if not isinstance(slug, str) or not slug:
                return LBUpdatePlan(None, (), "MALFORMED_LOAD_BALANCER_RESPONSE: missing or invalid 'region'")
        elif isinstance(region, str) and region:
            slug = region
        else:
            return LBUpdatePlan(None, (), "MALFORMED_LOAD_BALANCER_RESPONSE: missing or invalid 'region'")

        firewall = load_balancer.get("firewall")
        if firewall is None:
            firewall = {}
        if not isinstance(firewall, dict):
            return LBUpdatePlan(None, (), "MALFORMED_LOAD_BALANCER_RESPONSE: invalid 'firewall' shape")

        deny = firewall.get("deny")
        if deny is None:
            deny = []
        if not isinstance(deny, list) or any(not isinstance(entry, str) for entry in deny):
            return LBUpdatePlan(None, (), "MALFORMED_LOAD_BALANCER_RESPONSE: invalid 'firewall.deny' shape")

        allow = firewall.get("allow")
        if allow is None:
            allow = []
        if not isinstance(allow, list) or any(not isinstance(entry, str) for entry in allow):
            return LBUpdatePlan(None, (), "MALFORMED_LOAD_BALANCER_RESPONSE: invalid 'firewall.allow' shape")

        added = []
        for address in addresses:
            try:
                entry = DOLoadBalancerClient.deny_entry(address)
            except (ValueError, TypeError):
                return LBUpdatePlan(None, (), f"INVALID_ADDRESS: {address!r}")
            if entry in deny or entry in added:
                continue
            added.append(entry)

        if not added:
            return LBUpdatePlan(None, (), None)

        payload = copy.deepcopy(load_balancer)
        for field in DOLoadBalancerClient.READ_ONLY_FIELDS:
            payload.pop(field, None)
        payload["region"] = slug

        if isinstance(payload.get("tag"), str) and payload.get("tag"):
            payload.pop("droplet_ids", None)
        else:
            payload.pop("tag", None)
            payload["droplet_ids"] = list(load_balancer.get("droplet_ids") or [])

        payload["firewall"] = {"deny": list(deny) + list(added), "allow": list(allow)}

        return LBUpdatePlan(payload, tuple(added), None)

    def _request(self, method: str, path: str, body: dict = None):
        return _do_request(self._base_url, self._token, self._timeout, method, path, body)

    def fetch(self) -> Tuple[DOResult, Optional[dict]]:
        get_status, get_body, get_error = self._request("GET", f"/v2/load_balancers/{self.lb_id}")
        if get_error is not None:
            return DOResult(False, get_status, get_error), None

        load_balancer, parse_error = parse_object(get_body, "load_balancer", self.MALFORMED)
        if parse_error is not None:
            return DOResult(False, get_status, parse_error), None
        return DOResult(True, get_status, None), load_balancer

    def update(self, payload: dict) -> DOResult:
        put_status, _put_body, put_error = self._request("PUT", f"/v2/load_balancers/{self.lb_id}", body=payload)
        if put_error is not None:
            return DOResult(False, put_status, put_error)
        return DOResult(True, put_status, None)

    def add_deny_entries(self, addresses) -> DOResult:
        res, load_balancer = self.fetch()
        if not res.ok:
            return res

        plan = self.plan_update(load_balancer, addresses)
        if plan.error is not None:
            if plan.error.startswith("MALFORMED_LOAD_BALANCER_RESPONSE"):
                return DOResult(False, res.http_status, plan.error)
            return DOResult(False, None, plan.error)
        if not plan.added:
            return DOResult(True, res.http_status, None)

        return self.update(plan.payload)

    def add_deny_rule(self, ip: str) -> DOResult:
        return self.add_deny_entries([ip])
