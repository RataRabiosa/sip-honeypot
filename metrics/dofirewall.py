import collections
import copy
from typing import List, Optional, Tuple

from metrics.doapi import USER_AGENT, DOResult
from metrics.doapi import parse_object
from metrics.doapi import request as _do_request

UpdatePlan = collections.namedtuple("UpdatePlan", "payload already_present error")
RemovePlan = collections.namedtuple("RemovePlan", "payload already_absent error")


class DOFirewallClient:
    USER_AGENT = USER_AGENT

    # DigitalOcean caps the total addresses across all deny rules of a firewall
    # at 1000, combined across inbound sources and outbound destinations. This
    # is a platform constant, not an operator-tunable value.
    DENY_ADDRESS_LIMIT = 1000

    def __init__(self, token, firewall_id, base_url="https://api.digitalocean.com", timeout=10.0):
        self._token = token
        self._firewall_id = firewall_id
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    @property
    def firewall_id(self) -> str:
        return self._firewall_id

    @staticmethod
    def is_managed_rule(rule: dict) -> bool:
        if not isinstance(rule, dict):
            return False
        if rule.get("protocol") != "all":
            return False
        if rule.get("action") != "deny":
            return False
        return rule.get("ports") in ("0", "all", "")

    @staticmethod
    def build_managed_rule(ip: str) -> dict:
        return {
            "protocol": "all",
            "ports": "0",
            "action": "deny",
            "sources": {"addresses": [ip]},
        }

    @staticmethod
    def _address_container_count(rule: dict, key: str) -> int:
        """Count addresses in a managed rule's 'sources'/'destinations' container.

        Defensive against any malformed nested shape: a non-dict container
        is treated as empty, and a non-list 'addresses' is treated as empty.
        Never raises on a dict `rule`.
        """
        container = rule.get(key)
        if not isinstance(container, dict):
            container = {}
        addresses = container.get("addresses")
        if not isinstance(addresses, list):
            addresses = []
        return len(addresses)

    @staticmethod
    def _managed_rule_shape_error(rule: dict, key: str) -> bool:
        """Return True if a managed rule's 'sources'/'destinations' shape is malformed.

        A container that is entirely absent, or present as a dict without an
        'addresses' key, is a normal/empty shape (e.g. a freshly created
        rule) and is not an error. A container that is present but not a
        dict, or an 'addresses' entry that is present but not a list, is a
        genuinely malformed shape.
        """
        if key not in rule:
            return False
        container = rule.get(key)
        if not isinstance(container, dict):
            return True
        return "addresses" in container and not isinstance(container["addresses"], list)

    @staticmethod
    def count_deny_addresses(firewall: dict) -> int:
        total = 0
        for rule in firewall.get("inbound_rules") or []:
            if not DOFirewallClient.is_managed_rule(rule):
                continue
            total += DOFirewallClient._address_container_count(rule, "sources")
        for rule in firewall.get("outbound_rules") or []:
            if not DOFirewallClient.is_managed_rule(rule):
                continue
            total += DOFirewallClient._address_container_count(rule, "destinations")
        return total

    @staticmethod
    def managed_deny_addresses(firewall: dict) -> List[str]:
        """Collect every address across all managed inbound deny rules.

        There can be more than one managed rule (e.g. legacy per-IP rules
        predating the single-managed-rule behavior). Addresses are
        de-duplicated, preserving first-encounter order. This is a read
        helper for the backfill script, not a validator: it is defensive
        against malformed nested shapes (skips them) rather than raising,
        and never raises on a dict `firewall`.
        """
        addresses: List[str] = []
        seen = set()
        if not isinstance(firewall, dict):
            return addresses
        inbound_rules = firewall.get("inbound_rules")
        if not isinstance(inbound_rules, list):
            return addresses
        for rule in inbound_rules:
            if not DOFirewallClient.is_managed_rule(rule):
                continue
            sources = rule.get("sources") if isinstance(rule, dict) else None
            if not isinstance(sources, dict):
                continue
            rule_addresses = sources.get("addresses")
            if not isinstance(rule_addresses, list):
                continue
            for addr in rule_addresses:
                if not isinstance(addr, str):
                    continue
                if addr in seen:
                    continue
                seen.add(addr)
                addresses.append(addr)
        return addresses

    @staticmethod
    def plan_update(firewall: dict, ip: str) -> "UpdatePlan":
        if not isinstance(firewall, dict):
            return UpdatePlan(None, False, "MALFORMED_FIREWALL_RESPONSE: firewall is not an object")
        name = firewall.get("name")
        if not isinstance(name, str) or not name:
            return UpdatePlan(None, False, "MALFORMED_FIREWALL_RESPONSE: missing or invalid 'name'")
        if not isinstance(firewall.get("inbound_rules"), list):
            return UpdatePlan(None, False, "MALFORMED_FIREWALL_RESPONSE: missing or invalid 'inbound_rules'")
        if not isinstance(firewall.get("outbound_rules"), list):
            return UpdatePlan(None, False, "MALFORMED_FIREWALL_RESPONSE: missing or invalid 'outbound_rules'")

        for rule in firewall["inbound_rules"]:
            if not DOFirewallClient.is_managed_rule(rule):
                continue
            if DOFirewallClient._managed_rule_shape_error(rule, "sources"):
                return UpdatePlan(
                    None,
                    False,
                    "MALFORMED_FIREWALL_RESPONSE: invalid 'sources' shape in managed inbound rule",
                )
        for rule in firewall["outbound_rules"]:
            if not DOFirewallClient.is_managed_rule(rule):
                continue
            if DOFirewallClient._managed_rule_shape_error(rule, "destinations"):
                return UpdatePlan(
                    None,
                    False,
                    "MALFORMED_FIREWALL_RESPONSE: invalid 'destinations' shape in managed outbound rule",
                )

        for rule in firewall["inbound_rules"]:
            if not DOFirewallClient.is_managed_rule(rule):
                continue
            addresses = rule.get("sources", {}).get("addresses", []) or []
            if ip in addresses:
                return UpdatePlan(None, True, None)

        existing_total = DOFirewallClient.count_deny_addresses(firewall)
        if existing_total >= DOFirewallClient.DENY_ADDRESS_LIMIT:
            return UpdatePlan(
                None,
                False,
                f"REMOTE_CAP_REACHED: firewall has {existing_total} deny addresses "
                f"(limit {DOFirewallClient.DENY_ADDRESS_LIMIT})",
            )

        new_inbound_rules = copy.deepcopy(firewall["inbound_rules"])
        appended = False
        for rule in new_inbound_rules:
            if not DOFirewallClient.is_managed_rule(rule):
                continue
            sources = rule.setdefault("sources", {})
            addresses = sources.setdefault("addresses", [])
            addresses.append(ip)
            appended = True
            break
        if not appended:
            new_inbound_rules.append(DOFirewallClient.build_managed_rule(ip))

        payload = {
            "name": firewall["name"],
            "droplet_ids": firewall.get("droplet_ids") or [],
            "tags": firewall.get("tags") or [],
            "inbound_rules": new_inbound_rules,
            "outbound_rules": firewall.get("outbound_rules") or [],
        }
        return UpdatePlan(payload, False, None)

    @staticmethod
    def plan_removal(firewall: dict, ip: str) -> "RemovePlan":
        if not isinstance(firewall, dict):
            return RemovePlan(None, False, "MALFORMED_FIREWALL_RESPONSE: firewall is not an object")
        name = firewall.get("name")
        if not isinstance(name, str) or not name:
            return RemovePlan(None, False, "MALFORMED_FIREWALL_RESPONSE: missing or invalid 'name'")
        if not isinstance(firewall.get("inbound_rules"), list):
            return RemovePlan(None, False, "MALFORMED_FIREWALL_RESPONSE: missing or invalid 'inbound_rules'")
        if not isinstance(firewall.get("outbound_rules"), list):
            return RemovePlan(None, False, "MALFORMED_FIREWALL_RESPONSE: missing or invalid 'outbound_rules'")

        for rule in firewall["inbound_rules"]:
            if not DOFirewallClient.is_managed_rule(rule):
                continue
            if DOFirewallClient._managed_rule_shape_error(rule, "sources"):
                return RemovePlan(
                    None, False, "MALFORMED_FIREWALL_RESPONSE: invalid 'sources' shape in managed inbound rule"
                )
        for rule in firewall["outbound_rules"]:
            if not DOFirewallClient.is_managed_rule(rule):
                continue
            if DOFirewallClient._managed_rule_shape_error(rule, "destinations"):
                return RemovePlan(
                    None, False, "MALFORMED_FIREWALL_RESPONSE: invalid 'destinations' shape in managed outbound rule"
                )

        new_inbound_rules = copy.deepcopy(firewall["inbound_rules"])
        removed = False
        for rule in new_inbound_rules:
            if not DOFirewallClient.is_managed_rule(rule):
                continue
            sources = rule.get("sources")
            if not isinstance(sources, dict):
                continue
            addresses = sources.get("addresses")
            if not isinstance(addresses, list):
                continue
            if ip in addresses:
                addresses[:] = [a for a in addresses if a != ip]
                removed = True

        if not removed:
            return RemovePlan(None, True, None)

        payload = {
            "name": firewall["name"],
            "droplet_ids": firewall.get("droplet_ids") or [],
            "tags": firewall.get("tags") or [],
            "inbound_rules": new_inbound_rules,
            "outbound_rules": firewall.get("outbound_rules") or [],
        }
        return RemovePlan(payload, False, None)

    def _request(self, method: str, path: str, body: dict = None):
        """Issue one HTTP request and map results/exceptions.

        Returns a (status, response_body_or_None, error_or_None) tuple. On
        success, error is None and response_body is the raw bytes read. On
        failure, status/error follow the same conventions used throughout
        this client for mapping urllib exceptions to DOResult-style errors.
        """
        return _do_request(self._base_url, self._token, self._timeout, method, path, body)

    def fetch(self) -> Tuple[DOResult, Optional[dict]]:
        """GET the firewall and return (DOResult, firewall_dict_or_None)."""
        get_status, get_body, get_error = self._request("GET", f"/v2/firewalls/{self._firewall_id}")
        if get_error is not None:
            return DOResult(False, get_status, get_error, self._firewall_id), None

        firewall, parse_error = parse_object(get_body, "firewall", "MALFORMED_FIREWALL_RESPONSE")
        if parse_error is not None:
            return DOResult(False, get_status, parse_error, self._firewall_id), None
        return DOResult(True, get_status, None, self._firewall_id), firewall

    def add_deny_rule(self, ip: str) -> DOResult:
        res, firewall = self.fetch()
        if not res.ok:
            return res

        plan = self.plan_update(firewall, ip)
        if plan.already_present:
            return DOResult(True, res.http_status, None, self._firewall_id)
        if plan.error is not None:
            if plan.error.startswith("MALFORMED_FIREWALL_RESPONSE"):
                return DOResult(False, res.http_status, plan.error, self._firewall_id)
            return DOResult(False, None, plan.error, self._firewall_id)

        put_status, _put_body, put_error = self._request("PUT", f"/v2/firewalls/{self._firewall_id}", body=plan.payload)
        if put_error is not None:
            return DOResult(False, put_status, put_error, self._firewall_id)
        return DOResult(True, put_status, None, self._firewall_id)

    def remove_deny_rule(self, ip: str, firewall_id: str = None) -> DOResult:
        if firewall_id is not None and firewall_id != self._firewall_id:
            return DOResult(
                False,
                None,
                f"FIREWALL_ID_MISMATCH: expected {self._firewall_id!r}, got {firewall_id!r}",
                self._firewall_id,
            )

        res, firewall = self.fetch()
        if not res.ok:
            return res

        plan = self.plan_removal(firewall, ip)
        if plan.already_absent:
            return DOResult(True, res.http_status, None, self._firewall_id)
        if plan.error is not None:
            if plan.error.startswith("MALFORMED_FIREWALL_RESPONSE"):
                return DOResult(False, res.http_status, plan.error, self._firewall_id)
            return DOResult(False, None, plan.error, self._firewall_id)

        put_status, _put_body, put_error = self._request("PUT", f"/v2/firewalls/{self._firewall_id}", body=plan.payload)
        if put_error is not None:
            return DOResult(False, put_status, put_error, self._firewall_id)
        return DOResult(True, put_status, None, self._firewall_id)
