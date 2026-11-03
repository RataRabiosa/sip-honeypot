import collections
import copy
import json
import socket
import urllib.error
import urllib.request

DOResult = collections.namedtuple("DOResult", "ok http_status error")
UpdatePlan = collections.namedtuple("UpdatePlan", "payload already_present error")


class DOFirewallClient:
    USER_AGENT = "sip-honeypot/1.0 (+https://github.com/0xNslabs/sip-honeypot)"

    # DigitalOcean caps the total addresses across all deny rules of a firewall
    # at 1000, combined across inbound sources and outbound destinations. This
    # is a platform constant, not an operator-tunable value.
    DENY_ADDRESS_LIMIT = 1000

    def __init__(self, token, firewall_id, base_url="https://api.digitalocean.com", timeout=10.0):
        self._token = token
        self._firewall_id = firewall_id
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

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

    def _request(self, method: str, path: str, body: dict = None):
        """Issue one HTTP request and map results/exceptions.

        Returns a (status, response_body_or_None, error_or_None) tuple. On
        success, error is None and response_body is the raw bytes read. On
        failure, status/error follow the same conventions used throughout
        this client for mapping urllib exceptions to DOResult-style errors.
        """
        url = f"{self._base_url}{path}"
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "User-Agent": self.USER_AGENT,
        }
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                status = resp.status
                response_body = resp.read()
                if 200 <= status < 300:
                    return status, response_body, None
                return status, response_body, f"HTTP {status}: unexpected status"
        except urllib.error.HTTPError as e:
            try:
                snippet = e.read(2048).decode("utf-8", errors="replace")
            except Exception:
                snippet = ""
            return e.code, None, f"HTTP {e.code}: {snippet}"
        except (urllib.error.URLError, socket.timeout, TimeoutError, OSError, ValueError) as e:
            return None, None, f"{type(e).__name__}: {e}"

    def add_deny_rule(self, ip: str) -> DOResult:
        get_status, get_body, get_error = self._request("GET", f"/v2/firewalls/{self._firewall_id}")
        if get_error is not None:
            return DOResult(False, get_status, get_error)

        try:
            parsed = json.loads(get_body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return DOResult(False, get_status, "MALFORMED_FIREWALL_RESPONSE: body is not valid JSON")

        firewall = parsed.get("firewall") if isinstance(parsed, dict) else None
        if not isinstance(firewall, dict):
            return DOResult(False, get_status, "MALFORMED_FIREWALL_RESPONSE: missing 'firewall' object")

        plan = self.plan_update(firewall, ip)
        if plan.already_present:
            return DOResult(True, get_status, None)
        if plan.error is not None:
            if plan.error.startswith("MALFORMED_FIREWALL_RESPONSE"):
                return DOResult(False, get_status, plan.error)
            return DOResult(False, None, plan.error)

        put_status, _put_body, put_error = self._request("PUT", f"/v2/firewalls/{self._firewall_id}", body=plan.payload)
        if put_error is not None:
            return DOResult(False, put_status, put_error)
        return DOResult(True, put_status, None)
