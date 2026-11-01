import collections
import json
import socket
import urllib.error
import urllib.request

DOResult = collections.namedtuple("DOResult", "ok http_status error")


class DOFirewallClient:
    USER_AGENT = "sip-honeypot/1.0 (+https://github.com/0xNslabs/sip-honeypot)"

    def __init__(self, token, firewall_id, base_url="https://api.digitalocean.com", timeout=10.0):
        self._token = token
        self._firewall_id = firewall_id
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    @staticmethod
    def build_payload(ip: str) -> dict:
        return {
            "inbound_rules": [
                {
                    "protocol": "all",
                    "ports": "0",
                    "action": "deny",
                    "sources": {"addresses": [ip]},
                }
            ]
        }

    def add_deny_rule(self, ip: str) -> DOResult:
        url = f"{self._base_url}/v2/firewalls/{self._firewall_id}/rules"
        body = json.dumps(self.build_payload(ip)).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": self.USER_AGENT,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                status = resp.status
                if 200 <= status < 300:
                    return DOResult(True, status, None)
                return DOResult(False, status, f"HTTP {status}: unexpected status")
        except urllib.error.HTTPError as e:
            try:
                snippet = e.read(2048).decode("utf-8", errors="replace")
            except Exception:
                snippet = ""
            return DOResult(False, e.code, f"HTTP {e.code}: {snippet}")
        except (urllib.error.URLError, socket.timeout, TimeoutError, OSError, ValueError) as e:
            return DOResult(False, None, f"{type(e).__name__}: {e}")
