import collections
import json
import socket
import urllib.error
import urllib.request

DOResult = collections.namedtuple("DOResult", "ok http_status error firewall_id", defaults=(None,))
USER_AGENT = "sip-honeypot/1.0 (+https://github.com/0xNslabs/sip-honeypot)"


def request(base_url: str, token: str, timeout: float, method: str, path: str, body: dict = None):
    """Issue one HTTP request against the DigitalOcean API and map results/exceptions.

    Returns a (status, response_body_or_None, error_or_None) tuple. On
    success, error is None and response_body is the raw bytes read. On
    failure, status/error follow the same conventions used throughout the
    DigitalOcean clients for mapping urllib exceptions to DOResult-style
    errors.
    """
    url = f"{base_url}{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
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


def parse_object(body: bytes, key: str, malformed_prefix: str):
    """Parse a JSON response body and require parsed[key] to be a dict.

    Returns (obj, None) on success. Returns
    (None, f"{malformed_prefix}: body is not valid JSON") on a JSON/decode
    error. Returns (None, f"{malformed_prefix}: missing '{key}' object") if
    parsed is not a dict or parsed[key] is not a dict.
    """
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None, f"{malformed_prefix}: body is not valid JSON"

    obj = parsed.get(key) if isinstance(parsed, dict) else None
    if not isinstance(obj, dict):
        return None, f"{malformed_prefix}: missing '{key}' object"
    return obj, None
