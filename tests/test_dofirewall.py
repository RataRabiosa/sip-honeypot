import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from metrics.dofirewall import DOFirewallClient

TOKEN = "super-secret-do-token-12345"


class _RecordingHandler(BaseHTTPRequestHandler):
    response_code = 204
    response_body = b""

    def log_message(self, fmt, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.server.last_request = {
            "path": self.path,
            "headers": dict(self.headers.items()),
            "body": json.loads(body.decode("utf-8")) if body else None,
        }
        self.send_response(self.response_code)
        if self.response_body:
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(self.response_body)))
            self.end_headers()
            self.wfile.write(self.response_body)
        else:
            self.end_headers()


def _make_server(response_code=204, response_body=b""):
    handler_cls = type(
        "Handler",
        (_RecordingHandler,),
        {"response_code": response_code, "response_body": response_body},
    )
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    server.last_request = None
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_add_deny_rule_posts_correct_request_and_succeeds_on_204():
    server, thread = _make_server(response_code=204)
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOFirewallClient(TOKEN, "fw-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_rule("198.51.100.7")

        assert result.ok is True
        assert result.http_status == 204
        assert result.error is None

        req = server.last_request
        assert req["path"] == "/v2/firewalls/fw-123/rules"
        assert req["headers"]["Authorization"] == f"Bearer {TOKEN}"
        assert req["body"] == {
            "inbound_rules": [
                {
                    "protocol": "all",
                    "ports": "0",
                    "action": "deny",
                    "sources": {"addresses": ["198.51.100.7"]},
                }
            ]
        }
        assert TOKEN not in (result.error or "")
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_add_deny_rule_handles_401_with_json_body():
    error_body = json.dumps({"id": "unauthorized", "message": "Unable to authenticate you."}).encode("utf-8")
    server, thread = _make_server(response_code=401, response_body=error_body)
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOFirewallClient(TOKEN, "fw-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_rule("198.51.100.7")

        assert result.ok is False
        assert result.http_status == 401
        assert "Unable to authenticate you" in (result.error or "")
        assert TOKEN not in (result.error or "")
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_add_deny_rule_handles_connection_failure():
    # Bind a socket to find a free port, then close it so nothing is listening there.
    probe = HTTPServer(("127.0.0.1", 0), _RecordingHandler)
    closed_port = probe.server_port
    probe.server_close()

    client = DOFirewallClient(TOKEN, "fw-123", base_url=f"http://127.0.0.1:{closed_port}", timeout=2.0)
    result = client.add_deny_rule("198.51.100.7")

    assert result.ok is False
    assert result.http_status is None
    assert TOKEN not in (result.error or "")
