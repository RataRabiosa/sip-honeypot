import copy
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from metrics.dofirewall import DOFirewallClient

TOKEN = "super-secret-do-token-12345"


class _RecordingHandler(BaseHTTPRequestHandler):
    get_response_code = 200
    get_response_body = b""
    put_response_code = 200
    put_response_body = b""

    def log_message(self, fmt, *args):
        pass

    def _record(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        self.server.requests.append(
            {
                "method": self.command,
                "path": self.path,
                "headers": dict(self.headers.items()),
                "body": json.loads(body.decode("utf-8")) if body else None,
            }
        )

    def _respond(self, code, body):
        self.send_response(code)
        if body:
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.end_headers()

    def do_GET(self):
        self._record()
        self._respond(self.get_response_code, self.get_response_body)

    def do_PUT(self):
        self._record()
        self._respond(self.put_response_code, self.put_response_body)


def _make_server(get_response_code=200, get_response_body=b"", put_response_code=200, put_response_body=b""):
    handler_cls = type(
        "Handler",
        (_RecordingHandler,),
        {
            "get_response_code": get_response_code,
            "get_response_body": get_response_body,
            "put_response_code": put_response_code,
            "put_response_body": put_response_body,
        },
    )
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    server.requests = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _firewall_body(inbound_rules, outbound_rules=None):
    return {
        "firewall": {
            "id": "fw-123",
            "name": "hp-fw",
            "status": "succeeded",
            "created_at": "2024-01-01T00:00:00Z",
            "pending_changes": [],
            "droplet_ids": [111],
            "tags": ["honeypot"],
            "inbound_rules": inbound_rules,
            "outbound_rules": outbound_rules if outbound_rules is not None else [],
        }
    }


def _json_bytes(obj):
    return json.dumps(obj).encode("utf-8")


def _malformed_shape_firewall(**overrides):
    firewall = {
        "id": "fw-123",
        "name": "hp-fw",
        "status": "succeeded",
        "created_at": "2024-01-01T00:00:00Z",
        "pending_changes": [],
        "droplet_ids": [111],
        "tags": ["honeypot"],
        "inbound_rules": [],
        "outbound_rules": [],
    }
    firewall.update(overrides)
    return firewall


def test_add_deny_rule_create_path_no_existing_managed_rule():
    unrelated_rule = {
        "protocol": "tcp",
        "ports": "22",
        "action": "allow",
        "sources": {"addresses": ["203.0.113.0/24"], "tags": ["admin"]},
    }
    get_body = _firewall_body([unrelated_rule])
    server, thread = _make_server(
        get_response_code=200,
        get_response_body=_json_bytes(get_body),
        put_response_code=200,
        put_response_body=b"",
    )
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOFirewallClient(TOKEN, "fw-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_rule("198.51.100.7")

        assert len(server.requests) == 2
        get_req, put_req = server.requests
        assert get_req["method"] == "GET"
        assert get_req["path"] == "/v2/firewalls/fw-123"
        assert put_req["method"] == "PUT"
        assert put_req["path"] == "/v2/firewalls/fw-123"

        put_body = put_req["body"]
        assert set(put_body.keys()) == {"name", "droplet_ids", "tags", "inbound_rules", "outbound_rules"}
        assert put_body["name"] == "hp-fw"
        assert put_body["droplet_ids"] == [111]
        assert put_body["tags"] == ["honeypot"]
        assert put_body["outbound_rules"] == []
        assert len(put_body["inbound_rules"]) == 2
        assert put_body["inbound_rules"][0] == unrelated_rule
        assert put_body["inbound_rules"][1] == {
            "protocol": "all",
            "ports": "0",
            "action": "deny",
            "sources": {"addresses": ["198.51.100.7"]},
        }

        assert result.ok is True
        assert result.http_status == 200
        assert result.error is None

        assert get_req["headers"]["Authorization"] == f"Bearer {TOKEN}"
        assert put_req["headers"]["Authorization"] == f"Bearer {TOKEN}"
        assert TOKEN not in (result.error or "")
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_add_deny_rule_append_path_existing_managed_rule_with_extra_source_keys():
    managed_rule = {
        "protocol": "all",
        "ports": "0",
        "action": "deny",
        "sources": {
            "addresses": ["198.51.100.1", "198.51.100.2"],
            "tags": ["t1"],
            "droplet_ids": [222],
        },
    }
    get_body = _firewall_body([managed_rule])
    server, thread = _make_server(
        get_response_code=200,
        get_response_body=_json_bytes(get_body),
        put_response_code=200,
        put_response_body=b"",
    )
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOFirewallClient(TOKEN, "fw-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_rule("198.51.100.9")

        assert len(server.requests) == 2
        put_body = server.requests[1]["body"]
        assert len(put_body["inbound_rules"]) == 1
        rule = put_body["inbound_rules"][0]
        assert rule["sources"]["addresses"] == ["198.51.100.1", "198.51.100.2", "198.51.100.9"]
        assert rule["sources"]["tags"] == ["t1"]
        assert rule["sources"]["droplet_ids"] == [222]

        assert result.ok is True
        assert result.http_status == 200
        assert result.error is None
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_add_deny_rule_only_first_matching_rule_is_appended_to():
    rule_a = {"protocol": "all", "ports": "0", "action": "deny", "sources": {"addresses": ["198.51.100.1"]}}
    rule_b = {"protocol": "all", "ports": "0", "action": "deny", "sources": {"addresses": ["198.51.100.2"]}}
    rule_c = {"protocol": "all", "ports": "0", "action": "deny", "sources": {"addresses": ["198.51.100.3"]}}
    get_body = _firewall_body([rule_a, rule_b, rule_c])
    server, thread = _make_server(
        get_response_code=200,
        get_response_body=_json_bytes(get_body),
        put_response_code=200,
        put_response_body=b"",
    )
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOFirewallClient(TOKEN, "fw-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_rule("198.51.100.99")

        put_body = server.requests[1]["body"]
        assert len(put_body["inbound_rules"]) == 3
        assert put_body["inbound_rules"][0]["sources"]["addresses"] == ["198.51.100.1", "198.51.100.99"]
        assert put_body["inbound_rules"][1] == rule_b
        assert put_body["inbound_rules"][2] == rule_c
        assert result.ok is True
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_add_deny_rule_ports_normalization_all():
    managed_rule = {"protocol": "all", "ports": "all", "action": "deny", "sources": {"addresses": ["198.51.100.1"]}}
    get_body = _firewall_body([managed_rule])
    server, thread = _make_server(
        get_response_code=200,
        get_response_body=_json_bytes(get_body),
        put_response_code=200,
        put_response_body=b"",
    )
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOFirewallClient(TOKEN, "fw-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_rule("198.51.100.2")

        put_body = server.requests[1]["body"]
        assert len(put_body["inbound_rules"]) == 1
        assert put_body["inbound_rules"][0]["sources"]["addresses"] == ["198.51.100.1", "198.51.100.2"]
        assert result.ok is True
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_add_deny_rule_ports_normalization_empty_string():
    managed_rule = {"protocol": "all", "ports": "", "action": "deny", "sources": {"addresses": ["198.51.100.1"]}}
    get_body = _firewall_body([managed_rule])
    server, thread = _make_server(
        get_response_code=200,
        get_response_body=_json_bytes(get_body),
        put_response_code=200,
        put_response_body=b"",
    )
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOFirewallClient(TOKEN, "fw-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_rule("198.51.100.2")

        put_body = server.requests[1]["body"]
        assert len(put_body["inbound_rules"]) == 1
        assert put_body["inbound_rules"][0]["sources"]["addresses"] == ["198.51.100.1", "198.51.100.2"]
        assert result.ok is True
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_add_deny_rule_idempotent_ip_already_present():
    rule_a = {"protocol": "all", "ports": "0", "action": "deny", "sources": {"addresses": ["198.51.100.1"]}}
    rule_b = {
        "protocol": "all",
        "ports": "0",
        "action": "deny",
        "sources": {"addresses": ["198.51.100.2", "198.51.100.9"]},
    }
    get_body = _firewall_body([rule_a, rule_b])
    server, thread = _make_server(
        get_response_code=200,
        get_response_body=_json_bytes(get_body),
    )
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOFirewallClient(TOKEN, "fw-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_rule("198.51.100.9")

        assert len(server.requests) == 1
        assert server.requests[0]["method"] == "GET"
        assert result.ok is True
        assert result.http_status == 200
        assert result.error is None
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_add_deny_rule_remote_cap_reached():
    inbound_addresses = [f"10.0.{i // 256}.{i % 256}" for i in range(999)]
    inbound_rule = {"protocol": "all", "ports": "0", "action": "deny", "sources": {"addresses": inbound_addresses}}
    outbound_rule = {
        "protocol": "all",
        "ports": "0",
        "action": "deny",
        "destinations": {"addresses": ["10.255.255.255"]},
    }
    get_body = _firewall_body([inbound_rule], outbound_rules=[outbound_rule])
    # Sanity check the fixture actually totals exactly the limit.
    assert DOFirewallClient.count_deny_addresses(get_body["firewall"]) == 1000

    server, thread = _make_server(
        get_response_code=200,
        get_response_body=_json_bytes(get_body),
    )
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOFirewallClient(TOKEN, "fw-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_rule("192.0.2.1")

        assert len(server.requests) == 1
        assert result.ok is False
        assert result.http_status is None
        assert result.error.startswith("REMOTE_CAP_REACHED")
        assert TOKEN not in (result.error or "")
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_add_deny_rule_remote_cap_allowed_at_boundary():
    inbound_addresses = [f"10.0.{i // 256}.{i % 256}" for i in range(998)]
    inbound_rule = {"protocol": "all", "ports": "0", "action": "deny", "sources": {"addresses": inbound_addresses}}
    outbound_rule = {
        "protocol": "all",
        "ports": "0",
        "action": "deny",
        "destinations": {"addresses": ["10.255.255.255"]},
    }
    get_body = _firewall_body([inbound_rule], outbound_rules=[outbound_rule])
    # Sanity check the fixture actually totals one below the limit.
    assert DOFirewallClient.count_deny_addresses(get_body["firewall"]) == 999

    server, thread = _make_server(
        get_response_code=200,
        get_response_body=_json_bytes(get_body),
        put_response_code=200,
        put_response_body=b"",
    )
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOFirewallClient(TOKEN, "fw-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_rule("192.0.2.1")

        assert len(server.requests) == 2
        put_req = server.requests[1]
        assert put_req["method"] == "PUT"
        put_body = put_req["body"]
        assert DOFirewallClient.count_deny_addresses(put_body) == 1000

        assert result.ok is True
        assert result.http_status == 200
        assert result.error is None
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_add_deny_rule_handles_get_401_with_json_body():
    error_body = _json_bytes({"id": "unauthorized", "message": "Unable to authenticate you."})
    server, thread = _make_server(get_response_code=401, get_response_body=error_body)
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOFirewallClient(TOKEN, "fw-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_rule("198.51.100.7")

        assert result.ok is False
        assert result.http_status == 401
        assert "Unable to authenticate you" in (result.error or "")
        assert TOKEN not in (result.error or "")
        assert len(server.requests) == 1
        assert server.requests[0]["method"] == "GET"
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.parametrize(
    "get_body",
    [b"not json", _json_bytes({"nope": 1})],
    ids=["not-json", "missing-firewall-key"],
)
def test_add_deny_rule_handles_malformed_get_body(get_body):
    server, thread = _make_server(get_response_code=200, get_response_body=get_body)
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOFirewallClient(TOKEN, "fw-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_rule("198.51.100.7")

        assert result.ok is False
        assert (result.error or "").startswith("MALFORMED_FIREWALL_RESPONSE")
        assert TOKEN not in (result.error or "")
        assert len(server.requests) == 1
        assert server.requests[0]["method"] == "GET"
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.parametrize(
    "firewall",
    [
        _malformed_shape_firewall(name=""),
        _malformed_shape_firewall(name=None),
        _malformed_shape_firewall(inbound_rules=None),
        _malformed_shape_firewall(outbound_rules=None),
    ],
    ids=["empty-name", "invalid-name", "null-inbound-rules", "null-outbound-rules"],
)
def test_add_deny_rule_handles_malformed_firewall_shape(firewall):
    get_body = {"firewall": firewall}
    server, thread = _make_server(get_response_code=200, get_response_body=_json_bytes(get_body))
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOFirewallClient(TOKEN, "fw-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_rule("198.51.100.7")

        assert result.ok is False
        assert (result.error or "").startswith("MALFORMED_FIREWALL_RESPONSE")
        assert TOKEN not in (result.error or "")
        assert len(server.requests) == 1
        assert server.requests[0]["method"] == "GET"
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.parametrize(
    "inbound_rules",
    [
        [{"protocol": "all", "ports": "0", "action": "deny", "sources": None}],
        [{"protocol": "all", "ports": "0", "action": "deny", "sources": {"addresses": "not-a-list"}}],
        [{"protocol": "all", "ports": "0", "action": "deny", "sources": []}],
    ],
    ids=["sources-null", "sources-addresses-not-list", "sources-not-a-dict"],
)
def test_add_deny_rule_rejects_malformed_inbound_sources_shape(inbound_rules):
    get_body = _firewall_body(inbound_rules)
    server, thread = _make_server(get_response_code=200, get_response_body=_json_bytes(get_body))
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOFirewallClient(TOKEN, "fw-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_rule("198.51.100.7")

        assert result.ok is False
        assert (result.error or "").startswith("MALFORMED_FIREWALL_RESPONSE")
        assert TOKEN not in (result.error or "")
        assert len(server.requests) == 1
        assert server.requests[0]["method"] == "GET"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_add_deny_rule_rejects_malformed_outbound_destinations_shape():
    outbound_rule = {
        "protocol": "all",
        "ports": "0",
        "action": "deny",
        "destinations": {"addresses": None},
    }
    get_body = _firewall_body([], outbound_rules=[outbound_rule])
    server, thread = _make_server(get_response_code=200, get_response_body=_json_bytes(get_body))
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOFirewallClient(TOKEN, "fw-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_rule("198.51.100.7")

        assert result.ok is False
        assert (result.error or "").startswith("MALFORMED_FIREWALL_RESPONSE")
        assert TOKEN not in (result.error or "")
        assert len(server.requests) == 1
        assert server.requests[0]["method"] == "GET"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_add_deny_rule_handles_put_422():
    unrelated_rules = [
        {"protocol": "tcp", "ports": str(1000 + i), "action": "allow", "sources": {"addresses": ["0.0.0.0/0"]}}
        for i in range(50)
    ]
    get_body = _firewall_body(unrelated_rules)
    put_error_body = _json_bytes(
        {"id": "unprocessable_entity", "message": "must have no more than 50 rules", "request_id": "abc"}
    )
    server, thread = _make_server(
        get_response_code=200,
        get_response_body=_json_bytes(get_body),
        put_response_code=422,
        put_response_body=put_error_body,
    )
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOFirewallClient(TOKEN, "fw-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_rule("198.51.100.7")

        assert result.ok is False
        assert result.http_status == 422
        assert "must have no more than 50 rules" in (result.error or "")
        assert TOKEN not in (result.error or "")
        assert len(server.requests) == 2
        assert server.requests[0]["method"] == "GET"
        assert server.requests[1]["method"] == "PUT"
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


def test_plan_update_does_not_mutate_input_firewall():
    firewall = {
        "name": "hp-fw",
        "droplet_ids": [111],
        "tags": ["honeypot"],
        "inbound_rules": [
            {"protocol": "all", "ports": "0", "action": "deny", "sources": {"addresses": ["198.51.100.1"]}}
        ],
        "outbound_rules": [],
    }
    before = copy.deepcopy(firewall)

    plan = DOFirewallClient.plan_update(firewall, "198.51.100.2")

    assert firewall == before
    assert firewall["inbound_rules"][0]["sources"]["addresses"] == ["198.51.100.1"]
    assert plan.payload["inbound_rules"][0]["sources"]["addresses"] == ["198.51.100.1", "198.51.100.2"]
