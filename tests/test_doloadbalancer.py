import copy
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from metrics.doloadbalancer import DOLoadBalancerClient

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


def _json_bytes(obj):
    return json.dumps(obj).encode("utf-8")


def _lb_body(**overrides):
    lb = {
        "id": "lb-123",
        "name": "hp-lb",
        "ip": "10.0.0.1",
        "ipv6": "",
        "status": "active",
        "created_at": "2024-01-01T00:00:00Z",
        "region": {"slug": "nyc3", "name": "New York 3"},
        "size_unit": 1,
        "forwarding_rules": [{"entry_protocol": "tcp", "entry_port": 443}],
        "droplet_ids": [111, 222],
        "firewall": {"deny": ["ip:198.51.100.1"], "allow": ["ip:203.0.113.5"]},
    }
    lb.update(overrides)
    return {"load_balancer": lb}


def test_add_deny_rule_droplet_managed_append_path():
    get_body = _lb_body()
    server, thread = _make_server(
        get_response_code=200,
        get_response_body=_json_bytes(get_body),
        put_response_code=200,
        put_response_body=b"",
    )
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOLoadBalancerClient(TOKEN, "lb-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_rule("198.51.100.9")

        assert len(server.requests) == 2
        get_req, put_req = server.requests
        assert get_req["method"] == "GET"
        assert get_req["path"] == "/v2/load_balancers/lb-123"
        assert put_req["method"] == "PUT"
        assert put_req["path"] == "/v2/load_balancers/lb-123"

        put_body = put_req["body"]
        assert "id" not in put_body
        assert "ip" not in put_body
        assert "ipv6" not in put_body
        assert "status" not in put_body
        assert "created_at" not in put_body
        assert put_body["region"] == "nyc3"
        assert put_body["droplet_ids"] == [111, 222]
        assert "tag" not in put_body
        assert put_body["firewall"]["deny"] == ["ip:198.51.100.1", "ip:198.51.100.9"]
        assert put_body["firewall"]["allow"] == ["ip:203.0.113.5"]
        assert put_body["size_unit"] == 1
        assert put_body["forwarding_rules"] == [{"entry_protocol": "tcp", "entry_port": 443}]

        assert result.ok is True
        assert result.http_status == 200
        assert result.error is None
        assert TOKEN not in (result.error or "")
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_plan_update_droplet_ids_payload_is_not_same_list_object():
    lb = _lb_body()["load_balancer"]

    plan = DOLoadBalancerClient.plan_update(lb, ["198.51.100.9"])

    assert plan.payload["droplet_ids"] == lb["droplet_ids"]
    assert plan.payload["droplet_ids"] is not lb["droplet_ids"]


def test_add_deny_rule_tag_managed_lb_has_tag_not_droplet_ids():
    get_body = _lb_body(tag="my-droplets", droplet_ids=[])
    server, thread = _make_server(
        get_response_code=200,
        get_response_body=_json_bytes(get_body),
        put_response_code=200,
        put_response_body=b"",
    )
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOLoadBalancerClient(TOKEN, "lb-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_rule("198.51.100.9")

        put_body = server.requests[1]["body"]
        assert put_body["tag"] == "my-droplets"
        assert "droplet_ids" not in put_body
        assert result.ok is True
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_add_deny_rule_no_firewall_key_in_get_response():
    lb = _lb_body()["load_balancer"]
    del lb["firewall"]
    get_body = {"load_balancer": lb}
    server, thread = _make_server(
        get_response_code=200,
        get_response_body=_json_bytes(get_body),
        put_response_code=200,
        put_response_body=b"",
    )
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOLoadBalancerClient(TOKEN, "lb-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_rule("198.51.100.9")

        put_body = server.requests[1]["body"]
        assert put_body["firewall"] == {"deny": ["ip:198.51.100.9"], "allow": []}
        assert result.ok is True
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_add_deny_rule_ip_already_present_no_put():
    get_body = _lb_body(firewall={"deny": ["ip:198.51.100.9"], "allow": []})
    server, thread = _make_server(get_response_code=200, get_response_body=_json_bytes(get_body))
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOLoadBalancerClient(TOKEN, "lb-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_rule("198.51.100.9")

        assert len(server.requests) == 1
        assert server.requests[0]["method"] == "GET"
        assert result.ok is True
        assert result.http_status == 200
        assert result.error is None
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_add_deny_entries_batch_mix_duplicate_already_present_new_cidr():
    get_body = _lb_body(firewall={"deny": ["ip:198.51.100.1"], "allow": []})
    server, thread = _make_server(
        get_response_code=200,
        get_response_body=_json_bytes(get_body),
        put_response_code=200,
        put_response_body=b"",
    )
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOLoadBalancerClient(TOKEN, "lb-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_entries(["198.51.100.1", "198.51.100.9", "198.51.100.9", "203.0.113.0/24"])

        put_body = server.requests[1]["body"]
        assert put_body["firewall"]["deny"] == [
            "ip:198.51.100.1",
            "ip:198.51.100.9",
            "cidr:203.0.113.0/24",
        ]
        assert result.ok is True
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_add_deny_rule_invalid_address_no_put():
    get_body = _lb_body()
    server, thread = _make_server(get_response_code=200, get_response_body=_json_bytes(get_body))
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOLoadBalancerClient(TOKEN, "lb-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_rule("not-an-ip")

        assert len(server.requests) == 1
        assert server.requests[0]["method"] == "GET"
        assert result.ok is False
        assert result.http_status is None
        assert (result.error or "").startswith("INVALID_ADDRESS")
        assert TOKEN not in (result.error or "")
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_plan_update_non_string_address_returns_invalid_address_not_typeerror():
    lb = _lb_body()["load_balancer"]

    plan = DOLoadBalancerClient.plan_update(lb, [123])

    assert plan.payload is None
    assert plan.added == ()
    assert (plan.error or "").startswith("INVALID_ADDRESS")


def _malformed_lb(**overrides):
    lb = {
        "id": "lb-123",
        "name": "hp-lb",
        "region": {"slug": "nyc3"},
        "forwarding_rules": [],
        "droplet_ids": [],
        "firewall": {"deny": [], "allow": []},
    }
    lb.update(overrides)
    return lb


@pytest.mark.parametrize(
    "get_body",
    [b"not json", _json_bytes({"nope": 1})],
    ids=["not-json", "missing-load-balancer-key"],
)
def test_add_deny_rule_handles_malformed_get_body(get_body):
    server, thread = _make_server(get_response_code=200, get_response_body=get_body)
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOLoadBalancerClient(TOKEN, "lb-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_rule("198.51.100.7")

        assert result.ok is False
        assert (result.error or "").startswith("MALFORMED_LOAD_BALANCER_RESPONSE")
        assert TOKEN not in (result.error or "")
        assert len(server.requests) == 1
        assert server.requests[0]["method"] == "GET"
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.parametrize(
    "lb",
    [
        _malformed_lb(name=""),
        _malformed_lb(name=None),
        _malformed_lb(forwarding_rules="not-a-list"),
        _malformed_lb(region=None),
        _malformed_lb(region={"name": "New York 3"}),
        _malformed_lb(firewall="not-a-dict"),
        _malformed_lb(firewall={"deny": "not-a-list", "allow": []}),
        _malformed_lb(firewall={"deny": ["ip:1.2.3.4", 5], "allow": []}),
    ],
    ids=[
        "empty-name",
        "null-name",
        "forwarding-rules-not-list",
        "region-missing",
        "region-dict-no-slug",
        "firewall-not-dict",
        "deny-not-list",
        "deny-contains-non-string",
    ],
)
def test_add_deny_rule_handles_malformed_lb_shape(lb):
    get_body = {"load_balancer": lb}
    server, thread = _make_server(get_response_code=200, get_response_body=_json_bytes(get_body))
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOLoadBalancerClient(TOKEN, "lb-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_rule("198.51.100.7")

        assert result.ok is False
        assert (result.error or "").startswith("MALFORMED_LOAD_BALANCER_RESPONSE")
        assert TOKEN not in (result.error or "")
        assert len(server.requests) == 1
        assert server.requests[0]["method"] == "GET"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_add_deny_rule_handles_get_401_with_json_body():
    error_body = _json_bytes({"id": "unauthorized", "message": "Unable to authenticate you."})
    server, thread = _make_server(get_response_code=401, get_response_body=error_body)
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOLoadBalancerClient(TOKEN, "lb-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_rule("198.51.100.7")

        assert result.ok is False
        assert result.http_status == 401
        assert "Unable to authenticate you" in (result.error or "")
        assert TOKEN not in (result.error or "")
        assert len(server.requests) == 1
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_add_deny_rule_handles_put_422():
    get_body = _lb_body()
    put_error_body = _json_bytes({"id": "unprocessable_entity", "message": "invalid firewall entry"})
    server, thread = _make_server(
        get_response_code=200,
        get_response_body=_json_bytes(get_body),
        put_response_code=422,
        put_response_body=put_error_body,
    )
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOLoadBalancerClient(TOKEN, "lb-123", base_url=base_url, timeout=5.0)
        result = client.add_deny_rule("198.51.100.7")

        assert result.ok is False
        assert result.http_status == 422
        assert "invalid firewall entry" in (result.error or "")
        assert TOKEN not in (result.error or "")
        assert len(server.requests) == 2
        assert server.requests[0]["method"] == "GET"
        assert server.requests[1]["method"] == "PUT"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_add_deny_rule_handles_connection_failure():
    probe = HTTPServer(("127.0.0.1", 0), _RecordingHandler)
    closed_port = probe.server_port
    probe.server_close()

    client = DOLoadBalancerClient(TOKEN, "lb-123", base_url=f"http://127.0.0.1:{closed_port}", timeout=2.0)
    result = client.add_deny_rule("198.51.100.7")

    assert result.ok is False
    assert result.http_status is None
    assert TOKEN not in (result.error or "")


def test_remove_deny_rule_removes_present_entry():
    get_body = _lb_body(firewall={"deny": ["ip:198.51.100.1", "ip:198.51.100.9"], "allow": ["ip:203.0.113.5"]})
    server, thread = _make_server(
        get_response_code=200,
        get_response_body=_json_bytes(get_body),
        put_response_code=200,
        put_response_body=b"",
    )
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOLoadBalancerClient(TOKEN, "lb-123", base_url=base_url, timeout=5.0)
        result = client.remove_deny_rule("198.51.100.9")

        assert len(server.requests) == 2
        put_req = server.requests[1]
        assert put_req["method"] == "PUT"
        put_body = put_req["body"]
        assert put_body["firewall"]["deny"] == ["ip:198.51.100.1"]
        assert put_body["firewall"]["allow"] == ["ip:203.0.113.5"]

        assert result.ok is True
        assert result.http_status == 200
        assert result.error is None
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_remove_deny_rule_address_not_present_no_put():
    get_body = _lb_body(firewall={"deny": ["ip:198.51.100.1"], "allow": []})
    server, thread = _make_server(get_response_code=200, get_response_body=_json_bytes(get_body))
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOLoadBalancerClient(TOKEN, "lb-123", base_url=base_url, timeout=5.0)
        result = client.remove_deny_rule("198.51.100.99")

        assert len(server.requests) == 1
        assert server.requests[0]["method"] == "GET"
        assert result.ok is True
        assert result.http_status == 200
        assert result.error is None
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_remove_deny_entries_batch_mixed_present_and_absent():
    get_body = _lb_body(firewall={"deny": ["ip:198.51.100.1", "cidr:203.0.113.0/24"], "allow": []})
    server, thread = _make_server(
        get_response_code=200,
        get_response_body=_json_bytes(get_body),
        put_response_code=200,
        put_response_body=b"",
    )
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOLoadBalancerClient(TOKEN, "lb-123", base_url=base_url, timeout=5.0)
        result = client.remove_deny_entries(["198.51.100.1", "198.51.100.77", "203.0.113.0/24"])

        put_body = server.requests[1]["body"]
        assert put_body["firewall"]["deny"] == []
        assert result.ok is True
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_remove_deny_rule_invalid_address_no_put():
    get_body = _lb_body()
    server, thread = _make_server(get_response_code=200, get_response_body=_json_bytes(get_body))
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOLoadBalancerClient(TOKEN, "lb-123", base_url=base_url, timeout=5.0)
        result = client.remove_deny_rule("not-an-ip")

        assert len(server.requests) == 1
        assert server.requests[0]["method"] == "GET"
        assert result.ok is False
        assert result.http_status is None
        assert (result.error or "").startswith("INVALID_ADDRESS")
        assert TOKEN not in (result.error or "")
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.parametrize(
    "lb",
    [
        _malformed_lb(name=""),
        _malformed_lb(name=None),
        _malformed_lb(forwarding_rules="not-a-list"),
        _malformed_lb(region=None),
        _malformed_lb(region={"name": "New York 3"}),
        _malformed_lb(firewall="not-a-dict"),
        _malformed_lb(firewall={"deny": "not-a-list", "allow": []}),
        _malformed_lb(firewall={"deny": ["ip:1.2.3.4", 5], "allow": []}),
    ],
    ids=[
        "empty-name",
        "null-name",
        "forwarding-rules-not-list",
        "region-missing",
        "region-dict-no-slug",
        "firewall-not-dict",
        "deny-not-list",
        "deny-contains-non-string",
    ],
)
def test_remove_deny_rule_handles_malformed_lb_shape(lb):
    get_body = {"load_balancer": lb}
    server, thread = _make_server(get_response_code=200, get_response_body=_json_bytes(get_body))
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        client = DOLoadBalancerClient(TOKEN, "lb-123", base_url=base_url, timeout=5.0)
        result = client.remove_deny_rule("198.51.100.7")

        assert result.ok is False
        assert (result.error or "").startswith("MALFORMED_LOAD_BALANCER_RESPONSE")
        assert TOKEN not in (result.error or "")
        assert len(server.requests) == 1
        assert server.requests[0]["method"] == "GET"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_plan_removal_does_not_mutate_input_load_balancer():
    lb = _lb_body(firewall={"deny": ["ip:198.51.100.1", "ip:198.51.100.9"], "allow": []})["load_balancer"]
    before = copy.deepcopy(lb)

    plan = DOLoadBalancerClient.plan_removal(lb, ["198.51.100.9"])

    assert lb == before
    assert lb["firewall"]["deny"] == ["ip:198.51.100.1", "ip:198.51.100.9"]
    assert plan.payload["firewall"]["deny"] == ["ip:198.51.100.1"]


def test_plan_update_does_not_mutate_input_load_balancer():
    lb = _lb_body()["load_balancer"]
    before = copy.deepcopy(lb)

    plan = DOLoadBalancerClient.plan_update(lb, ["198.51.100.9"])

    assert lb == before
    assert lb["firewall"]["deny"] == ["ip:198.51.100.1"]
    assert plan.payload["firewall"]["deny"] == ["ip:198.51.100.1", "ip:198.51.100.9"]
