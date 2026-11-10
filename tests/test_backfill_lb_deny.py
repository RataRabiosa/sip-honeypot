import json

from scripts.backfill_lb_deny import main
from tests.fake_do_server import make_routed_server

TOKEN = "super-secret-do-token-12345"


def _json_bytes(obj):
    return json.dumps(obj).encode("utf-8")


def _firewall_get_body():
    rule1 = {
        "protocol": "all",
        "ports": "0",
        "action": "deny",
        "sources": {"addresses": ["198.51.100.1", "203.0.113.0/24", "198.51.100.2"]},
    }
    rule2 = {
        "protocol": "all",
        "ports": "0",
        "action": "deny",
        "sources": {"addresses": ["198.51.100.2", "198.51.100.3"]},
    }
    unrelated = {
        "protocol": "tcp",
        "ports": "22",
        "action": "allow",
        "sources": {"addresses": ["0.0.0.0/0"]},
    }
    return {
        "firewall": {
            "id": "fw-123",
            "name": "hp-fw",
            "inbound_rules": [rule1, rule2, unrelated],
            "outbound_rules": [],
        }
    }


def _empty_firewall_get_body():
    unrelated = {
        "protocol": "tcp",
        "ports": "22",
        "action": "allow",
        "sources": {"addresses": ["0.0.0.0/0"]},
    }
    return {
        "firewall": {
            "id": "fw-123",
            "name": "hp-fw",
            "inbound_rules": [unrelated],
            "outbound_rules": [],
        }
    }


def _lb1_get_body(deny=None, allow=None):
    return {
        "load_balancer": {
            "id": "lb-1",
            "name": "lb-one",
            "region": {"slug": "nyc3"},
            "forwarding_rules": [],
            "droplet_ids": [1],
            "firewall": {
                "deny": deny if deny is not None else ["ip:198.51.100.1"],
                "allow": allow or ["ip:203.0.113.9"],
            },
        }
    }


def _lb2_get_body(firewall=None):
    lb = {
        "id": "lb-2",
        "name": "lb-two",
        "region": {"slug": "nyc3"},
        "forwarding_rules": [],
        "droplet_ids": [2],
    }
    if firewall is not None:
        lb["firewall"] = firewall
    return {"load_balancer": lb}


def _firewall2_get_body():
    # Overlaps "198.51.100.2" with _firewall_get_body() and adds two distinct addresses.
    rule = {
        "protocol": "all",
        "ports": "0",
        "action": "deny",
        "sources": {"addresses": ["198.51.100.2", "198.51.100.9", "198.51.100.10"]},
    }
    return {
        "firewall": {
            "id": "fw-456",
            "name": "hp-fw-2",
            "inbound_rules": [rule],
            "outbound_rules": [],
        }
    }


# Expected, order-preserved set of managed deny addresses from _firewall_get_body().
ALL_ADDRESSES = ["198.51.100.1", "203.0.113.0/24", "198.51.100.2", "198.51.100.3"]

# Expected, order-preserved, de-duplicated union of _firewall_get_body() and
# _firewall2_get_body()'s managed deny addresses.
UNIONED_ADDRESSES = [
    "198.51.100.1",
    "203.0.113.0/24",
    "198.51.100.2",
    "198.51.100.3",
    "198.51.100.9",
    "198.51.100.10",
]


def _base_environ(base_url):
    return {
        "DO_API_TOKEN": TOKEN,
        "DO_FIREWALL_ID": "fw-123",
        "DO_LOAD_BALANCER_IDS": "lb-1,lb-2",
        "DO_API_BASE_URL": base_url,
        "DO_API_TIMEOUT_SECONDS": "5",
    }


def test_dry_run_then_live_run_then_idempotent_rerun(capsys):
    get_routes = {
        "/v2/firewalls/fw-123": (200, _json_bytes(_firewall_get_body())),
        "/v2/load_balancers/lb-1": (200, _json_bytes(_lb1_get_body())),
        "/v2/load_balancers/lb-2": (200, _json_bytes(_lb2_get_body())),
    }
    put_routes = {
        "/v2/load_balancers/lb-1": (200, b""),
        "/v2/load_balancers/lb-2": (200, b""),
    }
    server, thread = make_routed_server(get_routes, put_routes)
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        environ = _base_environ(base_url)

        # (a) dry run: GET-only, no PUTs, exit 0, correct to-add entries printed.
        exit_code = main(["--dry-run"], dict(environ))
        out = capsys.readouterr().out
        assert exit_code == 0
        assert all(req["method"] == "GET" for req in server.requests)
        assert "+ cidr:203.0.113.0/24" in out
        assert "+ ip:198.51.100.2" in out
        assert "+ ip:198.51.100.3" in out
        # lb-1 already has ip:198.51.100.1, so it must not be listed as newly added for lb-1.
        assert "LB lb-1" in out
        assert "LB lb-2" in out
        server.requests.clear()

        # (b) live run: PUTs issued to both LBs with expected deny contents, allow preserved.
        exit_code = main([], dict(environ))
        out = capsys.readouterr().out
        assert exit_code == 0
        put_reqs = [req for req in server.requests if req["method"] == "PUT"]
        assert len(put_reqs) == 2
        put_by_path = {req["path"]: req["body"] for req in put_reqs}

        lb1_put = put_by_path["/v2/load_balancers/lb-1"]
        assert lb1_put["firewall"]["deny"] == [
            "ip:198.51.100.1",
            "cidr:203.0.113.0/24",
            "ip:198.51.100.2",
            "ip:198.51.100.3",
        ]
        assert lb1_put["firewall"]["allow"] == ["ip:203.0.113.9"]

        lb2_put = put_by_path["/v2/load_balancers/lb-2"]
        assert lb2_put["firewall"]["deny"] == [
            "ip:198.51.100.1",
            "cidr:203.0.113.0/24",
            "ip:198.51.100.2",
            "ip:198.51.100.3",
        ]
        assert lb2_put["firewall"]["allow"] == []

        # (c) re-run with GET responses now reflecting the post-write state: no PUTs this time.
        server.get_routes["/v2/load_balancers/lb-1"] = (
            200,
            _json_bytes(_lb1_get_body(deny=lb1_put["firewall"]["deny"])),
        )
        server.get_routes["/v2/load_balancers/lb-2"] = (
            200,
            _json_bytes(_lb2_get_body(firewall=lb2_put["firewall"])),
        )
        server.requests.clear()

        exit_code = main([], dict(environ))
        out = capsys.readouterr().out
        assert exit_code == 0
        assert all(req["method"] == "GET" for req in server.requests)
        assert "up to date" in out
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_one_lb_fetch_failure_other_lb_still_updated_exit_1(capsys):
    get_routes = {
        "/v2/firewalls/fw-123": (200, _json_bytes(_firewall_get_body())),
        "/v2/load_balancers/lb-1": (200, _json_bytes(_lb1_get_body())),
        "/v2/load_balancers/lb-2": (500, b""),
    }
    put_routes = {
        "/v2/load_balancers/lb-1": (200, b""),
    }
    server, thread = make_routed_server(get_routes, put_routes)
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        environ = _base_environ(base_url)

        exit_code = main([], dict(environ))
        out = capsys.readouterr().out

        assert exit_code == 1
        assert "LB lb-2: FAILED fetch" in out
        put_reqs = [
            req for req in server.requests if req["method"] == "PUT" and req["path"] == "/v2/load_balancers/lb-1"
        ]
        assert len(put_reqs) == 1
        assert "LB lb-1: updated" in out
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_firewall_fetch_failure_no_lb_requests_exit_1(capsys):
    get_routes = {
        "/v2/firewalls/fw-123": (404, b""),
        "/v2/load_balancers/lb-1": (200, _json_bytes(_lb1_get_body())),
        "/v2/load_balancers/lb-2": (200, _json_bytes(_lb2_get_body())),
    }
    server, thread = make_routed_server(get_routes, {})
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        environ = _base_environ(base_url)

        exit_code = main([], dict(environ))
        err = capsys.readouterr().err

        assert exit_code == 1
        assert "ERROR: firewall fw-123" in err
        assert all(req["path"].startswith("/v2/firewalls/") for req in server.requests)
        assert len(server.requests) == 1
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_missing_token_or_empty_load_balancer_ids_exit_2_no_requests(capsys):
    get_routes = {
        "/v2/firewalls/fw-123": (200, _json_bytes(_firewall_get_body())),
    }
    server, thread = make_routed_server(get_routes, {})
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"

        environ_no_token = _base_environ(base_url)
        del environ_no_token["DO_API_TOKEN"]
        exit_code = main([], environ_no_token)
        err = capsys.readouterr().err
        assert exit_code == 2
        assert "ERROR" in err
        assert server.requests == []

        environ_no_lbs = _base_environ(base_url)
        environ_no_lbs["DO_LOAD_BALANCER_IDS"] = ""
        exit_code = main([], environ_no_lbs)
        err = capsys.readouterr().err
        assert exit_code == 2
        assert "ERROR" in err
        assert server.requests == []
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_zero_managed_addresses_nothing_to_backfill(capsys):
    get_routes = {
        "/v2/firewalls/fw-123": (200, _json_bytes(_empty_firewall_get_body())),
        "/v2/load_balancers/lb-1": (200, _json_bytes(_lb1_get_body())),
        "/v2/load_balancers/lb-2": (200, _json_bytes(_lb2_get_body())),
    }
    server, thread = make_routed_server(get_routes, {})
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        environ = _base_environ(base_url)

        exit_code = main([], dict(environ))
        out = capsys.readouterr().out

        assert exit_code == 0
        assert "nothing to backfill" in out
        assert all(req["path"].startswith("/v2/firewalls/") for req in server.requests)
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_firewall_missing_name_does_not_crash_and_still_processes_lbs(capsys):
    firewall_body = _firewall_get_body()
    del firewall_body["firewall"]["name"]
    get_routes = {
        "/v2/firewalls/fw-123": (200, _json_bytes(firewall_body)),
        "/v2/load_balancers/lb-1": (200, _json_bytes(_lb1_get_body())),
        "/v2/load_balancers/lb-2": (200, _json_bytes(_lb2_get_body())),
    }
    put_routes = {
        "/v2/load_balancers/lb-1": (200, b""),
        "/v2/load_balancers/lb-2": (200, b""),
    }
    server, thread = make_routed_server(get_routes, put_routes)
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        environ = _base_environ(base_url)

        exit_code = main([], dict(environ))
        out = capsys.readouterr().out

        assert exit_code == 0
        assert "firewall fw-123 (None)" in out
        assert "LB lb-1" in out
        assert "LB lb-2" in out
        put_reqs = [req for req in server.requests if req["method"] == "PUT"]
        assert len(put_reqs) == 2
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_invalid_timeout_returns_2_no_requests(capsys):
    get_routes = {
        "/v2/firewalls/fw-123": (200, _json_bytes(_firewall_get_body())),
        "/v2/load_balancers/lb-1": (200, _json_bytes(_lb1_get_body())),
        "/v2/load_balancers/lb-2": (200, _json_bytes(_lb2_get_body())),
    }
    server, thread = make_routed_server(get_routes, {})
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        environ = _base_environ(base_url)
        environ["DO_API_TIMEOUT_SECONDS"] = "not-a-number"

        exit_code = main([], dict(environ))
        err = capsys.readouterr().err

        assert exit_code == 2
        assert "ERROR:" in err
        assert "not-a-number" in err
        assert server.requests == []
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_show_payload_prints_region(capsys):
    get_routes = {
        "/v2/firewalls/fw-123": (200, _json_bytes(_firewall_get_body())),
        "/v2/load_balancers/lb-1": (200, _json_bytes(_lb1_get_body())),
        "/v2/load_balancers/lb-2": (200, _json_bytes(_lb2_get_body())),
    }
    put_routes = {
        "/v2/load_balancers/lb-1": (200, b""),
        "/v2/load_balancers/lb-2": (200, b""),
    }
    server, thread = make_routed_server(get_routes, put_routes)
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        environ = _base_environ(base_url)

        exit_code = main(["--dry-run", "--show-payload"], dict(environ))
        out = capsys.readouterr().out

        assert exit_code == 0
        assert '"region"' in out
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_multi_firewall_union_is_backfilled_to_lbs(capsys):
    get_routes = {
        "/v2/firewalls/fw-123": (200, _json_bytes(_firewall_get_body())),
        "/v2/firewalls/fw-456": (200, _json_bytes(_firewall2_get_body())),
        "/v2/load_balancers/lb-1": (200, _json_bytes(_lb2_get_body())),
        "/v2/load_balancers/lb-2": (200, _json_bytes(_lb2_get_body())),
    }
    put_routes = {
        "/v2/load_balancers/lb-1": (200, b""),
        "/v2/load_balancers/lb-2": (200, b""),
    }
    server, thread = make_routed_server(get_routes, put_routes)
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        environ = _base_environ(base_url)
        environ["DO_FIREWALL_IDS"] = "fw-123,fw-456"

        exit_code = main([], dict(environ))
        out = capsys.readouterr().out

        assert exit_code == 0
        assert "firewall fw-123 (hp-fw)" in out
        assert "firewall fw-456 (hp-fw-2)" in out

        expected_deny = [
            "ip:198.51.100.1",
            "cidr:203.0.113.0/24",
            "ip:198.51.100.2",
            "ip:198.51.100.3",
            "ip:198.51.100.9",
            "ip:198.51.100.10",
        ]
        put_reqs = [req for req in server.requests if req["method"] == "PUT"]
        assert len(put_reqs) == 2
        for req in put_reqs:
            assert req["body"]["firewall"]["deny"] == expected_deny
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_second_of_two_firewalls_fetch_failure_aborts_before_lb_requests(capsys):
    get_routes = {
        "/v2/firewalls/fw-123": (200, _json_bytes(_firewall_get_body())),
        "/v2/firewalls/fw-456": (500, b""),
        "/v2/load_balancers/lb-1": (200, _json_bytes(_lb1_get_body())),
        "/v2/load_balancers/lb-2": (200, _json_bytes(_lb2_get_body())),
    }
    server, thread = make_routed_server(get_routes, {})
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        environ = _base_environ(base_url)
        environ["DO_FIREWALL_IDS"] = "fw-123,fw-456"

        exit_code = main([], dict(environ))
        err = capsys.readouterr().err

        assert exit_code == 1
        assert "ERROR: firewall fw-456" in err
        assert all(req["path"].startswith("/v2/firewalls/") for req in server.requests)
        assert len(server.requests) == 2
    finally:
        server.shutdown()
        thread.join(timeout=5)
