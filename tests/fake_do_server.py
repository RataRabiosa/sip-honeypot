"""Shared test helper: a real local HTTP server that answers routed GET/PUT
requests, modeled on the private helpers in tests/test_dofirewall.py.

Used by tests that need one fake server answering more than one path (e.g.
both /v2/firewalls/... and /v2/load_balancers/... for the backfill script),
so tests/test_dofirewall.py itself needs zero edits.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class _RoutedHandler(BaseHTTPRequestHandler):
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

    def _handle(self, routes):
        self._record()
        route = routes.get(self.path)
        if route is None:
            self._respond(404, b"")
            return
        status, body = route
        self._respond(status, body)

    def do_GET(self):
        self._handle(self.server.get_routes)

    def do_PUT(self):
        self._handle(self.server.put_routes)


def make_routed_server(get_routes: dict = None, put_routes: dict = None):
    """Start a real local HTTPServer answering the given GET/PUT routes.

    `get_routes`/`put_routes` map a path string to (status_code,
    response_body_bytes). An unmatched path/method returns 404. Every
    request made is recorded on `server.requests` as a dict with
    `method`, `path`, `headers`, and `body` (parsed JSON, or None if the
    request had no body).

    The returned `get_routes`/`put_routes` dicts (accessible as
    `server.get_routes`/`server.put_routes`) are the same mutable objects
    passed in (or newly created empty ones), so a test may mutate them
    in-place between requests to change how the server responds.
    """
    server = HTTPServer(("127.0.0.1", 0), _RoutedHandler)
    server.get_routes = get_routes if get_routes is not None else {}
    server.put_routes = put_routes if put_routes is not None else {}
    server.requests = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread
