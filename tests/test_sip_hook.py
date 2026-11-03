import types

import sip
from scripts.send_sip_probe import build_sip_request


class FakeHost:
    def __init__(self, host, port):
        self.host = host
        self.port = port


class FakeTransport:
    def __init__(self, host="0.0.0.0", port=5060):
        self._host = FakeHost(host, port)
        self.writes = []

    def getHost(self):
        return self._host

    def write(self, data, addr):
        self.writes.append((data, addr))


class RecordingMetrics:
    def __init__(self):
        self.events = []

    def submit(self, event):
        self.events.append(event)
        return True


def test_options_datagram_is_parsed_and_metrics_submitted(monkeypatch):
    # Make simulateResponse's deferLater run its callback immediately so we
    # can observe the eventual response packets without a running reactor.
    def _run_now(_reactor, _delay, fn, *args, **kwargs):
        return fn(*args, **kwargs)

    monkeypatch.setattr(sip.task, "deferLater", _run_now)

    metrics = RecordingMetrics()
    protocol = sip.SimpleSIPProtocol(metrics=metrics)
    protocol.transport = FakeTransport(host="198.51.100.1", port=5060)

    src_addr = ("203.0.113.9", 5061)
    datagram = build_sip_request("OPTIONS", "198.51.100.1", 5060, local_host=src_addr[0], local_port=src_addr[1])

    protocol.datagramReceived(datagram, src_addr)

    # (a) the fix works: no immediate 400 fallback was ever written.
    assert all(not data.startswith(b"SIP/2.0 400") for data, _addr in protocol.transport.writes)
    assert any(data.startswith(b"SIP/2.0 200") for data, _addr in protocol.transport.writes)

    # (b) metrics.submit was called with the parsed event.
    assert len(metrics.events) == 1
    event = metrics.events[0]
    assert event["method"] == "OPTIONS"
    assert event["src_ip"] == src_addr[0]
    assert event["src_port"] == src_addr[1]


def test_invite_200_ok_includes_dummy_sdp(monkeypatch):
    # Make simulateResponse's deferLater run its callback immediately so we
    # can observe the eventual response packets without a running reactor.
    def _run_now(_reactor, _delay, fn, *args, **kwargs):
        return fn(*args, **kwargs)

    monkeypatch.setattr(sip.task, "deferLater", _run_now)

    metrics = RecordingMetrics()
    protocol = sip.SimpleSIPProtocol(metrics=metrics)
    protocol.transport = FakeTransport(host="198.51.100.1", port=5060)

    src_addr = ("203.0.113.9", 5061)
    datagram = build_sip_request("INVITE", "198.51.100.1", 5060, local_host=src_addr[0], local_port=src_addr[1])

    protocol.datagramReceived(datagram, src_addr)

    writes = [data for data, _addr in protocol.transport.writes]
    assert len(writes) == 3

    trying_pkt = next(data for data in writes if data.startswith(b"SIP/2.0 100"))
    ringing_pkt = next(data for data in writes if data.startswith(b"SIP/2.0 180"))
    ok_pkt = next(data for data in writes if data.startswith(b"SIP/2.0 200"))

    for pkt in (trying_pkt, ringing_pkt):
        assert b"Content-Length: 0" in pkt
        assert b"Content-Type: application/sdp" not in pkt
        body = pkt.split(b"\r\n\r\n", 1)[1]
        assert body == b""

    assert b"Content-Type: application/sdp" in ok_pkt
    headers, body = ok_pkt.split(b"\r\n\r\n", 1)
    match = [line for line in headers.split(b"\r\n") if line.startswith(b"Content-Length: ")][0]
    content_length = int(match.split(b": ", 1)[1])
    assert content_length > 0
    assert body != b""
    assert body.startswith(b"v=0")
