import sip
from scripts.send_sip_probe import build_sip_request

from tests.test_sip_hook import FakeTransport, RecordingMetrics


def _malformed_datagram(host, port, local_host="198.51.100.5", local_port=5060):
    """A SIP request declaring a Content-Length far larger than the body
    actually present in the datagram.

    This mirrors how an attacker would trigger Twisted's
    MessagesParser.dataDone() to raise RuntimeError("this should never
    happen") *before* the parser resets its internal state, leaving it
    wedged mid-body.
    """
    lines = [
        f"OPTIONS sip:service@{host}:{port} SIP/2.0",
        f"Via: SIP/2.0/UDP {local_host}:{local_port};branch=z9hG4bKdeadbeef",
        f"From: <sip:probe@{local_host}>;tag=deadbeef",
        f"To: <sip:service@{host}>",
        "Call-ID: malformed-wedge-test",
        "CSeq: 1 OPTIONS",
        "Max-Forwards: 70",
        "Content-Length: 2000000000",
        "",
        "XY",
    ]
    return "\r\n".join(lines).encode("utf-8")


def test_malformed_datagram_does_not_wedge_parser_for_next_address(monkeypatch):
    # Make simulateResponse's deferLater run its callback immediately so we
    # can observe response packets without a running reactor.
    def _run_now(_reactor, _delay, fn, *args, **kwargs):
        return fn(*args, **kwargs)

    monkeypatch.setattr(sip.task, "deferLater", _run_now)

    metrics = RecordingMetrics()
    protocol = sip.SimpleSIPProtocol(metrics=metrics)
    protocol.transport = FakeTransport(host="198.51.100.1", port=5060)

    attacker_addr = ("203.0.113.9", 5061)
    victim_addr = ("203.0.113.99", 5062)

    # (1) Send the malformed datagram that wedges the shared, stateful
    # MessagesParser mid-body.
    bad_datagram = _malformed_datagram("198.51.100.1", 5060, local_host=attacker_addr[0], local_port=attacker_addr[1])
    protocol.datagramReceived(bad_datagram, attacker_addr)

    # (2) Send a second, well-formed OPTIONS datagram from a *different*
    # address. If the parser is still wedged, these bytes get silently
    # consumed as "more body" of the stale attacker message instead of being
    # parsed as their own request.
    good_datagram = build_sip_request(
        "OPTIONS", "198.51.100.1", 5060, local_host=victim_addr[0], local_port=victim_addr[1]
    )
    protocol.datagramReceived(good_datagram, victim_addr)

    # The second datagram must be parsed and dispatched correctly: a metrics
    # event recorded for the victim's address, and a non-400 response sent
    # directly to the victim's address.
    victim_events = [e for e in metrics.events if e["src_ip"] == victim_addr[0]]
    assert len(victim_events) == 1
    assert victim_events[0]["method"] == "OPTIONS"

    victim_writes = [data for data, addr in protocol.transport.writes if addr == victim_addr]
    assert any(data.startswith(b"SIP/2.0 200") for data in victim_writes)
