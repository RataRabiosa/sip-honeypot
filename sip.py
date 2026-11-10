import os
import random
import argparse
import hashlib
import time
import binascii
import sys
from twisted.python import log
from twisted.internet import reactor, protocol, task
from twisted.protocols.sip import Base, Response
from metrics.config import ConfigError, load_settings

script_dir = os.path.dirname(os.path.abspath(__file__))

_REASON = {
    100: "Trying",
    180: "Ringing",
    200: "OK",
    202: "Accepted",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    408: "Request Timeout",
    480: "Temporarily Unavailable",
    486: "Busy Here",
    487: "Request Terminated",
    500: "Server Internal Error",
    501: "Not Implemented",
}

_ALLOWED = [
    "INVITE", "ACK", "CANCEL", "OPTIONS", "BYE", "REGISTER",
    "REFER", "NOTIFY", "MESSAGE", "SUBSCRIBE", "INFO", "PING",
    "PRACK", "UPDATE",
]


class SimpleSIPProtocol(Base):
    MAX_PACKET_LEN = 8192
    MAX_RAW_LOG_BYTES = 512
    TX_CACHE_TTL = 30.0

    def __init__(self, user_agent=None, metrics=None):
        Base.__init__(self)
        self.user_agent = str(user_agent) if user_agent is not None else "FRITZ!OS 1.0"
        self._tx_cache = {}
        self._gc = None
        self._cur_dat = None
        self.metrics = metrics

    def startProtocol(self):
        self._gc = task.LoopingCall(self._gc_states)
        self._gc.start(5.0, now=False)

    def stopProtocol(self):
        try:
            if self._gc and self._gc.running:
                self._gc.stop()
        except Exception:
            pass

    def _gc_states(self):
        now = time.time()
        dead = [k for k, v in self._tx_cache.items() if (now - v.get("ts", now)) > self.TX_CACHE_TTL]
        for k in dead:
            self._tx_cache.pop(k, None)

    def datagramReceived(self, datagram, address):
        if datagram is None:
            return
        if len(datagram) == 0:
            return
        if len(datagram) > self.MAX_PACKET_LEN:
            return

        if datagram in (b"\r\n", b"\r\n\r\n"):
            self._raw_log(datagram, address, parse_error="CRLF_KEEPALIVE")
            try:
                self.transport.write(b"\r\n", address)
            except Exception:
                pass
            return

        self._raw_log(datagram, address)
        self._cur_dat = (address, datagram)

        try:
            return Base.datagramReceived(self, datagram, address)
        except Exception as e:
            self._raw_log(datagram, address, parse_error=type(e).__name__)
            try:
                pkt = self._build_minimal_response(400, datagram, address)
                self.transport.write(pkt, address)
            except Exception:
                pass
        finally:
            # Twisted's MessagesParser is shared and stateful across datagrams.
            # If dataDone() raised (e.g. Content-Length longer than the body
            # actually present), the parser can be left mid-body, causing the
            # next unrelated datagram's bytes to be consumed as "more body" of
            # the stale message. Force a reset after every datagram, success
            # or failure, so no state leaks between datagrams/addresses.
            try:
                self.parser.reset()
                self.messages[:] = []
            except Exception:
                pass

    def _raw_log(self, data, address, parse_error=""):
        try:
            sha = hashlib.sha256(data).hexdigest()
            head = data[: self.MAX_RAW_LOG_BYTES]
            hex_head = binascii.hexlify(head).decode("ascii", "ignore")
            bx = "".join(f"\\x{b:02x}" for b in head)
            suffix = "" if len(data) <= self.MAX_RAW_LOG_BYTES else f"...(+{len(data)-self.MAX_RAW_LOG_BYTES} bytes)"
            if parse_error:
                log.msg(f"SIP_RAW_META - From: {address}, Len: {len(data)}, SHA256: {sha}, ParseError: {parse_error}")
            else:
                log.msg(f"SIP_RAW_META - From: {address}, Len: {len(data)}, SHA256: {sha}")
            log.msg(f"SIP_RAW_HEX  - {hex_head}{suffix}")
            log.msg(f"SIP_RAW_BX   - {bx}{suffix}")
        except Exception:
            pass

    def handle_request(self, request, addr):
        logs = {}
        dst_host, dst_port = self.get_destination_info()
        for key, value in request.headers.items():
            if value is not None:
                logs[key.upper()] = ", ".join(value)
        log.msg(logs)
        if self.metrics is not None:
            try:
                self.metrics.submit(self._metrics_event(request, addr, dst_host, dst_port))
            except Exception:
                pass
        self.simulateResponse(request, addr)

    def _metrics_event(self, request, addr, dst_host, dst_port):
        return {
            "ts": time.time(),
            "src_ip": str(addr[0]),
            "src_port": int(addr[1]),
            "dst_host": str(dst_host),
            "dst_port": int(dst_port),
            "method": self._b2s(getattr(request, "method", "")).upper().strip() or "UNKNOWN",
            "user_agent": self._get_header_first(request, b"user-agent", "") or None,
            "from_uri": self._from(request) or None,
            "to_uri": self._to(request) or None,
            "call_id": (
                self._get_header_first(request, b"call-id", "")
                or self._get_header_first(request, b"i", "")
            ).strip()
            or None,
        }

    def simulateResponse(self, request, addr):
        delay = random.uniform(0.1, 1.0)
        task.deferLater(reactor, delay, self.sendFakeResponse, request, addr)

    def _b2s(self, x):
        if x is None:
            return ""
        if isinstance(x, bytes):
            return x.decode("utf-8", "replace")
        return str(x)

    def _get_header_list(self, request, name):
        try:
            v = request.headers.get(name)
            if v:
                return v
        except Exception:
            pass
        try:
            if isinstance(name, bytes):
                v = request.headers.get(name.decode("ascii", "ignore"))
                if v:
                    return v
        except Exception:
            pass
        return []

    def _get_header_first(self, request, name, default=""):
        vals = self._get_header_list(request, name)
        if not vals:
            return default
        return self._b2s(vals[0])

    def _vias(self, request):
        out = []
        for v in self._get_header_list(request, b"via") + self._get_header_list(request, b"v"):
            s = self._b2s(v).strip()
            if s:
                out.append(s)
        return out

    def _call_id(self, request):
        cid = self._get_header_first(request, b"call-id", "") or self._get_header_first(request, b"i", "")
        return cid.strip() or hashlib.sha256(f"{time.time()}|{random.random()}".encode("utf-8", "ignore")).hexdigest()[:16]

    def _cseq(self, request):
        return (self._get_header_first(request, b"cseq", "") or "").strip()

    def _from(self, request):
        return (self._get_header_first(request, b"from", "") or self._get_header_first(request, b"f", "")).strip()

    def _to(self, request):
        return (self._get_header_first(request, b"to", "") or self._get_header_first(request, b"t", "")).strip()

    def _ensure_to_tag(self, to_val, call_id):
        if not to_val:
            host = getattr(self.transport.getHost(), "host", "127.0.0.1")
            return f"<sip:1001@{host}>;tag={self._tag_for_callid(call_id)}"
        if "tag=" in to_val.lower():
            return to_val
        return f"{to_val};tag={self._tag_for_callid(call_id)}"

    def _tag_for_callid(self, call_id):
        h = hashlib.sha256((call_id or "").encode("utf-8", "ignore")).hexdigest()
        return h[:8]

    def _has_auth(self, request):
        a = self._get_header_list(request, b"authorization") or self._get_header_list(request, b"proxy-authorization")
        if a and a[0]:
            return True
        return False

    def _now_gmt(self):
        return time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())

    def _tx_key(self, addr, request):
        cid = self._call_id(request)
        cseq = self._cseq(request)
        try:
            m = self._b2s(request.method).upper()
        except Exception:
            m = ""
        return f"{addr[0]}:{addr[1]}|{cid}|{cseq}|{m}"

    def _cache_packets(self, key, packets):
        self._tx_cache[key] = {"ts": time.time(), "packets": packets}

    def _replay_cached(self, addr, key):
        st = self._tx_cache.get(key)
        if not st:
            return False
        st["ts"] = time.time()
        for pkt in st.get("packets", []):
            try:
                self.transport.write(pkt, addr)
            except Exception:
                pass
        return True

    def _build_response_pkt(self, code, request, addr, extra_headers=None, body=b""):
        reason = _REASON.get(int(code), "OK")
        call_id = self._call_id(request)
        vias = self._vias(request)
        frm = self._from(request)
        to_v = self._ensure_to_tag(self._to(request), call_id)
        cseq = self._cseq(request)
        host = getattr(self.transport.getHost(), "host", "127.0.0.1")
        contact = f"<sip:1001@{host}>"

        lines = [f"SIP/2.0 {int(code)} {reason}"]
        for v in vias:
            lines.append(f"Via: {v}")
        if frm:
            lines.append(f"From: {frm}")
        if to_v:
            lines.append(f"To: {to_v}")
        lines.append(f"Call-ID: {call_id}")
        if cseq:
            lines.append(f"CSeq: {cseq}")
        lines.append(f"Server: {self.user_agent}")
        lines.append("Allow: " + ", ".join(_ALLOWED))
        lines.append("Supported: replaces, timer")
        lines.append("Date: " + self._now_gmt())
        if int(code) == 200:
            lines.append(f"Contact: {contact}")

        if extra_headers:
            for k, v in extra_headers.items():
                if v is None:
                    continue
                lines.append(f"{k}: {v}")

        if body:
            lines.append("Content-Type: application/sdp")
            lines.append(f"Content-Length: {len(body)}")
            return ("\r\n".join(lines)).encode("utf-8", "replace") + b"\r\n\r\n" + body

        lines.append("Content-Length: 0")
        return ("\r\n".join(lines)).encode("utf-8", "replace") + b"\r\n\r\n"

    def _build_minimal_response(self, code, raw, addr):
        reason = _REASON.get(int(code), "OK")
        host = getattr(self.transport.getHost(), "host", "127.0.0.1")
        lines = [
            f"SIP/2.0 {int(code)} {reason}",
            f"Via: SIP/2.0/UDP {host}",
            f"From: \"Alice\" <sip:alice@{host}>;tag={random.getrandbits(32):x}",
            f"To: \"VoIPServer\" <sip:voip@{host}>;tag={random.getrandbits(32):x}",
            f"Call-ID: {hashlib.sha256(raw[:128]).hexdigest()[:16]}",
            "CSeq: 1 OPTIONS",
            f"Server: {self.user_agent}",
            "Allow: " + ", ".join(_ALLOWED),
            "Supported: replaces, timer",
            "Date: " + self._now_gmt(),
            "Content-Length: 0",
            "",
            "",
        ]
        return "\r\n".join(lines).encode("utf-8", "replace")

    def _make_sdp(self):
        host = getattr(self.transport.getHost(), "host", "127.0.0.1")
        if not host or host == "0.0.0.0":
            host = "127.0.0.1"
        sdp = (
            "v=0\r\n"
            f"o=- 0 0 IN IP4 {host}\r\n"
            f"s={self.user_agent}\r\n"
            f"c=IN IP4 {host}\r\n"
            "t=0 0\r\n"
            "m=audio 4000 RTP/AVP 0 8 101\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
            "a=rtpmap:8 PCMA/8000\r\n"
            "a=rtpmap:101 telephone-event/8000\r\n"
            "a=fmtp:101 0-16\r\n"
        )
        return sdp.encode("utf-8", "replace")

    def sendFakeResponse(self, request, addr):
        try:
            key = self._tx_key(addr, request)
            if self._replay_cached(addr, key):
                return

            method = self._b2s(getattr(request, "method", b"")).upper().strip()
            packets = []

            if method == "OPTIONS":
                packets.append(self._build_response_pkt(200, request, addr))
            elif method == "REGISTER":
                if self._has_auth(request):
                    packets.append(self._build_response_pkt(200, request, addr, extra_headers={"Expires": "3600"}))
                else:
                    nonce = hashlib.sha256(f"{addr[0]}|{time.time()}|{random.random()}".encode("utf-8", "ignore")).hexdigest()
                    packets.append(
                        self._build_response_pkt(
                            401,
                            request,
                            addr,
                            extra_headers={
                                "WWW-Authenticate": f'Digest realm="example.com", nonce="{nonce}", algorithm=MD5, qop="auth"'
                            },
                        )
                    )
            elif method == "INVITE":
                packets.append(self._build_response_pkt(100, request, addr))
                packets.append(self._build_response_pkt(180, request, addr))
                packets.append(self._build_response_pkt(200, request, addr, body=self._make_sdp()))
            elif method in ("BYE", "CANCEL", "PRACK", "UPDATE", "INFO", "NOTIFY", "PING", "REFER", "SUBSCRIBE"):
                packets.append(self._build_response_pkt(200, request, addr))
            elif method == "MESSAGE":
                packets.append(self._build_response_pkt(202, request, addr))
            elif method == "ACK":
                self._cache_packets(key, [])
                return
            else:
                packets.append(self._build_response_pkt(404, request, addr))

            self._cache_packets(key, packets)

            if method == "INVITE":
                if packets:
                    try:
                        self.transport.write(packets[0], addr)
                    except Exception:
                        return
                def _send2():
                    try:
                        self.transport.write(packets[1], addr)
                    except Exception:
                        pass
                def _send3():
                    try:
                        self.transport.write(packets[2], addr)
                    except Exception:
                        pass
                task.deferLater(reactor, random.uniform(0.05, 0.25), _send2)
                task.deferLater(reactor, random.uniform(0.2, 0.8), _send3)
                return

            for pkt in packets:
                try:
                    self.transport.write(pkt, addr)
                except Exception:
                    return

        except Exception:
            return

    def get_destination_info(self):
        destination = self.transport.getHost()
        return destination.host, destination.port


class SimpleSIPFactory(protocol.Factory):
    protocol = SimpleSIPProtocol


def main():
    try:
        settings = load_settings(script_dir)
    except ConfigError as e:
        print(f"CONFIG ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    parser = argparse.ArgumentParser(description="Run a simple SIP honeypot server.")
    parser.add_argument("--host", type=str, default=settings.sip_host, help="Host to bind the SIP server to.")
    parser.add_argument("--port", type=int, default=settings.sip_port, help="Port to bind the SIP server to.")
    parser.add_argument("--user-agent", type=str, default=settings.sip_user_agent)
    args = parser.parse_args()

    LOG_FILE_PATH = settings.sip_log_file
    print(f"SIP HONEYPOT ACTIVE ON HOST: {args.host}, PORT: {args.port}")
    print(f"ALL SIP requests will be logged in: {LOG_FILE_PATH}")

    log_observer = log.FileLogObserver(open(LOG_FILE_PATH, "a"))
    log.startLoggingWithObserver(log_observer.emit, setStdout=False)

    if settings.sip_log_stdout:
        stdout_observer = log.FileLogObserver(sys.stdout)
        log.addObserver(stdout_observer.emit)

    metrics = None
    if settings.metrics_enabled:
        from metrics.db import MetricsDB
        from metrics.worker import MetricsWorker

        db = MetricsDB(
            settings.mysql_host,
            settings.mysql_port,
            settings.mysql_user,
            settings.mysql_password,
            settings.mysql_database,
        )

        firewall = None
        if settings.do_block_enabled:
            from metrics.dofirewall import DOFirewallClient
            from metrics.doblock import FanoutBlocker, ShardedFirewallBlocker

            if len(settings.do_firewall_ids) > 1:
                shards = [
                    DOFirewallClient(
                        settings.do_api_token,
                        fid,
                        base_url=settings.do_api_base_url,
                        timeout=settings.do_api_timeout,
                    )
                    for fid in settings.do_firewall_ids
                ]
                firewall = ShardedFirewallBlocker(shards)
            else:
                firewall = DOFirewallClient(
                    settings.do_api_token,
                    settings.do_firewall_ids[0],
                    base_url=settings.do_api_base_url,
                    timeout=settings.do_api_timeout,
                )

            if settings.do_load_balancer_ids:
                from metrics.doloadbalancer import DOLoadBalancerClient

                load_balancers = [
                    DOLoadBalancerClient(
                        settings.do_api_token,
                        lb_id,
                        base_url=settings.do_api_base_url,
                        timeout=settings.do_api_timeout,
                    )
                    for lb_id in settings.do_load_balancer_ids
                ]
                firewall = FanoutBlocker(firewall, load_balancers)

        worker = MetricsWorker(settings, db, firewall, log_fn=lambda m: reactor.callFromThread(log.msg, m))
        worker.start()
        reactor.addSystemEventTrigger("before", "shutdown", worker.stop)
        metrics = worker

        print(
            f"METRICS: enabled -> mysql://{settings.mysql_user}@{settings.mysql_host}:{settings.mysql_port}/{settings.mysql_database}"
        )
        if settings.do_block_enabled:
            firewall_label = (
                f"firewalls {', '.join(settings.do_firewall_ids)}"
                if len(settings.do_firewall_ids) > 1
                else f"firewall {settings.do_firewall_id}"
            )
            if settings.do_load_balancer_ids:
                print(
                    f"DO BLOCK: enabled ({firewall_label}, "
                    f"load balancers {', '.join(settings.do_load_balancer_ids)})"
                )
            else:
                print(f"DO BLOCK: enabled ({firewall_label})")
        else:
            print("DO BLOCK: disabled")
    else:
        print("METRICS: disabled (METRICS_ENABLED not set)")

    sip_protocol = SimpleSIPProtocol(user_agent=args.user_agent, metrics=metrics)
    reactor.listenUDP(args.port, sip_protocol, interface=args.host)
    reactor.run()


if __name__ == "__main__":
    main()
