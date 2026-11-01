#!/usr/bin/env python3
"""Stdlib-only UDP probe client for the SIP honeypot.

Builds a minimal, well-formed SIP request (OPTIONS/REGISTER/INVITE), sends it
over UDP, and prints whatever response packet(s) arrive before a timeout.
"""

import argparse
import random
import socket
import sys
import time


def build_sip_request(method, host, port, local_host="127.0.0.1", local_port=5061, call_id=None, branch=None):
    """Build a minimal valid SIP request as raw bytes.

    Shared between this probe script and tests/test_sip_hook.py so both stay
    consistent with what the honeypot (and Twisted's sip.Base parser) expect.
    """
    call_id = call_id or f"{random.getrandbits(32):x}@{local_host}"
    branch = branch or f"z9hG4bK{random.getrandbits(32):x}"
    tag = f"{random.getrandbits(32):x}"

    lines = [
        f"{method} sip:service@{host}:{port} SIP/2.0",
        f"Via: SIP/2.0/UDP {local_host}:{local_port};branch={branch}",
        f"From: <sip:probe@{local_host}>;tag={tag}",
        f"To: <sip:service@{host}>",
        f"Call-ID: {call_id}",
        "CSeq: 1 " + method,
        "Max-Forwards: 70",
        "Contact: <sip:probe@" + local_host + ":" + str(local_port) + ">",
        "Content-Length: 0",
        "",
        "",
    ]
    return "\r\n".join(lines).encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description="Send a minimal SIP probe request over UDP.")
    parser.add_argument("--host", default="127.0.0.1", help="Target host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5060, help="Target port (default: 5060)")
    parser.add_argument(
        "--method",
        default="OPTIONS",
        choices=["OPTIONS", "REGISTER", "INVITE"],
        help="SIP method to send (default: OPTIONS)",
    )
    args = parser.parse_args()

    packet = build_sip_request(args.method, args.host, args.port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    try:
        sock.sendto(packet, (args.host, args.port))

        received_any = False
        deadline = time.monotonic() + 2.0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                break
            received_any = True
            print(f"--- response from {addr} ---")
            print(data.decode("utf-8", "replace"))

        if not received_any:
            print("No response received before timeout.", file=sys.stderr)
            sys.exit(1)
    finally:
        sock.close()


if __name__ == "__main__":
    main()
