#!/usr/bin/env python3
"""Backfill a DigitalOcean firewall's managed deny addresses into one or more load balancers."""

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from metrics.config import ConfigError, parse_firewall_ids, parse_load_balancer_ids  # noqa: E402
from metrics.dofirewall import DOFirewallClient  # noqa: E402
from metrics.doloadbalancer import DOLoadBalancerClient  # noqa: E402


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Copy a DigitalOcean firewall's managed deny addresses into one or more load balancers."
    )
    parser.add_argument("--firewall-id", default=None, help="DigitalOcean firewall ID (default: DO_FIREWALL_ID)")
    parser.add_argument(
        "--firewall-ids",
        default=None,
        help="Comma-separated DigitalOcean firewall IDs (default: DO_FIREWALL_IDS)",
    )
    parser.add_argument(
        "--load-balancer-ids",
        default=None,
        help="Comma-separated DigitalOcean load balancer IDs (default: DO_LOAD_BALANCER_IDS)",
    )
    parser.add_argument("--base-url", default=None, help="DigitalOcean API base URL (default: DO_API_BASE_URL)")
    parser.add_argument(
        "--timeout", type=float, default=None, help="API timeout in seconds (default: DO_API_TIMEOUT_SECONDS)"
    )
    parser.add_argument("--dry-run", action="store_true", help="Do not issue any PUT requests")
    parser.add_argument(
        "--show-payload", action="store_true", help="Print the PUT payload JSON for each LB that has changes"
    )
    return parser


def main(argv=None, environ=None) -> int:
    if environ is None:
        try:
            from dotenv import load_dotenv

            load_dotenv(REPO_ROOT / ".env", override=False)
        except ImportError:
            pass
        environ = os.environ

    parser = _build_parser()
    args = parser.parse_args(argv)

    token = environ.get("DO_API_TOKEN")
    firewall_id = args.firewall_id if args.firewall_id is not None else environ.get("DO_FIREWALL_ID")
    raw_firewall_ids = args.firewall_ids if args.firewall_ids is not None else environ.get("DO_FIREWALL_IDS")
    raw_lb_ids = args.load_balancer_ids if args.load_balancer_ids is not None else environ.get("DO_LOAD_BALANCER_IDS")
    base_url = (
        args.base_url if args.base_url is not None else environ.get("DO_API_BASE_URL", "https://api.digitalocean.com")
    )
    if args.timeout is not None:
        timeout = args.timeout
    else:
        raw_timeout = environ.get("DO_API_TIMEOUT_SECONDS")
        try:
            timeout = float(raw_timeout) if raw_timeout else 10.0
        except ValueError:
            print(
                f"ERROR: --timeout/DO_API_TIMEOUT_SECONDS must be a number, got: {raw_timeout!r}",
                file=sys.stderr,
            )
            return 2

    if not token:
        print("ERROR: DO_API_TOKEN is required (set it in the environment or .env)", file=sys.stderr)
        return 2

    try:
        firewall_ids = parse_firewall_ids(raw_firewall_ids)
    except ConfigError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    if not firewall_ids:
        if not firewall_id:
            print("ERROR: --firewall-id or DO_FIREWALL_ID is required", file=sys.stderr)
            return 2
        firewall_ids = (firewall_id,)

    try:
        lb_ids = parse_load_balancer_ids(raw_lb_ids)
    except ConfigError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    if not lb_ids:
        print(
            "ERROR: --load-balancer-ids or DO_LOAD_BALANCER_IDS must contain at least one load balancer ID",
            file=sys.stderr,
        )
        return 2

    addresses = []
    seen_addresses = set()
    for fw_id in firewall_ids:
        firewall_client = DOFirewallClient(token, fw_id, base_url=base_url, timeout=timeout)
        res, firewall = firewall_client.fetch()
        if not res.ok:
            print(f"ERROR: firewall {fw_id}: {res.error}", file=sys.stderr)
            return 1

        fw_addresses = DOFirewallClient.managed_deny_addresses(firewall)
        print(f"firewall {fw_id} ({firewall.get('name')}): {len(fw_addresses)} managed deny addresses")
        for addr in fw_addresses:
            if addr in seen_addresses:
                continue
            seen_addresses.add(addr)
            addresses.append(addr)

    if len(addresses) == 0:
        print("nothing to backfill")
        return 0

    failed = False
    updated_count = 0
    up_to_date_count = 0
    would_update_count = 0

    for lb_id in lb_ids:
        lb_client = DOLoadBalancerClient(token, lb_id, base_url=base_url, timeout=timeout)
        res, lb = lb_client.fetch()
        if not res.ok:
            print(f"LB {lb_id}: FAILED fetch: {res.error}")
            failed = True
            continue

        plan = DOLoadBalancerClient.plan_update(lb, addresses)
        if plan.error is not None:
            print(f"LB {lb_id}: FAILED plan: {plan.error}")
            failed = True
            continue

        existing_firewall = lb.get("firewall") if isinstance(lb, dict) else None
        existing_deny = existing_firewall.get("deny") if isinstance(existing_firewall, dict) else None
        existing_allow = existing_firewall.get("allow") if isinstance(existing_firewall, dict) else None
        existing_deny_len = len(existing_deny) if isinstance(existing_deny, list) else 0
        existing_allow_len = len(existing_allow) if isinstance(existing_allow, list) else 0

        print(
            f"LB {lb_id} ({lb['name']}): deny={existing_deny_len} allow={existing_allow_len} "
            f"(untouched) to_add={len(plan.added)}"
        )
        for entry in plan.added:
            print(f"  + {entry}")

        if args.show_payload and plan.added:
            print(json.dumps(plan.payload, indent=2))

        if not plan.added:
            print(f"LB {lb_id}: up to date")
            up_to_date_count += 1
            continue

        would_update_count += 1

        if args.dry_run:
            print(f"LB {lb_id}: DRY RUN, not writing")
            continue

        res = lb_client.update(plan.payload)
        if res.ok:
            print(f"LB {lb_id}: updated (HTTP {res.http_status}), added {len(plan.added)}")
            updated_count += 1
        else:
            print(f"LB {lb_id}: FAILED update: HTTP {res.http_status} {res.error}")
            failed = True

    if args.dry_run:
        failed_count = len(lb_ids) - would_update_count - up_to_date_count
        print(
            f"done: {would_update_count}/{len(lb_ids)} load balancers would update, "
            f"{failed_count} failed, {up_to_date_count} already up to date"
        )
    else:
        failed_count = len(lb_ids) - updated_count - up_to_date_count
        print(
            f"done: {updated_count}/{len(lb_ids)} load balancers updated, "
            f"{failed_count} failed, {up_to_date_count} already up to date"
        )

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
