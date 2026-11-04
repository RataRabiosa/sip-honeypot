# Simple SIP Honeypot Server

## Introduction
The Simple SIP Honeypot Server is an easy-to-use script created for cybersecurity practitioners and enthusiasts. Using Python and the Twisted framework, this script sets up a low-interaction Session Initiation Protocol (SIP) server to log SIP requests, acting as a vital tool for basic VoIP traffic analysis and early detection of potential threats in SIP-based communication systems.

## Features
- **Low-Interaction Honeypot**: Designed to mimic SIP services and capture SIP request details with minimal risk.
- **Customizable Server Settings**: Command-line arguments allow for easy configuration of host and port settings.
- **Detailed Logging**: Each SIP request is logged, providing insights for security analysis.
- **Real-time Interaction**: Responds to SIP requests, simulating a live SIP server environment.
- **Educational Tool**: An excellent resource for learning about SIP vulnerabilities and SIP-based attacks.
- **Raw Payload Telemetry**: Logs bounded raw UDP payload bytes (hex + \x format) with SHA256 to help identify malformed probes and potential zero-days.
- **Configurable SIP Fingerprint**: Set the `Server` header via a `--user-agent` CLI argument to emulate common SIP stacks and devices.
- **More Realistic SIP Behavior**: Implements common response patterns (e.g., INVITE flow, OPTIONS OK, REGISTER challenge/accept) and basic retransmit handling.
- **MySQL-Backed Metrics (optional)**: Every parsed SIP request can be recorded to MySQL (source IP, method, headers, timestamps) for longer-term analysis, in addition to the existing log file.
- **Web Dashboard (optional)**: A small Flask dashboard visualizes request volume, methods, and top source IPs from the metrics database.
- **Automatic DigitalOcean Firewall Blocking (optional)**: Scanning IPs can optionally be auto-blocked via the DigitalOcean Cloud Firewall API, with a local policy layer, retry/cooldown logic, and a safety cap.

## Requirements
- Python 3.x
- Twisted Python library
- Optional: MySQL, Docker/Docker Compose, and a DigitalOcean account/firewall if you use the metrics, dashboard, or auto-blocking features.

## Quick Start (Docker Compose, with metrics and dashboard)

The easiest way to run the honeypot with MySQL-backed metrics and the web dashboard is via Docker Compose:

```bash
git clone https://github.com/0xNslabs/sip-honeypot.git
cd sip-honeypot
cp .env.example .env
# edit .env: set real MySQL passwords, and optionally configure DigitalOcean blocking
docker compose up -d --build
```

This starts three services:
- `mysql`: stores request/source-IP/blocked-IP metrics (schema in `db/schema.sql`, applied automatically on first start).
- `honeypot`: the SIP honeypot itself, listening on UDP `5060` by default.
- `web`: the read-only dashboard, bound to `127.0.0.1:8080` by default (see "Web Dashboard" below).

### Environment variables

All variables are documented with comments in `.env.example`. Summary:

| Variable | Default | Purpose |
|---|---|---|
| `SIP_HOST` | `0.0.0.0` | Interface the SIP honeypot listens on. |
| `SIP_PORT` | `5060` | UDP port the SIP honeypot listens on. |
| `SIP_USER_AGENT` | `FRITZ!OS 1.0` | `Server` header value emulated in SIP responses. |
| `SIP_LOG_FILE` | `sip_honeypot.log` | Path to the honeypot's log file. |
| `SIP_LOG_STDOUT` | `false` | If true, also log to stdout (useful for `docker compose logs`). |
| `METRICS_ENABLED` | `false` | Enables recording every SIP request to MySQL and the dashboard/blocking features. |
| `MYSQL_ROOT_PASSWORD` | — | Root password for the `mysql` container (compose-only). |
| `MYSQL_HOST` | — | MySQL hostname. Required if `METRICS_ENABLED=true`. |
| `MYSQL_PORT` | `3306` | MySQL port. |
| `MYSQL_DATABASE` | `sip_honeypot` | MySQL database name. |
| `MYSQL_USER` | — | MySQL application user. Required if `METRICS_ENABLED=true`. |
| `MYSQL_PASSWORD` | — | MySQL application user's password. Required if `METRICS_ENABLED=true`. |
| `METRICS_QUEUE_SIZE` | `10000` | Max in-memory buffered metrics events before new ones are dropped. |
| `DO_BLOCK_ENABLED` | `false` | Enables automatic DigitalOcean firewall blocking. Requires `METRICS_ENABLED=true`. |
| `DO_API_TOKEN` | — | DigitalOcean API token with firewall write access. Required if `DO_BLOCK_ENABLED=true`. Keep secret. |
| `DO_FIREWALL_ID` | — | ID of the pre-existing DigitalOcean firewall whose honeypot-managed deny rule receives blocked IPs. Required if `DO_BLOCK_ENABLED=true`. |
| `DO_LOAD_BALANCER_IDS` | (empty) | Optional, comma-separated DigitalOcean load balancer IDs. Each one's `firewall.deny` is kept in sync with the honeypot's blocks; `firewall.allow` is never touched. |
| `DO_API_BASE_URL` | `https://api.digitalocean.com` | DigitalOcean API base URL (override for testing only). |
| `DO_API_TIMEOUT_SECONDS` | `10` | Timeout for DigitalOcean API calls. |
| `DO_NEVER_BLOCK` | (empty) | Comma-separated CIDR ranges that must never be auto-blocked. **Populate this with your own management/admin IPs before enabling blocking.** |
| `DO_RETRY_INTERVAL_SECONDS` | `300` | Minimum seconds between retrying a block attempt for the same IP. |
| `DO_FAILURE_COOLDOWN_SECONDS` | `60` | Seconds to pause all new block attempts after a DigitalOcean API failure. |
| `DO_MAX_BLOCKED_IPS` | `1000` | Local cap on the number of IPs this honeypot will block (counted from its own database). DigitalOcean separately caps addresses across all deny rules at 1,000 combined; the client refuses to exceed that remote limit. |
| `WEB_PORT` | `8080` | Port the dashboard listens on / is published as. |
| `WEB_BIND_HOST` | `127.0.0.1` | Host interface the dashboard port is published on. |
| `WEB_BASIC_AUTH_ENABLED` | `false` | Enables HTTP Basic Auth on the dashboard (additional layer, off by default). |
| `WEB_BASIC_AUTH_USERNAME` | — | Username required for Basic Auth. Required if `WEB_BASIC_AUTH_ENABLED=true`. |
| `WEB_BASIC_AUTH_PASSWORD` | — | Password required for Basic Auth. Required if `WEB_BASIC_AUTH_ENABLED=true`. Keep secret. |

## Installation (standalone, no Docker/metrics)

To run just the original standalone honeypot (no MySQL, no dashboard, no DigitalOcean integration — unchanged original behavior):

```bash
git clone https://github.com/0xNslabs/sip-honeypot.git
cd sip-honeypot
pip install -r requirements.txt
```

## Usage

Execute the script with optional arguments for host and port. Defaults to 0.0.0.0 (all interfaces) and port 5060.


```bash
python3 sip.py --host 0.0.0.0 --port 5060 --user-agent "Cisco/SPA8000-6.1.5"
```

With `METRICS_ENABLED=false` (the default, e.g. when no `.env` is present), this runs exactly as it always has: no MySQL connection is attempted and no metrics are recorded. Set `METRICS_ENABLED=true` (and the required `MYSQL_*` variables) in the environment or a `.env` file next to `sip.py` to enable metrics outside of Docker too.

## Logging

All SIP interactions are logged in sip_honeypot.log for further analysis and research.

In addition to parsed SIP headers, the honeypot logs bounded raw UDP payload telemetry (length, SHA256, and hex/byte-prefix) to help detect malformed packets and unusual payload shapes during mass-scans.

## Web Dashboard

When `METRICS_ENABLED=true`, a small Flask dashboard (`web/`) reads from the metrics database and shows request volume over time, methods seen, top source IPs, and the status of any DigitalOcean block attempts.

- Reach it at `http://127.0.0.1:8080/` (or whatever `WEB_PORT` you configured) after `docker compose up -d`.
- **The dashboard has no authentication and is bound to `127.0.0.1` (loopback only) by default.** This is a deliberate trade-off to keep the project simple, not an oversight: anyone who can reach the dashboard port can see all recorded request/source-IP/block data. If you need remote access, put it behind your own authenticating reverse proxy or SSH tunnel — do not change `WEB_BIND_HOST` to `0.0.0.0` or expose the port publicly without adding your own auth.
- **Optional HTTP Basic Auth**: set `WEB_BASIC_AUTH_ENABLED=true` along with `WEB_BASIC_AUTH_USERNAME` and `WEB_BASIC_AUTH_PASSWORD` to require a single shared username/password to access every route (`/` and `/healthz`). This is an additional, opt-in layer on top of the loopback-binding default above — the dashboard still has no auth by default unless you set these. Basic Auth credentials are base64-encoded on the wire, not encrypted, so this is defense-in-depth, not a substitute for TLS if the dashboard is ever exposed beyond localhost (e.g. via a reverse proxy, which would be the right place to add HTTPS).

## DigitalOcean Automatic Blocking

When `DO_BLOCK_ENABLED=true` (and `METRICS_ENABLED=true`), the honeypot's metrics worker thread will, on first seeing a new globally-routable source IP, call the DigitalOcean Cloud Firewall API to block it. The honeypot maintains a single managed deny rule (`protocol=all`, all ports) on the firewall identified by `DO_FIREWALL_ID`; each newly blocked IP is appended to that rule's address list by reading the firewall (`GET`) and writing it back (`PUT`) with the IP added. A new managed rule is created only if none exists yet. State (pending/blocked/failed, attempts, last error) is tracked in the `blocked_ips` table and visible on the dashboard.

Existing deployments upgrading from the older one-rule-per-IP behavior need no manual migration: the first pre-existing rule matching the managed shape (`protocol=all`, all ports, `action=deny`) is adopted as the managed rule automatically, and new IPs are appended to it. Other legacy per-IP rules are left alone and can optionally be consolidated by hand later.

**Security warning: UDP source IPs can be spoofed.** SIP honeypot traffic arrives over UDP, and UDP source addresses are trivially forgeable. A block decision based solely on the apparent source IP of a UDP packet is **not** proof that IP actually sent the traffic — it could be collateral damage from a spoofed-source flood or reflection attack aimed at a third party. Treat auto-blocking as a best-effort noise-reduction measure, not an attribution or law-enforcement-grade signal.

Before enabling `DO_BLOCK_ENABLED`:
- Populate `DO_NEVER_BLOCK` with your own management/admin IP ranges (and any other IPs you never want blocked) so a spoofed or legitimate packet from your own infrastructure can never be firewalled off.
- DigitalOcean caps firewalls at 50 total rule objects and at 1,000 addresses combined across deny rules. This honeypot packs IPs into one managed rule specifically to stay within the 1,000-address ceiling instead of the 50-rule-object one — it is still not an unlimited blocklist. `DO_MAX_BLOCKED_IPS` and the remote 1,000-address cap are independent: hitting either one stops new blocks (visible as `LOCAL_CAP_REACHED` or `REMOTE_CAP_REACHED` in the dashboard/last_error).
- This feature assumes a DigitalOcean firewall already exists (identified by `DO_FIREWALL_ID`); it does not create or provision firewall resources.
- Only one honeypot process should manage a given `DO_FIREWALL_ID` at a time. Manual edits to that firewall made in the DigitalOcean console/`doctl` while the honeypot is actively blocking may be overwritten, since each update reads and rewrites the whole firewall object.
- There is no automatic unblocking or TTL — blocked IPs stay blocked until removed manually from the honeypot-managed rule's address list on the DigitalOcean firewall. Removing an IP that way does not reset that IP's `blocked` status in the honeypot's own database.

### Mirroring blocks to load balancers

Setting `DO_LOAD_BALANCER_IDS` (comma-separated) is entirely opt-in: leaving it empty keeps today's behavior unchanged — only the firewall is touched. When set, each successful firewall block is also mirrored into every listed load balancer's `firewall.deny` list; `firewall.allow` is never written to on any load balancer. Ordering is firewall-first and fail-fast: the firewall is updated first, and the load balancers are only attempted if that succeeds (including the "already blocked" case); the first load balancer failure stops the rest from being attempted that cycle (the retry sweep will pick them up again later). A load balancer failure surfaces in the dashboard/`last_error` as `LB <id>: <error>`. There is no separate size limit on a load balancer's deny list — it is bounded only indirectly, by the existing `DO_MAX_BLOCKED_IPS`/firewall caps upstream. `DO_LOAD_BALANCER_IDS` has no effect unless `DO_BLOCK_ENABLED=true` is also set, since mirroring only runs as part of the same blocking pipeline. A persistent failure on just one load balancer will show that IP as `failed` in the dashboard even though the firewall block itself succeeded; the background retry sweep picks it up automatically, so this is expected, self-healing behavior rather than a bug.

When first enabling `DO_LOAD_BALANCER_IDS` on a honeypot that has already blocked IPs, run `scripts/backfill_lb_deny.py` once to copy every address already in the firewall's managed deny rule(s) into the newly configured load balancers (new blocks going forward are mirrored automatically; this script only catches up on history). Try `--dry-run` first to preview what would change before writing anything.

**Unconfirmed assumption:** the load balancer `PUT` is assumed to carry forward every field from the `GET` response unchanged except the known read-only fields and the region/droplet_ids/tag transforms (the same full-replace pattern already used for the Firewalls product) — this has not been validated against a real DigitalOcean account. Before enabling this in production, run `scripts/backfill_lb_deny.py --dry-run --show-payload` and review one load balancer's payload.

## Running the Test Suite

The test suite is pure unit tests (no real network, MySQL, or Twisted reactor required):

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest tests -q
```

Formatting for the new `metrics/`, `web/`, `tests/`, and `scripts/` code is checked with Black (`sip.py` itself is intentionally left out of this check):

```bash
.venv/bin/black --check metrics web tests scripts
```

## Simple SIP Honeypot In Action

![Simple SIP Honeypot in Action](https://raw.githubusercontent.com/0xNslabs/sip-honeypot/main/PoC.png)
*The image above captures the Simple SIP Honeypot logging real-time SIP queries*

## Other Simple Honeypot Services

Check out the other honeypot services for monitoring various network protocols:

- [DNS Honeypot](https://github.com/0xNslabs/dns-honeypot) - Monitors DNS interactions.
- [FTP Honeypot](https://github.com/0xNslabs/ftp-honeypot) - Simulates an FTP server.
- [LDAP Honeypot](https://github.com/0xNslabs/ldap-honeypot) - Mimics an LDAP server.
- [HTTP Honeypot](https://github.com/0xNslabs/http-honeypot) - Monitors HTTP interactions.
- [HTTPS Honeypot](https://github.com/0xNslabs/https-honeypot) - Monitors HTTPS interactions.
- [MongoDB Honeypot](https://github.com/0xNslabs/mongodb-honeypot) - Simulates a MongoDB database server.
- [NTP Honeypot](https://github.com/0xNslabs/ntp-honeypot) - Monitors Network Time Protocol interactions.
- [PostgreSQL Honeypot](https://github.com/0xNslabs/postgresql-honeypot) - Simulates a PostgreSQL database server.
- [SIP Honeypot](https://github.com/0xNslabs/sip-honeypot) - Monitors SIP (Session Initiation Protocol) interactions.
- [SSH Honeypot](https://github.com/0xNslabs/ssh-honeypot) - Emulates an SSH server.
- [TELNET Honeypot](https://github.com/0xNslabs/telnet-honeypot) - Simulates a TELNET server.

## Security and Compliance
- **Caution**: This server is a honeypot. Employ responsibly in controlled network environments.
- **Compliance**: Adhere to local laws and regulations in deployment.

## License
This project is distributed under the MIT License. See `LICENSE` for more information.
