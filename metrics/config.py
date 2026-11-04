from __future__ import annotations

import dataclasses
import ipaddress
import os
from typing import Mapping, Optional, Tuple, Union


class ConfigError(Exception):
    pass


IPNet = Union["ipaddress.IPv4Network", "ipaddress.IPv6Network"]


@dataclasses.dataclass(frozen=True)
class Settings:
    sip_host: str
    sip_port: int
    sip_user_agent: str
    sip_log_file: str
    sip_log_stdout: bool
    metrics_enabled: bool
    mysql_host: Optional[str]
    mysql_port: int
    mysql_database: str
    mysql_user: Optional[str]
    mysql_password: Optional[str]
    metrics_queue_size: int
    do_block_enabled: bool
    do_api_token: Optional[str]
    do_firewall_id: Optional[str]
    do_load_balancer_ids: Tuple[str, ...]
    do_api_base_url: str
    do_api_timeout: float
    do_never_block: Tuple[IPNet, ...]
    do_retry_interval: float
    do_failure_cooldown: float
    do_max_blocked_ips: int


def _get_bool(environ: Mapping[str, str], key: str, default: bool) -> bool:
    raw = environ.get(key)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _get_str(environ: Mapping[str, str], key: str, default: Optional[str]) -> Optional[str]:
    if key not in environ:
        return default
    return environ[key]


def _get_int(environ: Mapping[str, str], key: str, default: int) -> int:
    raw = environ.get(key)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw.strip())
    except ValueError:
        raise ConfigError(f"{key} must be an integer, got: {raw!r}")


def _get_float(environ: Mapping[str, str], key: str, default: float) -> float:
    raw = environ.get(key)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw.strip())
    except ValueError:
        raise ConfigError(f"{key} must be a number, got: {raw!r}")


def parse_load_balancer_ids(raw: Optional[str]) -> Tuple[str, ...]:
    if not raw:
        return ()
    ids = []
    seen = set()
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if entry in seen:
            raise ConfigError(f"DO_LOAD_BALANCER_IDS contains a duplicate entry: {entry!r}")
        seen.add(entry)
        ids.append(entry)
    return tuple(ids)


def load_settings(script_dir: str, environ: Optional[Mapping[str, str]] = None) -> Settings:
    if environ is None:
        from dotenv import load_dotenv

        load_dotenv(os.path.join(script_dir, ".env"), override=False)
        environ = os.environ

    sip_host = _get_str(environ, "SIP_HOST", "0.0.0.0")

    sip_port = _get_int(environ, "SIP_PORT", 5060)
    if not (1 <= sip_port <= 65535):
        raise ConfigError(f"SIP_PORT must be between 1 and 65535, got: {sip_port}")

    sip_user_agent = _get_str(environ, "SIP_USER_AGENT", "FRITZ!OS 1.0")

    sip_log_file = _get_str(environ, "SIP_LOG_FILE", os.path.join(script_dir, "sip_honeypot.log"))
    sip_log_stdout = _get_bool(environ, "SIP_LOG_STDOUT", False)

    metrics_enabled = _get_bool(environ, "METRICS_ENABLED", False)

    mysql_host = _get_str(environ, "MYSQL_HOST", None)
    if metrics_enabled and not mysql_host:
        raise ConfigError("MYSQL_HOST is required when METRICS_ENABLED is true")

    mysql_port = _get_int(environ, "MYSQL_PORT", 3306)

    mysql_database = _get_str(environ, "MYSQL_DATABASE", "sip_honeypot")

    mysql_user = _get_str(environ, "MYSQL_USER", None)
    if metrics_enabled and not mysql_user:
        raise ConfigError("MYSQL_USER is required when METRICS_ENABLED is true")

    if metrics_enabled and "MYSQL_PASSWORD" not in environ:
        raise ConfigError("MYSQL_PASSWORD is required when METRICS_ENABLED is true")
    mysql_password = _get_str(environ, "MYSQL_PASSWORD", None)

    metrics_queue_size = _get_int(environ, "METRICS_QUEUE_SIZE", 10000)
    if metrics_queue_size < 100:
        raise ConfigError(f"METRICS_QUEUE_SIZE must be >= 100, got: {metrics_queue_size}")

    do_block_enabled = _get_bool(environ, "DO_BLOCK_ENABLED", False)
    if do_block_enabled and not metrics_enabled:
        raise ConfigError("DO_BLOCK_ENABLED requires METRICS_ENABLED to be true")

    do_api_token = _get_str(environ, "DO_API_TOKEN", None)
    if do_block_enabled and not do_api_token:
        raise ConfigError("DO_API_TOKEN is required when DO_BLOCK_ENABLED is true")

    do_firewall_id = _get_str(environ, "DO_FIREWALL_ID", None)
    if do_block_enabled and not do_firewall_id:
        raise ConfigError("DO_FIREWALL_ID is required when DO_BLOCK_ENABLED is true")

    raw_load_balancer_ids = _get_str(environ, "DO_LOAD_BALANCER_IDS", "")
    do_load_balancer_ids = parse_load_balancer_ids(raw_load_balancer_ids)

    do_api_base_url = (_get_str(environ, "DO_API_BASE_URL", "https://api.digitalocean.com") or "").rstrip("/")

    do_api_timeout = _get_float(environ, "DO_API_TIMEOUT_SECONDS", 10)
    if not (1 <= do_api_timeout <= 60):
        raise ConfigError(f"DO_API_TIMEOUT_SECONDS must be between 1 and 60, got: {do_api_timeout}")

    raw_never_block = _get_str(environ, "DO_NEVER_BLOCK", "") or ""
    never_block = []
    for entry in raw_never_block.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            never_block.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            raise ConfigError(f"DO_NEVER_BLOCK contains an invalid network: {entry!r}")

    do_retry_interval = _get_float(environ, "DO_RETRY_INTERVAL_SECONDS", 300)
    do_failure_cooldown = _get_float(environ, "DO_FAILURE_COOLDOWN_SECONDS", 60)

    do_max_blocked_ips = _get_int(environ, "DO_MAX_BLOCKED_IPS", 1000)
    if do_max_blocked_ips < 1:
        raise ConfigError(f"DO_MAX_BLOCKED_IPS must be >= 1, got: {do_max_blocked_ips}")

    return Settings(
        sip_host=sip_host,
        sip_port=sip_port,
        sip_user_agent=sip_user_agent,
        sip_log_file=sip_log_file,
        sip_log_stdout=sip_log_stdout,
        metrics_enabled=metrics_enabled,
        mysql_host=mysql_host,
        mysql_port=mysql_port,
        mysql_database=mysql_database,
        mysql_user=mysql_user,
        mysql_password=mysql_password,
        metrics_queue_size=metrics_queue_size,
        do_block_enabled=do_block_enabled,
        do_api_token=do_api_token,
        do_firewall_id=do_firewall_id,
        do_load_balancer_ids=do_load_balancer_ids,
        do_api_base_url=do_api_base_url,
        do_api_timeout=do_api_timeout,
        do_never_block=tuple(never_block),
        do_retry_interval=do_retry_interval,
        do_failure_cooldown=do_failure_cooldown,
        do_max_blocked_ips=do_max_blocked_ips,
    )
