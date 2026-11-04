import pytest

from metrics.config import ConfigError, load_settings, parse_load_balancer_ids


def test_defaults_minimal_environ(tmp_path):
    settings = load_settings(str(tmp_path), environ={})
    assert settings.sip_host == "0.0.0.0"
    assert settings.sip_port == 5060
    assert settings.sip_user_agent == "FRITZ!OS 1.0"
    assert settings.sip_log_file == str(tmp_path / "sip_honeypot.log")
    assert settings.sip_log_stdout is False
    assert settings.metrics_enabled is False
    assert settings.mysql_host is None
    assert settings.mysql_port == 3306
    assert settings.mysql_database == "sip_honeypot"
    assert settings.metrics_queue_size == 10000
    assert settings.do_block_enabled is False
    assert settings.do_api_base_url == "https://api.digitalocean.com"
    assert settings.do_api_timeout == 10
    assert settings.do_never_block == ()
    assert settings.do_retry_interval == 300
    assert settings.do_failure_cooldown == 60
    assert settings.do_max_blocked_ips == 1000
    assert settings.do_load_balancer_ids == ()


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("1", True),
        ("true", True),
        ("True", True),
        ("YES", True),
        ("on", True),
        (" on ", True),
        ("0", False),
        ("false", False),
        ("no", False),
        ("off", False),
        ("garbage", False),
        ("", False),
    ],
)
def test_bool_parsing_variants(tmp_path, raw, expected):
    settings = load_settings(str(tmp_path), environ={"SIP_LOG_STDOUT": raw})
    assert settings.sip_log_stdout is expected


def test_bool_default_used_when_unset(tmp_path):
    settings = load_settings(str(tmp_path), environ={})
    assert settings.sip_log_stdout is False


def test_metrics_enabled_requires_mysql_vars(tmp_path):
    with pytest.raises(ConfigError):
        load_settings(str(tmp_path), environ={"METRICS_ENABLED": "true"})

    with pytest.raises(ConfigError):
        load_settings(
            str(tmp_path),
            environ={"METRICS_ENABLED": "true", "MYSQL_HOST": "db", "MYSQL_USER": "u"},
        )


def test_metrics_enabled_succeeds_with_required_vars(tmp_path):
    settings = load_settings(
        str(tmp_path),
        environ={
            "METRICS_ENABLED": "true",
            "MYSQL_HOST": "db",
            "MYSQL_USER": "u",
            "MYSQL_PASSWORD": "",
        },
    )
    assert settings.metrics_enabled is True
    assert settings.mysql_host == "db"
    assert settings.mysql_password == ""


def test_do_block_enabled_without_token_or_firewall_id_raises(tmp_path):
    base_env = {
        "METRICS_ENABLED": "true",
        "MYSQL_HOST": "db",
        "MYSQL_USER": "u",
        "MYSQL_PASSWORD": "pw",
        "DO_BLOCK_ENABLED": "true",
    }
    with pytest.raises(ConfigError):
        load_settings(str(tmp_path), environ=dict(base_env))

    with_token = dict(base_env)
    with_token["DO_API_TOKEN"] = "tok"
    with pytest.raises(ConfigError):
        load_settings(str(tmp_path), environ=with_token)

    with_both = dict(base_env)
    with_both["DO_API_TOKEN"] = "tok"
    with_both["DO_FIREWALL_ID"] = "fw-1"
    settings = load_settings(str(tmp_path), environ=with_both)
    assert settings.do_block_enabled is True


def test_do_block_enabled_requires_metrics_enabled(tmp_path):
    with pytest.raises(ConfigError):
        load_settings(
            str(tmp_path),
            environ={
                "DO_BLOCK_ENABLED": "true",
                "DO_API_TOKEN": "tok",
                "DO_FIREWALL_ID": "fw-1",
            },
        )
    with pytest.raises(ConfigError):
        load_settings(
            str(tmp_path),
            environ={
                "METRICS_ENABLED": "false",
                "DO_BLOCK_ENABLED": "true",
                "DO_API_TOKEN": "tok",
                "DO_FIREWALL_ID": "fw-1",
            },
        )


def test_invalid_do_never_block_entry_raises(tmp_path):
    with pytest.raises(ConfigError) as exc_info:
        load_settings(str(tmp_path), environ={"DO_NEVER_BLOCK": "10.0.0.0/8,not-an-ip"})
    assert "not-an-ip" in str(exc_info.value)


def test_do_never_block_parses_and_skips_blank_entries(tmp_path):
    settings = load_settings(str(tmp_path), environ={"DO_NEVER_BLOCK": "10.0.0.0/8,, 192.168.1.0/24 ,"})
    assert len(settings.do_never_block) == 2


def test_invalid_sip_port_raises(tmp_path):
    with pytest.raises(ConfigError):
        load_settings(str(tmp_path), environ={"SIP_PORT": "not-a-number"})
    with pytest.raises(ConfigError):
        load_settings(str(tmp_path), environ={"SIP_PORT": "0"})
    with pytest.raises(ConfigError):
        load_settings(str(tmp_path), environ={"SIP_PORT": "70000"})


def test_do_load_balancer_ids_default_empty(tmp_path):
    settings = load_settings(str(tmp_path), environ={})
    assert settings.do_load_balancer_ids == ()


def test_do_load_balancer_ids_parses_whitespace_and_blank_entries_preserving_order(tmp_path):
    settings = load_settings(
        str(tmp_path),
        environ={"DO_LOAD_BALANCER_IDS": " lb-1 ,lb-2,, lb-3 ,"},
    )
    assert settings.do_load_balancer_ids == ("lb-1", "lb-2", "lb-3")


def test_do_load_balancer_ids_duplicate_entry_raises(tmp_path):
    with pytest.raises(ConfigError) as exc_info:
        load_settings(str(tmp_path), environ={"DO_LOAD_BALANCER_IDS": "lb-1,lb-2,lb-1"})
    assert "DO_LOAD_BALANCER_IDS contains a duplicate entry: 'lb-1'" in str(exc_info.value)


def test_do_load_balancer_ids_accepted_when_do_block_disabled(tmp_path):
    settings = load_settings(str(tmp_path), environ={"DO_LOAD_BALANCER_IDS": "lb-1"})
    assert settings.do_block_enabled is False
    assert settings.do_load_balancer_ids == ("lb-1",)


def test_parse_load_balancer_ids_none_and_empty():
    assert parse_load_balancer_ids(None) == ()
    assert parse_load_balancer_ids("") == ()


def test_parse_load_balancer_ids_strips_and_skips_blanks_preserving_order():
    assert parse_load_balancer_ids(" a , b ,,c ,") == ("a", "b", "c")


def test_parse_load_balancer_ids_duplicate_raises():
    with pytest.raises(ConfigError):
        parse_load_balancer_ids("a,b,a")
