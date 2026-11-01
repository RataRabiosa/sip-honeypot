import ipaddress

import pytest

from metrics.policy import is_blockable


@pytest.mark.parametrize(
    "ip",
    ["10.0.0.1", "127.0.0.1", "169.254.1.1", "fe80::1", "not-an-ip"],
)
def test_non_global_or_garbage_ips_are_never_blockable(ip):
    assert is_blockable(ip, []) is False


def test_public_ip_is_blockable():
    # NOTE: the spec example used 203.0.113.5 (RFC 5737 TEST-NET-3), but Python's
    # ipaddress.is_global treats documentation/reserved ranges as non-global
    # (is_private=True for that block), so it would incorrectly return False here.
    # 1.1.1.1 is used instead as a genuinely globally-routable address.
    assert is_blockable("1.1.1.1", []) is True


def test_public_ip_in_never_block_is_not_blockable():
    never_block = [ipaddress.ip_network("1.1.1.0/24")]
    assert is_blockable("1.1.1.1", never_block) is False


@pytest.mark.parametrize("ip", ["224.0.0.1", "239.1.2.3"])
def test_multicast_ips_are_never_blockable(ip):
    # ipaddress.ip_address(ip).is_global returns True for multicast addresses,
    # so is_blockable must explicitly exclude them.
    assert is_blockable(ip, []) is False
