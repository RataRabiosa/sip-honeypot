import ipaddress
from typing import Iterable


def is_blockable(ip: str, never_block: Iterable) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if not addr.is_global:
        return False
    if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return False
    for net in never_block:
        if addr in net:
            return False
    return True
