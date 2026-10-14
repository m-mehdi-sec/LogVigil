"""Utilities for validating source IP addresses."""

from ipaddress import ip_address


def is_usable_source_ip(value):
    """Return whether an IP can identify a non-loopback source."""
    if not isinstance(value, str):
        return False

    try:
        address = ip_address(value.strip())
    except ValueError:
        return False

    return not (address.is_loopback or address.is_unspecified)
