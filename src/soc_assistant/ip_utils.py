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


def classify_source_ip(value):
    """Classify an IP address without assigning security intent."""
    from ipaddress import ip_address, ip_network

    if not isinstance(value, str):
        return "invalid"

    try:
        address = ip_address(value.strip())
    except ValueError:
        return "invalid"

    if getattr(address, "ipv4_mapped", None):
        address = address.ipv4_mapped

    documentation_networks = (
        ip_network("192.0.2.0/24"),
        ip_network("198.51.100.0/24"),
        ip_network("203.0.113.0/24"),
        ip_network("2001:db8::/32"),
    )

    if address.is_loopback:
        return "loopback"

    if address.is_unspecified:
        return "unspecified"

    if any(address in network for network in documentation_networks):
        return "documentation"

    if address.is_link_local:
        return "link_local"

    if address.is_multicast:
        return "multicast"

    if address.is_private:
        return "private"

    if address.is_global:
        return "public"

    return "reserved"
