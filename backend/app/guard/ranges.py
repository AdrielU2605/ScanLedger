"""Code-defined network range constants for ScanGuard.

These are compile-time constants. No user input, scope profile, config file, or
API request may add to, remove from, or override anything in this module
(PRD 8.1: "the allowed private ranges are code-defined constants").

Two independent checks exist here:

* ``is_always_denied`` / ``network_always_denied`` - destinations that are
  refused no matter what a scope profile says, including a mis-configured one.
* ``allowed_ranges_for`` - the private ranges a scope profile is permitted to
  draw its entries from.

A destination must clear BOTH (not always-denied, and inside an allowed range)
before ScanGuard will even consider it against the active scope profile.
"""

from __future__ import annotations

import ipaddress

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Private ranges every scope profile may draw from (PRD 4.4).
BASE_ALLOWED_RANGES: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)

# Off by default; a scope profile may opt in to these explicitly (PRD 4.4).
CGNAT_RANGE: IPNetwork = ipaddress.ip_network("100.64.0.0/10")
LINK_LOCAL_RANGES: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
)

# The cloud-metadata address stays denied even when a profile opts in to
# link-local, which is why it is checked before any allowed-range membership.
CLOUD_METADATA_NETWORKS: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("fd00:ec2::254/128"),
)

DOCUMENTATION_RANGES: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)

LIMITED_BROADCAST: IPAddress = ipaddress.ip_address("255.255.255.255")

# MVP CIDR breadth limits (PRD 4.4).
MIN_IPV4_PREFIX_LENGTH = 16
MIN_IPV6_PREFIX_LENGTH = 64


def allowed_ranges_for(
    *, allow_cgnat: bool = False, allow_link_local: bool = False
) -> tuple[IPNetwork, ...]:
    """Return the private ranges a profile with these opt-ins may draw from."""
    ranges: list[IPNetwork] = list(BASE_ALLOWED_RANGES)
    if allow_cgnat:
        ranges.append(CGNAT_RANGE)
    if allow_link_local:
        ranges.extend(LINK_LOCAL_RANGES)
    return tuple(ranges)


def is_always_denied(address: IPAddress) -> str | None:
    """Return why *address* is unconditionally denied, or None if it is not.

    A None result does NOT mean the address is allowed - it only means this
    address is not forbidden outright. Scope membership is checked separately.
    """
    if any(address in network for network in CLOUD_METADATA_NETWORKS):
        return "cloud-metadata address"
    if address.is_multicast:
        return "multicast address"
    if address == LIMITED_BROADCAST:
        return "broadcast address"
    if address.is_unspecified:
        return "unspecified address"
    if any(address in network for network in DOCUMENTATION_RANGES):
        return "documentation/example address"
    if address.is_global:
        return "public/globally routable address"
    return None


def network_always_denied(network: IPNetwork) -> str | None:
    """Return why *network* is unconditionally denied, or None if it is not.

    Overlap (not containment) is used deliberately: a CIDR that touches an
    always-denied range anywhere is refused whole rather than partially scanned.
    """
    for denied in CLOUD_METADATA_NETWORKS:
        if network.version == denied.version and network.overlaps(denied):
            return "overlaps the cloud-metadata address"
    if network.is_multicast:
        return "multicast range"
    if network.version == 4 and network.overlaps(ipaddress.ip_network("255.255.255.255/32")):
        return "includes the broadcast address"
    if network.is_unspecified:
        return "unspecified address range"
    for denied in DOCUMENTATION_RANGES:
        if network.version == denied.version and network.overlaps(denied):
            return "overlaps a documentation/example range"
    if network.is_global:
        return "public/globally routable range"
    return None


def network_within_allowed(network: IPNetwork, allowed: tuple[IPNetwork, ...]) -> bool:
    """True only if every address in *network* falls inside one allowed range.

    Containment is proven algebraically with ``subnet_of`` rather than by
    enumerating members: for IPv4 the two are equivalent, and for IPv6 a /64
    cannot be enumerated at all. The guarantee the PRD asks for - that no
    member of the CIDR is out of scope before the first packet - is the same.
    """
    return any(
        network.version == candidate.version and network.subnet_of(candidate)  # type: ignore[arg-type]
        for candidate in allowed
    )


def check_prefix_breadth(network: IPNetwork) -> str | None:
    """Return why *network* is too broad for the MVP, or None if acceptable."""
    if network.version == 4 and network.prefixlen < MIN_IPV4_PREFIX_LENGTH:
        return (
            f"/{network.prefixlen} is broader than the MVP limit of "
            f"/{MIN_IPV4_PREFIX_LENGTH} for IPv4"
        )
    if network.version == 6 and network.prefixlen < MIN_IPV6_PREFIX_LENGTH:
        return (
            f"/{network.prefixlen} is broader than the MVP limit of "
            f"/{MIN_IPV6_PREFIX_LENGTH} for IPv6"
        )
    return None
