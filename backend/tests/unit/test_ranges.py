"""Address classification tests - the constants ScanGuard is built on."""

from __future__ import annotations

import ipaddress

import pytest

from app.guard.ranges import (
    allowed_ranges_for,
    check_prefix_breadth,
    is_always_denied,
    network_always_denied,
    network_within_allowed,
)


@pytest.mark.parametrize(
    ("address", "expected_reason"),
    [
        ("8.8.8.8", "public/globally routable address"),
        ("1.1.1.1", "public/globally routable address"),
        ("169.254.169.254", "cloud-metadata address"),
        ("fd00:ec2::254", "cloud-metadata address"),
        ("224.0.0.1", "multicast address"),
        ("ff02::1", "multicast address"),
        ("255.255.255.255", "broadcast address"),
        ("0.0.0.0", "unspecified address"),
        ("::", "unspecified address"),
        ("192.0.2.5", "documentation/example address"),
        ("198.51.100.5", "documentation/example address"),
        ("203.0.113.5", "documentation/example address"),
    ],
)
def test_always_denied_addresses(address: str, expected_reason: str) -> None:
    assert is_always_denied(ipaddress.ip_address(address)) == expected_reason


@pytest.mark.parametrize(
    "address",
    ["10.0.0.5", "172.16.4.1", "192.168.1.10", "127.0.0.1", "::1", "fd12:3456::1"],
)
def test_private_addresses_are_not_always_denied(address: str) -> None:
    assert is_always_denied(ipaddress.ip_address(address)) is None


def test_cloud_metadata_denied_even_though_it_is_link_local() -> None:
    """169.254.169.254 sits inside the opt-in link-local range and must still lose."""
    metadata = ipaddress.ip_address("169.254.169.254")
    allowed = allowed_ranges_for(allow_link_local=True)

    assert any(metadata in network for network in allowed)
    assert is_always_denied(metadata) == "cloud-metadata address"


def test_opt_in_ranges_are_off_by_default() -> None:
    default = allowed_ranges_for()
    cgnat = ipaddress.ip_address("100.64.0.1")
    link_local = ipaddress.ip_address("169.254.10.10")

    assert not any(cgnat in network for network in default)
    assert not any(link_local in network for network in default)
    assert any(cgnat in network for network in allowed_ranges_for(allow_cgnat=True))
    assert any(link_local in network for network in allowed_ranges_for(allow_link_local=True))


@pytest.mark.parametrize(
    ("network", "expected_reason"),
    [
        ("8.8.8.0/24", "public/globally routable range"),
        ("169.254.169.254/32", "overlaps the cloud-metadata address"),
        ("169.254.169.0/24", "overlaps the cloud-metadata address"),
        ("224.0.0.0/24", "multicast range"),
        ("192.0.2.0/24", "overlaps a documentation/example range"),
    ],
)
def test_always_denied_networks(network: str, expected_reason: str) -> None:
    assert network_always_denied(ipaddress.ip_network(network)) == expected_reason


@pytest.mark.parametrize("network", ["10.0.0.0/24", "192.168.1.0/24", "127.0.0.0/24"])
def test_private_networks_are_not_always_denied(network: str) -> None:
    assert network_always_denied(ipaddress.ip_network(network)) is None


def test_network_within_allowed_requires_full_containment() -> None:
    allowed = allowed_ranges_for()

    assert network_within_allowed(ipaddress.ip_network("10.1.2.0/24"), allowed)
    assert not network_within_allowed(ipaddress.ip_network("100.64.0.0/16"), allowed)
    assert network_within_allowed(
        ipaddress.ip_network("100.64.0.0/16"), allowed_ranges_for(allow_cgnat=True)
    )


@pytest.mark.parametrize(
    ("network", "rejected"),
    [
        ("10.0.0.0/8", True),
        ("10.0.0.0/15", True),
        ("10.0.0.0/16", False),
        ("10.0.0.0/24", False),
        ("10.0.0.5/32", False),
        ("fd00::/48", True),
        ("fd00::/64", False),
        ("fd00::1/128", False),
    ],
)
def test_cidr_breadth_limits(network: str, rejected: bool) -> None:
    problem = check_prefix_breadth(ipaddress.ip_network(network))
    assert (problem is not None) is rejected
