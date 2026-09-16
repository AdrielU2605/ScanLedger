"""Outbound CVE gateway boundary tests (PRD FR-05)."""

from __future__ import annotations

import pytest

from app.config import USER_AGENT
from app.services.outbound import DisallowedProviderHost, OutboundGateway


@pytest.fixture
def gateway() -> OutboundGateway:
    return OutboundGateway(user_agent=USER_AGENT)


@pytest.mark.parametrize(
    "url",
    [
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    ],
)
def test_allowlisted_providers_pass(gateway: OutboundGateway, url: str) -> None:
    assert gateway.check_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/cves",
        "https://nvd.nist.gov.attacker.example/rest",
        "https://10.10.0.5/cves",
        "https://127.0.0.1:8000/api",
    ],
)
def test_non_allowlisted_hosts_are_refused(gateway: OutboundGateway, url: str) -> None:
    with pytest.raises(DisallowedProviderHost):
        gateway.check_url(url)


def test_plain_http_is_refused(gateway: OutboundGateway) -> None:
    with pytest.raises(DisallowedProviderHost, match="https"):
        gateway.check_url("http://services.nvd.nist.gov/rest/json/cves/2.0")


def test_identifying_user_agent_is_sent(gateway: OutboundGateway) -> None:
    headers = gateway.headers()
    assert "ScanLedger" in headers["User-Agent"]
    assert "github.com" in headers["User-Agent"]


def test_redirects_are_off_by_default(gateway: OutboundGateway) -> None:
    assert gateway.follow_redirects is False
