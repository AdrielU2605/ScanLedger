"""CVE correlation tests (PRD FR-09, 10.2 required module cases).

Provider responses are mocked throughout: CI performs no live network calls,
and the shapes below were copied from the real NVD and CISA payloads verified
on 2026-11-18.

The cases that matter most are the honest-reporting ones - missing NVD
enrichment, an empty result, and a provider failure - because each is a way a
scanner can quietly tell a user they are safe when it simply does not know.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.guard.ledger import InMemoryLedger
from app.guard.scanguard import ScanGuard, ScopeProfile
from app.models.domain import Confidence, FindingCategory
from app.models.findings import Finding
from app.modules.base import ModuleContext
from app.modules.cpe import cpe_for, normalize_version
from app.modules.cve_correlate import CveCorrelateModule, services_from_findings
from app.scan.governor import IntensityGovernor
from app.services.cache import ResponseCache
from app.services.outbound import (
    OutboundGateway,
    ProviderRateLimited,
    ProviderResponse,
    ProviderUnavailable,
)
from app.services.providers.kev import KEV_URL
from app.services.providers.nvd import NVD_CVE_URL


def nvd_payload(*entries: dict[str, Any]) -> dict[str, Any]:
    return {
        "resultsPerPage": len(entries),
        "totalResults": len(entries),
        "format": "NVD_CVE",
        "version": "2.0",
        "vulnerabilities": [{"cve": entry} for entry in entries],
    }


def cve(
    cve_id: str,
    *,
    status: str = "Analyzed",
    score: float | None = 7.5,
    configurations: bool = True,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "id": cve_id,
        "vulnStatus": status,
        "descriptions": [{"lang": "en", "value": f"A flaw described for {cve_id}."}],
        "metrics": {},
    }
    if score is not None:
        entry["metrics"] = {
            "cvssMetricV31": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {"baseScore": score, "baseSeverity": "HIGH"},
                }
            ]
        }
    if configurations:
        entry["configurations"] = [{"nodes": []}]
    return entry


def kev_payload(*cve_ids: str, ransomware: bool = False) -> dict[str, Any]:
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.11.18",
        "dateReleased": "2026-11-18T18:00:00.0000Z",
        "count": len(cve_ids),
        "vulnerabilities": [
            {
                "cveID": cve_id,
                "vendorProject": "Example",
                "product": "Example Server",
                "vulnerabilityName": f"{cve_id} exploited in the wild",
                "dateAdded": "2026-10-01",
                "dueDate": "2026-10-22",
                "knownRansomwareCampaignUse": "Known" if ransomware else "Unknown",
                "requiredAction": "Apply mitigations.",
                "shortDescription": "Exploited.",
                "forensicTriage": "",
                "cwes": [],
                "notes": "",
            }
            for cve_id in cve_ids
        ],
    }


class FakeGateway(OutboundGateway):
    """Records what was asked for and replays canned provider answers."""

    def __init__(
        self,
        *,
        nvd: dict[str, Any] | Exception | None = None,
        kev: dict[str, Any] | Exception | None = None,
    ) -> None:
        super().__init__(user_agent="ScanLedger/test")
        self._nvd = nvd
        self._kev = kev
        self.requests: list[tuple[str, dict[str, str]]] = []

    async def get_json(self, url: str, params: dict[str, str] | None = None) -> ProviderResponse:
        self.check_url(url)
        self.requests.append((url, dict(params or {})))

        answer = self._kev if url == KEV_URL else self._nvd
        if isinstance(answer, Exception):
            raise answer
        if answer is None:
            return ProviderResponse(200, nvd_payload())
        return ProviderResponse(200, answer)


async def make_context(
    *,
    gateway: OutboundGateway,
    cache: ResponseCache | None = None,
    product: str | None = "OpenSSH",
    version: str | None = "8.9p1",
) -> ModuleContext:
    guard = ScanGuard(ScopeProfile.create("self-test", ["127.0.0.0/24"]), InMemoryLedger())
    target = await guard.validate_target("127.0.0.1")

    prior: tuple[Finding, ...] = ()
    if product is not None:
        prior = (
            Finding(
                host="127.0.0.1",
                port=22,
                category=FindingCategory.PORT_SERVICE,
                kind="service.detected",
                title="ssh",
                summary="ssh",
                module="service_detect",
                identity_key="service/22",
                normalized_value={
                    "port": 22,
                    "service": "ssh",
                    "product": product,
                    "version": version,
                },
            ),
        )

    return ModuleContext(
        scan_id="scan-1",
        target=target,
        guard=guard,
        governor=IntensityGovernor("polite"),
        is_cancel_requested=lambda: False,
        prior_findings=prior,
        gateway=gateway,
        cache=cache,
    )


class TestCpeMapping:
    def test_a_curated_product_maps_to_an_exact_cpe(self) -> None:
        assert cpe_for("OpenSSH", "8.9p1") == "cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*"

    def test_vendor_suffixes_are_trimmed_to_the_numeric_core(self) -> None:
        assert normalize_version("1.18.0 (Ubuntu)") == "1.18.0"
        assert normalize_version("8.9p1") == "8.9"

    def test_an_unknown_product_is_not_guessed_at(self) -> None:
        assert cpe_for("TotallyMadeUpDaemon", "1.0") is None

    def test_a_missing_version_becomes_a_wildcard_not_an_invention(self) -> None:
        assert cpe_for("nginx", None) == "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"


class TestServiceSelection:
    def test_services_without_a_product_are_skipped(self) -> None:
        finding = Finding(
            host="127.0.0.1",
            port=135,
            category=FindingCategory.PORT_SERVICE,
            kind="service.detected",
            title="msrpc",
            summary="msrpc",
            module="service_detect",
            identity_key="service/135",
            normalized_value={"port": 135, "service": "msrpc", "product": None},
        )
        assert services_from_findings((finding,)) == ()


class TestCorrelation:
    async def test_an_nvd_match_is_reported_as_unconfirmed(self) -> None:
        gateway = FakeGateway(nvd=nvd_payload(cve("CVE-2026-0001")), kev=kev_payload())
        result = await CveCorrelateModule().run(await make_context(gateway=gateway))

        candidates = [f for f in result.findings if f.kind == "cve.candidate"]
        assert len(candidates) == 1
        finding = candidates[0]

        assert finding.category is FindingCategory.VULNERABILITY
        assert finding.normalized_value["confirmed"] is False
        assert "Unconfirmed" in finding.summary
        assert "does not attempt exploitation" in finding.summary
        # A version match is never high confidence; it was never verified.
        assert finding.confidence is not Confidence.HIGH
        assert "nvd" in finding.sources

    async def test_the_cpe_path_is_used_when_the_product_is_curated(self) -> None:
        gateway = FakeGateway(nvd=nvd_payload(cve("CVE-2026-0001")), kev=kev_payload())
        await CveCorrelateModule().run(await make_context(gateway=gateway))

        nvd_requests = [r for r in gateway.requests if r[0] == NVD_CVE_URL]
        assert nvd_requests[0][1]["cpeName"] == "cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*"

    async def test_an_uncurated_product_falls_back_to_keyword_and_says_so(self) -> None:
        gateway = FakeGateway(nvd=nvd_payload(cve("CVE-2026-0002")), kev=kev_payload())
        context = await make_context(gateway=gateway, product="WeirdDaemon", version="2.1")
        result = await CveCorrelateModule().run(context)

        nvd_requests = [r for r in gateway.requests if r[0] == NVD_CVE_URL]
        assert nvd_requests[0][1]["keywordSearch"] == "WeirdDaemon"

        candidate = next(f for f in result.findings if f.kind == "cve.candidate")
        assert candidate.normalized_value["match_method"] == "keyword"
        assert candidate.confidence is Confidence.LOW

        coverage = next(f for f in result.findings if f.kind == "cve.coverage")
        assert "not on the detected version" in coverage.summary

    async def test_a_kev_listing_is_flagged(self) -> None:
        gateway = FakeGateway(
            nvd=nvd_payload(cve("CVE-2026-0003")),
            kev=kev_payload("CVE-2026-0003", ransomware=True),
        )
        result = await CveCorrelateModule().run(await make_context(gateway=gateway))

        candidate = next(f for f in result.findings if f.kind == "cve.candidate")
        assert candidate.normalized_value["kev_listed"] is True
        assert candidate.normalized_value["kev_ransomware"] is True
        assert "[KEV]" in candidate.title
        assert "ransomware" in candidate.summary

    async def test_missing_nvd_enrichment_is_stated_not_hidden(self) -> None:
        """The 2026 risk-based model makes this the common case, not the exception."""
        gateway = FakeGateway(
            nvd=nvd_payload(
                cve("CVE-2026-0004", status="Deferred", score=None, configurations=False)
            ),
            kev=kev_payload(),
        )
        result = await CveCorrelateModule().run(await make_context(gateway=gateway))

        candidate = next(f for f in result.findings if f.kind == "cve.candidate")
        assert candidate.normalized_value["nvd_enrichment_missing"] is True
        assert candidate.normalized_value["cvss_score"] is None
        assert "no CVSS score published by NVD" in candidate.summary
        assert "not an indication of low risk" in candidate.summary

    async def test_no_matches_still_explains_what_was_not_seen(self) -> None:
        """An empty Vulnerabilities section must never read as 'clean'."""
        gateway = FakeGateway(nvd=nvd_payload(), kev=kev_payload())
        result = await CveCorrelateModule().run(await make_context(gateway=gateway))

        assert [f for f in result.findings if f.kind == "cve.candidate"] == []
        coverage = next(f for f in result.findings if f.kind == "cve.coverage")
        assert "not evidence" in coverage.summary
        assert "carry no CPE data" in coverage.summary

    async def test_a_rejected_cve_is_not_reported(self) -> None:
        gateway = FakeGateway(
            nvd=nvd_payload(cve("CVE-2026-0005", status="Rejected")), kev=kev_payload()
        )
        result = await CveCorrelateModule().run(await make_context(gateway=gateway))
        assert [f for f in result.findings if f.kind == "cve.candidate"] == []


class TestProviderFailures:
    async def test_rate_limiting_warns_and_never_fails_the_scan(self) -> None:
        gateway = FakeGateway(
            nvd=ProviderRateLimited("429 from NVD", status=429), kev=kev_payload()
        )
        result = await CveCorrelateModule().run(await make_context(gateway=gateway))

        assert result.findings == ()
        assert any("rate limited" in warning for warning in result.warnings)
        assert any("means nothing" in warning for warning in result.warnings)

    async def test_an_unreachable_provider_warns_rather_than_raising(self) -> None:
        gateway = FakeGateway(nvd=ProviderUnavailable("connection reset"), kev=kev_payload())
        result = await CveCorrelateModule().run(await make_context(gateway=gateway))

        assert result.findings == ()
        assert any("not correlated" in warning for warning in result.warnings)

    async def test_a_missing_kev_catalog_is_declared(self) -> None:
        gateway = FakeGateway(
            nvd=nvd_payload(cve("CVE-2026-0006")), kev=ProviderUnavailable("CISA down")
        )
        result = await CveCorrelateModule().run(await make_context(gateway=gateway))

        assert any("known-exploited flag" in warning for warning in result.warnings)
        candidate = next(f for f in result.findings if f.kind == "cve.candidate")
        assert candidate.normalized_value["kev_listed"] is False
        coverage = next(f for f in result.findings if f.kind == "cve.coverage")
        assert "KEV catalog was unavailable" in coverage.summary

    async def test_nothing_to_correlate_is_not_a_clean_bill_of_health(self) -> None:
        gateway = FakeGateway()
        context = await make_context(gateway=gateway, product=None)
        result = await CveCorrelateModule().run(context)

        assert result.findings == ()
        assert "not a statement that the hosts are unaffected" in result.warnings[0]
        assert gateway.requests == []


class TestCaching:
    async def test_a_second_scan_is_served_from_cache(self, session_factory: Any) -> None:
        cache = ResponseCache(session_factory)
        gateway = FakeGateway(nvd=nvd_payload(cve("CVE-2026-0007")), kev=kev_payload())

        first = await CveCorrelateModule().run(await make_context(gateway=gateway, cache=cache))
        nvd_calls_after_first = len([r for r in gateway.requests if r[0] == NVD_CVE_URL])

        second = await CveCorrelateModule().run(await make_context(gateway=gateway, cache=cache))
        nvd_calls_after_second = len([r for r in gateway.requests if r[0] == NVD_CVE_URL])

        assert nvd_calls_after_first == 1
        assert nvd_calls_after_second == 1, "the second lookup must not hit NVD again"

        # Both runs report the same CVE; only the second avoided the network.
        first_ids = [
            f.normalized_value["cve_id"] for f in first.findings if f.kind == "cve.candidate"
        ]
        second_ids = [
            f.normalized_value["cve_id"] for f in second.findings if f.kind == "cve.candidate"
        ]
        assert first_ids == second_ids == ["CVE-2026-0007"]

        coverage = next(f for f in second.findings if f.kind == "cve.coverage")
        assert coverage.normalized_value["cache_hit"] is True
        assert "no request left this machine" in coverage.summary

    async def test_the_kev_catalog_is_fetched_once_and_cached(self, session_factory: Any) -> None:
        cache = ResponseCache(session_factory)
        gateway = FakeGateway(
            nvd=nvd_payload(cve("CVE-2026-0008")), kev=kev_payload("CVE-2026-0008")
        )

        await CveCorrelateModule().run(await make_context(gateway=gateway, cache=cache))
        await CveCorrelateModule().run(await make_context(gateway=gateway, cache=cache))

        kev_calls = len([r for r in gateway.requests if r[0] == KEV_URL])
        assert kev_calls == 1

    async def test_a_provider_failure_is_never_cached_as_success(
        self, session_factory: Any
    ) -> None:
        """Otherwise a transient outage becomes a day-long 'nothing found'."""
        cache = ResponseCache(session_factory)
        failing = FakeGateway(nvd=ProviderUnavailable("boom"), kev=kev_payload())
        await CveCorrelateModule().run(await make_context(gateway=failing, cache=cache))

        working = FakeGateway(nvd=nvd_payload(cve("CVE-2026-0009")), kev=kev_payload())
        result = await CveCorrelateModule().run(await make_context(gateway=working, cache=cache))

        assert [f for f in result.findings if f.kind == "cve.candidate"]


@pytest.mark.parametrize("url", [NVD_CVE_URL, KEV_URL])
def test_only_provider_hosts_are_reachable(url: str) -> None:
    gateway = OutboundGateway(user_agent="ScanLedger/test")
    assert gateway.check_url(url) == url
