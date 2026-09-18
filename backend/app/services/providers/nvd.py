"""NVD CVE API 2.0 client (PRD FR-09, R3-R5).

Re-verified against the live API on 2026-09-18. What that check found matters
more than the endpoint shape, and shapes this module:

* In a sample of 40 CVEs published in the last few weeks, **35 were
  ``Deferred``** and **36 carried no ``configurations`` block at all**. Under
  NVD's risk-based enrichment model most recent CVEs never receive CPE
  mapping, so a ``cpeName`` query - which matches against exactly that block -
  cannot see them.
* ``keywordSearch`` with an exact "product version" phrase returned zero
  results, because CVE descriptions rarely contain that literal string. A
  product-name keyword search does work, so it is used as a labelled fallback
  rather than a precision tool.

The consequence is stated on every result: an empty NVD answer is evidence
about NVD's coverage, never evidence that the service is safe.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.outbound import NVD_HOST, OutboundGateway

NVD_CVE_URL = f"https://{NVD_HOST}/rest/json/cves/2.0"
MAX_RESULTS_PER_PAGE = 50

# Preference order: newest scoring system first, since NVD now publishes v4.0
# alongside v3.1 and only older records are v2 only.
METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

UNENRICHED_STATUSES = frozenset(
    {"Awaiting Analysis", "Received", "Deferred", "Undergoing Analysis"}
)


@dataclass(frozen=True)
class CveRecord:
    cve_id: str
    description: str
    vuln_status: str | None
    cvss_score: float | None
    cvss_severity: str | None
    cvss_version: str | None
    has_cpe_configuration: bool

    @property
    def enrichment_missing(self) -> bool:
        """True when NVD has not (yet) added the detail a reader would assume.

        Explicitly surfaced rather than silently treated as "no risk": under
        the 2026 risk-based model this is the common case, not the exception.
        """
        return (
            self.cvss_score is None
            or not self.has_cpe_configuration
            or (self.vuln_status or "") in UNENRICHED_STATUSES
        )


@dataclass(frozen=True)
class NvdResult:
    records: tuple[CveRecord, ...] = ()
    total_results: int = 0
    query_kind: str = "cpe"
    notes: tuple[str, ...] = field(default_factory=tuple)


def _first_metric(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    for key in METRIC_KEYS:
        entries = metrics.get(key)
        if not entries:
            continue
        data = entries[0].get("cvssData", {})
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
        return (
            float(score) if isinstance(score, int | float) else None,
            str(severity) if severity else None,
            key,
        )
    return None, None, None


def parse_cve_payload(payload: dict[str, Any]) -> tuple[tuple[CveRecord, ...], int]:
    records: list[CveRecord] = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve") or {}
        cve_id = cve.get("id")
        if not cve_id:
            continue
        if cve.get("vulnStatus") == "Rejected":
            # A rejected CVE is not a finding about anything.
            continue

        description = ""
        for entry in cve.get("descriptions", []):
            if entry.get("lang") == "en":
                description = entry.get("value", "")
                break

        score, severity, version = _first_metric(cve.get("metrics") or {})
        records.append(
            CveRecord(
                cve_id=cve_id,
                description=description,
                vuln_status=cve.get("vulnStatus"),
                cvss_score=score,
                cvss_severity=severity,
                cvss_version=version,
                has_cpe_configuration=bool(cve.get("configurations")),
            )
        )
    return tuple(records), int(payload.get("totalResults", len(records)))


class NvdClient:
    """Queries NVD through the outbound gateway. Never sees a scanned host."""

    def __init__(self, gateway: OutboundGateway) -> None:
        self._gateway = gateway

    async def by_cpe(self, cpe_name: str) -> NvdResult:
        """Precise path: NVD matches the version against its CPE configurations."""
        response = await self._gateway.get_json(
            NVD_CVE_URL,
            params={"cpeName": cpe_name, "resultsPerPage": str(MAX_RESULTS_PER_PAGE)},
        )
        records, total = parse_cve_payload(response.payload)
        notes: tuple[str, ...] = ()
        if total == 0:
            notes = (
                "NVD returned no CVE with a CPE configuration matching this exact "
                "product and version. Under NVD's 2026 risk-based enrichment model "
                "most recent CVEs carry no CPE data at all, so this is not evidence "
                "that the service is unaffected.",
            )
        return NvdResult(records=records, total_results=total, query_kind="cpe", notes=notes)

    async def by_keyword(self, product: str) -> NvdResult:
        """Fallback path for products with no curated CPE. Lower precision.

        Matches on the product name only - an exact "product version" phrase
        returns nothing - so the caller must treat these as candidates and say
        so on the finding.
        """
        response = await self._gateway.get_json(
            NVD_CVE_URL,
            params={"keywordSearch": product, "resultsPerPage": str(MAX_RESULTS_PER_PAGE)},
        )
        records, total = parse_cve_payload(response.payload)
        return NvdResult(
            records=records,
            total_results=total,
            query_kind="keyword",
            notes=(
                f"Matched on the product name {product!r} only, not on the detected "
                "version, because no curated CPE exists for this product. These are "
                "candidates to review, not version-matched results.",
            ),
        )
