"""Multi-source CVE correlation (PRD FR-09).

Correlation, never confirmation. A match here says "the version this service
reported appears in a vulnerability record", which is a lead to investigate -
not proof the host is exploitable. Nothing in this module touches the target;
it reads the versions earlier modules already observed and asks NVD and CISA
about them. Every finding it produces carries an unconfirmed label.

Two things verified against the live providers on 2026-11-18 shape the output:

* **Every one of 40 recently published CVEs had no CPE configuration**, and
  none were ``Analyzed`` (23 Deferred, 14 Awaiting Analysis). A ``cpeName``
  query matches against exactly that missing block, so NVD returning nothing
  is a statement about NVD's coverage and not about the service. Each service
  therefore gets a coverage finding saying so in words, because an empty
  Vulnerabilities section is otherwise read as "clean".
* The KEV catalog has no per-CVE endpoint, so it is fetched once per scan,
  cached for a day, and matched locally - which also means CISA is never told
  what is being scanned.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.models.domain import (
    Confidence,
    FindingCategory,
    ModuleCategory,
    TargetType,
)
from app.models.findings import Finding
from app.modules.base import ModuleContext, ModuleMetadata, ModuleResult, ScanModule
from app.modules.cpe import cpe_for, normalize_version
from app.services.cache import STATUS_EMPTY, STATUS_HIT, ResponseCache, build_cache_key
from app.services.outbound import ProviderRateLimited, ProviderUnavailable
from app.services.providers import kev as kev_provider
from app.services.providers.kev import KevCatalog, KevClient
from app.services.providers.nvd import CveRecord, NvdClient, NvdResult

MODULE_NAME = "cve_correlate"

# Enough to be useful without burying the rest of the report. The exports
# carry the full set, and the finding says how many were held back.
MAX_CANDIDATES_PER_SERVICE = 25

UNCONFIRMED_NOTE = (
    "Unconfirmed: this is a version match against a published vulnerability record, "
    "not a test of the service. ScanLedger does not attempt exploitation."
)


@dataclass(frozen=True)
class ServiceVersion:
    host: str
    port: int
    service: str
    product: str
    version: str | None

    @property
    def label(self) -> str:
        return f"{self.product} {self.version}" if self.version else self.product


def services_from_findings(findings: tuple[Finding, ...]) -> tuple[ServiceVersion, ...]:
    """Pick out the services earlier modules identified by product name.

    A service with no product name is skipped rather than guessed at: there is
    nothing honest to ask a provider about.
    """
    seen: set[tuple[str, int]] = set()
    services: list[ServiceVersion] = []

    for finding in findings:
        if finding.kind != "service.detected" or finding.port is None:
            continue
        product = finding.normalized_value.get("product")
        if not isinstance(product, str) or not product.strip():
            continue

        key = (finding.host, finding.port)
        if key in seen:
            continue
        seen.add(key)

        version = finding.normalized_value.get("version")
        services.append(
            ServiceVersion(
                host=finding.host,
                port=finding.port,
                service=str(finding.normalized_value.get("service") or "unknown"),
                product=product.strip(),
                version=version if isinstance(version, str) else None,
            )
        )
    return tuple(services)


class CveCorrelateModule(ScanModule):
    metadata = ModuleMetadata(
        name=MODULE_NAME,
        display_name="CVE correlation (NVD + CISA KEV)",
        description=(
            "Maps detected product versions to published CVEs using NVD and the "
            "CISA Known Exploited Vulnerabilities catalog. Every match is labelled "
            "unconfirmed; nothing is verified against the target."
        ),
        category=ModuleCategory.VULNERABILITY,
        supported_targets=frozenset({TargetType.IP, TargetType.CIDR, TargetType.HOST}),
        timeout_seconds=1800.0,
        order=50,
        cache_ttl_seconds=24 * 60 * 60,
        # Provider rate limits are outside ScanLedger's control, so correlation
        # must not hold the whole scan open behind them.
        blocks_scan_completion=False,
    )

    async def run(self, context: ModuleContext) -> ModuleResult:
        services = services_from_findings(context.prior_findings)
        if not services:
            return ModuleResult(
                warnings=(
                    "no service reported a product name, so there was nothing to "
                    "correlate. This is not a statement that the hosts are unaffected.",
                ),
            )

        if context.gateway is None:
            return ModuleResult(
                warnings=("the outbound provider gateway is not configured",),
            )

        nvd = NvdClient(context.gateway)
        findings: list[Finding] = []
        warnings: list[str] = []

        catalog, kev_warning = await self._load_kev(context)
        if kev_warning:
            warnings.append(kev_warning)

        for service in services:
            if context.is_cancel_requested():
                warnings.append("the scan was cancelled before every service was correlated")
                break

            try:
                result, cache_hit = await self._lookup(context, nvd, service)
            except ProviderRateLimited as exc:
                # A provider limit is never allowed to fail the scan (PRD 10.2).
                warnings.append(
                    f"{service.label}: NVD rate limited ScanLedger ({exc}); this service "
                    "was not correlated and its absence from the list means nothing"
                )
                continue
            except ProviderUnavailable as exc:
                warnings.append(
                    f"{service.label}: NVD was unavailable ({exc}); this service was not "
                    "correlated and its absence from the list means nothing"
                )
                continue

            findings.extend(_candidate_findings(service, result, catalog))
            findings.append(_coverage_finding(service, result, catalog, cache_hit))

        return ModuleResult(
            findings=tuple(findings),
            cache_hit=False,
            warnings=tuple(warnings),
        )

    async def _load_kev(self, context: ModuleContext) -> tuple[KevCatalog | None, str | None]:
        """Fetch the KEV catalog once, preferring a cached copy."""
        if context.gateway is None:
            return None, "the outbound provider gateway is not configured"

        cache = context.cache
        if cache is not None:
            cached = await cache.get(kev_provider.CACHE_KEY)
            if cached is not None and cached.normalized:
                return kev_provider.parse_catalog(cached.normalized), None

        try:
            catalog = await KevClient(context.gateway).fetch_catalog()
        except ProviderUnavailable as exc:
            return None, (
                f"the CISA KEV catalog could not be fetched ({exc}); findings below carry "
                "no known-exploited flag, which is missing information rather than a "
                "statement that none are exploited"
            )

        if cache is not None:
            await cache.store(
                kev_provider.CACHE_KEY,
                source="kev",
                status=STATUS_HIT,
                normalized=kev_provider.serialize_catalog(catalog),
                ttl_seconds=kev_provider.CACHE_TTL_SECONDS,
            )
        return catalog, None

    async def _lookup(
        self, context: ModuleContext, nvd: NvdClient, service: ServiceVersion
    ) -> tuple[NvdResult, bool]:
        """Ask NVD about one product version, through the cache."""
        cache: ResponseCache | None = context.cache
        cache_key = build_cache_key(
            source="nvd", product=service.product, version=normalize_version(service.version)
        )

        if cache is not None:
            cached = await cache.get(cache_key)
            if cached is not None and cached.normalized is not None:
                return _result_from_cache(cached.normalized), True

        cpe_name = cpe_for(service.product, service.version)
        result = (
            await nvd.by_cpe(cpe_name)
            if cpe_name is not None
            else await nvd.by_keyword(service.product)
        )

        if cache is not None:
            await cache.store(
                cache_key,
                source="nvd",
                status=STATUS_HIT if result.records else STATUS_EMPTY,
                normalized=_result_to_cache(result),
            )
        return result, False


def _result_to_cache(result: NvdResult) -> dict[str, Any]:
    return {
        "query_kind": result.query_kind,
        "total_results": result.total_results,
        "notes": list(result.notes),
        "records": [
            {
                "cve_id": record.cve_id,
                "description": record.description,
                "vuln_status": record.vuln_status,
                "cvss_score": record.cvss_score,
                "cvss_severity": record.cvss_severity,
                "cvss_version": record.cvss_version,
                "has_cpe_configuration": record.has_cpe_configuration,
            }
            for record in result.records
        ],
    }


def _result_from_cache(payload: dict[str, Any]) -> NvdResult:
    return NvdResult(
        records=tuple(
            CveRecord(
                cve_id=item["cve_id"],
                description=item.get("description", ""),
                vuln_status=item.get("vuln_status"),
                cvss_score=item.get("cvss_score"),
                cvss_severity=item.get("cvss_severity"),
                cvss_version=item.get("cvss_version"),
                has_cpe_configuration=bool(item.get("has_cpe_configuration")),
            )
            for item in payload.get("records", [])
        ),
        total_results=int(payload.get("total_results", 0)),
        query_kind=str(payload.get("query_kind", "cpe")),
        notes=tuple(payload.get("notes", [])),
    )


def _confidence_for(result: NvdResult, service: ServiceVersion) -> Confidence:
    """A correlation is never high confidence - it was never verified.

    An exact CPE match on a stated version is the strongest case and still
    only reaches medium, because the version itself came from a banner the
    service volunteered.
    """
    if result.query_kind == "cpe" and service.version:
        return Confidence.MEDIUM
    return Confidence.LOW


def _candidate_findings(
    service: ServiceVersion, result: NvdResult, catalog: KevCatalog | None
) -> list[Finding]:
    confidence = _confidence_for(result, service)
    sources = ("nvd",) if catalog is None else ("nvd", "cisa-kev")
    findings: list[Finding] = []

    for record in result.records[:MAX_CANDIDATES_PER_SERVICE]:
        kev_entry = catalog.get(record.cve_id) if catalog is not None else None

        severity_text = (
            f"{record.cvss_severity} {record.cvss_score}"
            if record.cvss_score is not None
            else "no CVSS score published by NVD"
        )
        summary_parts = [
            f"{service.label} matches {record.cve_id} ({severity_text}).",
        ]
        if kev_entry is not None:
            summary_parts.append(
                "Listed in the CISA Known Exploited Vulnerabilities catalog"
                + (
                    " and linked to ransomware campaigns."
                    if kev_entry.known_ransomware_use
                    else "."
                )
            )
        if record.enrichment_missing:
            summary_parts.append(
                f"NVD enrichment is incomplete (status {record.vuln_status or 'unknown'}"
                + ("" if record.has_cpe_configuration else ", no CPE mapping")
                + ("" if record.cvss_score is not None else ", no CVSS")
                + "); missing detail is not an indication of low risk."
            )
        summary_parts.append(UNCONFIRMED_NOTE)

        findings.append(
            Finding(
                host=service.host,
                port=service.port,
                category=FindingCategory.VULNERABILITY,
                kind="cve.candidate",
                title=(
                    f"{record.cve_id} - unconfirmed candidate for "
                    f"{service.label} on {service.host}:{service.port}"
                    + (" [KEV]" if kev_entry is not None else "")
                ),
                summary=" ".join(summary_parts),
                module=MODULE_NAME,
                identity_key=f"cve/{record.cve_id}",
                normalized_value={
                    "cve_id": record.cve_id,
                    "product": service.product,
                    "version": service.version,
                    "cvss_score": record.cvss_score,
                    "cvss_severity": record.cvss_severity,
                    "cvss_version": record.cvss_version,
                    "nvd_status": record.vuln_status,
                    "nvd_enrichment_missing": record.enrichment_missing,
                    "kev_listed": kev_entry is not None,
                    "kev_ransomware": bool(kev_entry and kev_entry.known_ransomware_use),
                    "kev_due_date": kev_entry.due_date if kev_entry else None,
                    "match_method": result.query_kind,
                    "confirmed": False,
                },
                raw_evidence=record.description[:1000] or None,
                confidence=confidence,
                sources=sources,
            )
        )
    return findings


def _coverage_finding(
    service: ServiceVersion,
    result: NvdResult,
    catalog: KevCatalog | None,
    cache_hit: bool,
) -> Finding:
    """States what the correlation could and could not see.

    Without this, a service with zero matches leaves an empty section that
    reads as "clean" - the single most misleading thing this module could do.
    """
    shown = min(len(result.records), MAX_CANDIDATES_PER_SERVICE)
    unenriched = sum(1 for record in result.records if record.enrichment_missing)

    parts = [
        f"Queried NVD by {result.query_kind} for {service.label}:"
        f" {result.total_results} record(s) returned, {shown} listed.",
    ]
    if len(result.records) > shown:
        parts.append(f"{len(result.records) - shown} further match(es) are in the exports.")
    if unenriched:
        parts.append(
            f"{unenriched} of the listed record(s) lack full NVD enrichment "
            "(no CVSS, no CPE mapping, or still awaiting analysis)."
        )
    parts.extend(result.notes)
    if catalog is None:
        parts.append("The CISA KEV catalog was unavailable, so no known-exploited flags were set.")
    else:
        parts.append(f"Cross-checked against CISA KEV catalog {catalog.version}.")
    if cache_hit:
        parts.append("Served from the local provider cache; no request left this machine.")

    return Finding(
        host=service.host,
        port=service.port,
        category=FindingCategory.VULNERABILITY,
        kind="cve.coverage",
        title=f"Correlation coverage for {service.label} on {service.host}:{service.port}",
        summary=" ".join(parts),
        module=MODULE_NAME,
        identity_key=f"coverage/{service.port}",
        normalized_value={
            "product": service.product,
            "version": service.version,
            "match_method": result.query_kind,
            "total_results": result.total_results,
            "listed": shown,
            "unenriched": unenriched,
            "kev_catalog_version": catalog.version if catalog else None,
            "cache_hit": cache_hit,
        },
        confidence=Confidence.HIGH,
        sources=("nvd",) if catalog is None else ("nvd", "cisa-kev"),
    )
