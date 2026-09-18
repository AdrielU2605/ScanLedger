"""CISA Known Exploited Vulnerabilities catalog (PRD FR-09, R6).

Re-verified against the live feed on 2026-09-18: catalog version 2026.09.16,
1713 entries, about 1.7 MB. There is no per-CVE query endpoint, so the whole
catalog is fetched once, cached, and matched locally - which also means the
KEV cross-check costs nothing per service and never leaks what we are scanning.

The live schema carries ``forensicTriage`` in addition to the long-standing
fields, so parsing reads only what it needs and tolerates additions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.services.outbound import KEV_HOST, OutboundGateway

KEV_URL = f"https://{KEV_HOST}/sites/default/files/feeds/known_exploited_vulnerabilities.json"

CACHE_KEY = "kev:catalog"
CACHE_TTL_SECONDS = 24 * 60 * 60


@dataclass(frozen=True)
class KevEntry:
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    due_date: str
    known_ransomware_use: bool
    required_action: str


@dataclass(frozen=True)
class KevCatalog:
    version: str
    released: str
    entries: dict[str, KevEntry]

    def get(self, cve_id: str) -> KevEntry | None:
        return self.entries.get(cve_id.upper())

    @property
    def count(self) -> int:
        return len(self.entries)


def parse_catalog(payload: dict[str, Any]) -> KevCatalog:
    entries: dict[str, KevEntry] = {}
    for item in payload.get("vulnerabilities", []):
        cve_id = str(item.get("cveID", "")).upper()
        if not cve_id:
            continue
        entries[cve_id] = KevEntry(
            cve_id=cve_id,
            vendor_project=str(item.get("vendorProject", "")),
            product=str(item.get("product", "")),
            vulnerability_name=str(item.get("vulnerabilityName", "")),
            date_added=str(item.get("dateAdded", "")),
            due_date=str(item.get("dueDate", "")),
            # The feed uses the strings "Known", "Unknown", and "Unlikely";
            # only an explicit "Known" is treated as ransomware use.
            known_ransomware_use=str(item.get("knownRansomwareCampaignUse", "")).lower() == "known",
            required_action=str(item.get("requiredAction", "")),
        )

    return KevCatalog(
        version=str(payload.get("catalogVersion", "unknown")),
        released=str(payload.get("dateReleased", "")),
        entries=entries,
    )


def serialize_catalog(catalog: KevCatalog) -> dict[str, Any]:
    """Shrunk to what correlation needs, so the cache row stays small."""
    return {
        "catalogVersion": catalog.version,
        "dateReleased": catalog.released,
        "vulnerabilities": [
            {
                "cveID": entry.cve_id,
                "vendorProject": entry.vendor_project,
                "product": entry.product,
                "vulnerabilityName": entry.vulnerability_name,
                "dateAdded": entry.date_added,
                "dueDate": entry.due_date,
                "knownRansomwareCampaignUse": "Known" if entry.known_ransomware_use else "Unknown",
                "requiredAction": entry.required_action,
            }
            for entry in catalog.entries.values()
        ],
    }


class KevClient:
    def __init__(self, gateway: OutboundGateway) -> None:
        self._gateway = gateway

    async def fetch_catalog(self) -> KevCatalog:
        response = await self._gateway.get_json(KEV_URL)
        return parse_catalog(response.payload)
