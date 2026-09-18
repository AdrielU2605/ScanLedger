"""Deterministic Markdown and JSON exports (PRD FR-12).

Everything here is regenerated from stored evidence - an export never sends a
probe. Both formats state the scan's limits explicitly, because a report that
omits what was skipped invites the reader to treat absence as proof.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from app.db.tables import FindingRow, ModuleRunRow, ScanLedgerRow, ScanRow, ScopeProfileRow
from app.models.domain import FindingCategory, ModuleStatus

EXPORT_SCHEMA_VERSION = 1
SUMMARY_ROWS_PER_CATEGORY = 20

CATEGORY_TITLES = {
    FindingCategory.LIVE_HOST: "Live hosts",
    FindingCategory.PORT_SERVICE: "Ports and services",
    FindingCategory.ENUMERATION: "Enumeration",
    FindingCategory.VULNERABILITY: "Vulnerabilities",
}


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    moment = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return moment.astimezone(UTC).isoformat()


def build_json_export(
    scan: ScanRow,
    scope: ScopeProfileRow,
    module_runs: Sequence[ModuleRunRow],
    findings: Sequence[FindingRow],
    ledger: Sequence[ScanLedgerRow],
) -> dict[str, Any]:
    return {
        "schema_version": EXPORT_SCHEMA_VERSION,
        "generated_at": _iso(datetime.now(UTC)),
        "scan": {
            "id": scan.id,
            "status": scan.status,
            "target_input": scan.target_input,
            "target_normalized": scan.target_normalized,
            "target_type": scan.target_type,
            "resolved_addresses": list(scan.resolved_addrs_json),
            "intensity_profile": scan.intensity_profile,
            "module_options": dict(scan.module_options_json),
            "note": scan.note,
            "created_at": _iso(scan.created_at),
            "started_at": _iso(scan.started_at),
            "finished_at": _iso(scan.finished_at),
        },
        "scope": {
            "id": scope.id,
            "name": scope.name,
            "entries": list(scope.entries_json),
            "allow_cgnat": scope.allow_cgnat,
            "allow_link_local": scope.allow_link_local,
        },
        "authorization": {
            "attestation_text": scan.attestation_text,
            "attestation_version": scan.attestation_version,
            "attested_at": _iso(scan.attestation_at),
        },
        "modules": [
            {
                "module": run.module,
                "status": run.status,
                "finding_count": run.finding_count,
                "cache_hit": run.cache_hit,
                "error_code": run.safe_error_code,
                "error_message": run.safe_error_message,
                "started_at": _iso(run.started_at),
                "finished_at": _iso(run.finished_at),
            }
            for run in module_runs
        ],
        "findings": [
            {
                "id": finding.id,
                "host": finding.host,
                "port": finding.port,
                "category": finding.category,
                "kind": finding.kind,
                "title": finding.title,
                "summary": finding.summary,
                "normalized_value": finding.normalized_value,
                "raw_evidence": finding.raw_evidence,
                "module": finding.module,
                "observed_at": _iso(finding.observed_at),
                "confidence": finding.confidence,
                "sources": list(finding.sources_json),
                "fingerprint": finding.fingerprint,
            }
            for finding in findings
        ],
        "ledger": [
            {
                "destination": entry.destination,
                "port": entry.port,
                "module": entry.module,
                "decision": entry.decision,
                "reason": entry.reason,
                "outcome": entry.outcome,
                "recorded_at": _iso(entry.created_at),
            }
            for entry in ledger
        ],
    }


def build_markdown_export(
    scan: ScanRow,
    scope: ScopeProfileRow,
    module_runs: Sequence[ModuleRunRow],
    findings: Sequence[FindingRow],
    ledger: Sequence[ScanLedgerRow],
    *,
    mode: str = "summary",
) -> str:
    full = mode == "full"
    lines: list[str] = [
        f"# ScanLedger report - {scan.target_normalized}",
        "",
        "> Authorized lab scan. Every destination below was inside the attested "
        "private scope profile; ScanLedger refuses any public or out-of-scope address.",
        "",
        "## Scan",
        "",
        f"- **Status:** {scan.status}",
        f"- **Target:** `{scan.target_input}` (normalized `{scan.target_normalized}`, "
        f"type {scan.target_type})",
        f"- **Scope profile:** {scope.name} - {', '.join(scope.entries_json)}",
        f"- **Intensity profile:** {scan.intensity_profile}",
        f"- **Created:** {_iso(scan.created_at)}",
        f"- **Finished:** {_iso(scan.finished_at) or 'not finished'}",
    ]
    if scan.note:
        lines.append(f"- **Engagement note:** {scan.note}")

    lines += [
        "",
        "## Authorization",
        "",
        f"> {scan.attestation_text}",
        "",
        f"Attested {_iso(scan.attestation_at)} (attestation {scan.attestation_version}).",
        "",
        "## Methodology and limits",
        "",
        "- Unprivileged TCP connect probing only. No raw sockets, no SYN scanning, "
        "no exploitation, no credential attacks, and nothing was written to a target.",
        "- Concurrency and connection rate were bounded by the intensity governor.",
        "- A skipped, failed, or interrupted module means *unknown*, never *absent*: "
        "it cannot be read as a closed port or as the absence of a finding.",
        "",
        "## Module status",
        "",
        "| Module | Status | Findings | Reason |",
        "| --- | --- | --- | --- |",
    ]
    for run in module_runs:
        reason = run.safe_error_message or ""
        lines.append(f"| {run.module} | {run.status} | {run.finding_count} | {reason} |")

    incomplete = [run.module for run in module_runs if run.status != str(ModuleStatus.DONE)]
    if incomplete:
        lines += [
            "",
            f"**{len(incomplete)} module(s) did not complete:** {', '.join(incomplete)}. "
            "Their categories below are incomplete, not empty.",
        ]

    by_category: dict[str, list[FindingRow]] = {}
    for finding in findings:
        by_category.setdefault(finding.category, []).append(finding)

    lines += ["", "## Findings", ""]
    for category in FindingCategory:
        rows = by_category.get(str(category), [])
        lines.append(f"### {CATEGORY_TITLES[category]}")
        lines.append("")
        if not rows:
            lines += ["No findings in this category.", ""]
            continue

        shown = rows if full else rows[:SUMMARY_ROWS_PER_CATEGORY]
        lines += [
            "| Host | Port | Finding | Module | Observed |",
            "| --- | --- | --- | --- | --- |",
        ]
        for finding in shown:
            port = "" if finding.port is None else str(finding.port)
            lines.append(
                f"| {finding.host} | {port} | {finding.title} | {finding.module} | "
                f"{_iso(finding.observed_at)} |"
            )
        if not full and len(rows) > len(shown):
            lines.append("")
            lines.append(
                f"_{len(rows) - len(shown)} further row(s) omitted from this summary; "
                "the JSON export carries the complete record._"
            )
        lines.append("")

    allowed = sum(1 for entry in ledger if entry.decision == "allowed")
    denied = sum(1 for entry in ledger if entry.decision == "denied")
    lines += [
        "## Audit ledger",
        "",
        f"- Destinations allowed and probed: **{allowed}**",
        f"- Destinations denied before any packet: **{denied}**",
        "",
    ]
    if denied:
        lines += ["| Destination | Reason |", "| --- | --- |"]
        for entry in ledger:
            if entry.decision == "denied":
                lines.append(f"| {entry.destination} | {entry.reason} |")
        lines.append("")

    lines += [f"_Generated {_iso(datetime.now(UTC))} from stored evidence; no probes were sent._"]
    return "\n".join(lines)


def dump_json_export(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=False, default=str)
