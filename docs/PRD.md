<!--
ScanLedger - Product Requirements Document, version 1.1 (reviewed baseline)
Markdown content master for repository use at docs/PRD.md.
The companion .docx is the formatted reading copy.
The Markdown is the content master: if the Markdown and Word copies ever disagree,
the Markdown wins. Where this prompt/handoff and the PRD disagree, the PRD wins.
-->

*PRODUCT REQUIREMENTS DOCUMENT*

# ScanLedger

*A lab-scoped active scanning and enumeration workbench for structured, repeatable, and auditable Phase 2 work*

Portfolio project | Information Systems & Technology - Cybersecurity

| Document | Value |
| --- | --- |
| Prepared for | Adriel Uribe De La Cruz |
| Version | 1.1 - reviewed requirements baseline |
| Date | September 16, 2026 |
| Status | Reviewed and ready for implementation planning |
| Release strategy | Local-first phased MVP |
| Implementation shape | React + TypeScript client; async FastAPI API; SQLite |
| Companion | Phase 2 of a tool suite; pairs with ReconLedger (Phase 1) |

> **Authorized lab use only:** ScanLedger sends real network probes and must be pointed only at systems you own or are explicitly authorized to test, inside a private lab you control. It refuses to scan any public or routable address. Running a scanner against systems you do not own or are not contracted to test is a crime in most countries; in the U.S. that is the Computer Fraud and Abuse Act. "It was reachable" is never the same as "it was allowed."

This document is the requirements baseline for ScanLedger, the Phase 2 companion to ReconLedger. Version 1.1 tightens the implementation boundary around live external scanners, resolver behavior, NVD enrichment language, and repository actions so the next implementation assistant has less room to make unsafe assumptions. Appendix C records the relationship between the two tools. Provider assumptions were checked against documentation available on September 16, 2026.

## Document map

- Executive summary
- 1. Product definition and boundaries
- 2. Users and primary workflow
- 3. Discovery decisions and product principles
- 4. Scope and release plan
- 5. User experience requirements
- 6. Functional and data requirements
- 7. Technical architecture
- 8. Safety, security, and privacy requirements
- 9. Non-functional requirements
- 10. Testing and definition of done
- 11. Risks and mitigations
- 12. Ranked roadmap and engineering advice
- 13. References
- Appendix A. Requirements discovery record
- Appendix B. Implementation AI handoff protocol
- Appendix C. Relationship to ReconLedger

## Executive summary

ScanLedger is a local-first web application that turns Phase 2 of a penetration test - scanning and enumeration - into a guided, rate-limited, fully auditable workflow for students and junior analysts working inside their own lab. Scanning means actively contacting hosts to learn which are alive, which ports are open, which services and versions are running, and what read-only metadata those services expose. Unlike passive reconnaissance, this requires sending packets to the target, so the product is built around a single non-negotiable constraint: every probe is confined to an authorized, private, lab scope, enforced by architecture rather than by a warning banner.

The safety boundary is the mirror image of ReconLedger. Where ReconLedger must never contact the target, ScanLedger may contact only the target - and only when that target is a private, in-scope, attested lab address. A central component, the ScanGuard, is the sole path to a target socket. It resolves and validates every destination before a packet is sent, denies by default, expands and checks CIDRs up front, blocks public, loopback-inappropriate, multicast, broadcast, and cloud-metadata addresses, and rejects a hostname that resolves outside the allowed private ranges. An intensity governor caps concurrency and packet rate so the tool cannot become a denial-of-service instrument even against an in-scope host, and an append-only audit ledger records exactly what was and was not probed.

The MVP delivers a complete active workflow with no external accounts: named lab scope profiles, an authorization gate, host discovery, TCP connect port scanning, service and version detection, safe read-only protocol enumeration, and vulnerability correlation that maps detected versions to known CVEs. Because the U.S. National Vulnerability Database moved to a risk-based enrichment model in 2026, many CVEs may be listed before they receive NVD enrichment such as severity, affected-product detail, or CPE mapping. Correlation is therefore multi-source from the start - NVD plus the CISA Known Exploited Vulnerabilities catalog - and every correlated finding is labeled unconfirmed. Heavier enumeration such as SMB and SNMP, UDP scanning, and external scanner imports beyond Nmap follow in release 1.1.

The stack matches ReconLedger so the two read as one engineered suite: a React and TypeScript dashboard over an async FastAPI backend, an asyncio scan engine behind the ScanGuard, httpx for CVE providers behind a separate outbound gateway, and SQLite through SQLAlchemy async with Alembic batch migrations and FTS5 search. A single in-process durable worker provides restartable scans and live per-module progress over Server-Sent Events without Redis.

> **Release outcome:** An analyst can define a lab scope, attest authorization, launch a rate-limited scan of a private host, watch each module progress, inspect a host-and-service map with correlated CVEs, compare two scans, and export an inventory and an audit ledger - while the application provably never sends a packet outside the authorized private scope.

## 1. Product definition and boundaries

### 1.1 Context

The project covers Phase 2, Scanning and Enumeration, in the EC-Council five-phase penetration-testing model, cross-mapped to PTES Vulnerability Analysis and the Discovery phase of NIST SP 800-115. Phase 1 recon, handled by the companion ReconLedger, produces a profile of domains, IP ranges, and technologies without touching the target. Phase 2 takes ranges the analyst is authorized to test and turns them into a precise map: live hosts, open ports, service versions, exposed metadata, and likely weak points (R1, R13). ScanLedger implements that map-building step for a private lab only, and stops at the boundary of Phase 3 - it never exploits a weakness it finds.

### 1.2 Problem statement

Learning Phase 2 usually means memorizing tool flags and reconciling inconsistent output from Nmap, RustScan, OpenVAS, and enum4linux by hand, while the discipline that actually matters - staying inside scope and keeping an accountable record of what was touched - is left to the analyst's memory. Beginners also blur the line between scanning and exploitation, and between a lab they own and a network that merely happens to be reachable. ScanLedger solves the workflow and the discipline together: one named scope, one authorization gate, a governed scan engine, normalized host and service evidence, correlated (not exploited) vulnerabilities, an inventory ready to hand to Phase 3, and a ledger that proves the engagement stayed in bounds.

### 1.3 Product vision

Make authorized lab scanning as repeatable as running a test suite, as accountable as a flight recorder, and as citable as a research brief - so a reviewer can trust both the findings and the fact that nothing outside scope was ever touched.

### 1.4 Goals

- Guide an analyst from a defined lab scope to a defensible service-and-vulnerability map without requiring CLI flag memorization.
- Enforce a private, in-scope-only network boundary through architecture, so no probe can leave the authorized lab even if a module or the UI is buggy.
- Make the tool incapable of denial of service against its own lab through a hard intensity governor.
- Normalize evidence from native probes and imported scans while preserving the raw observation, its module, and its retrieval time.
- Correlate service versions to known and known-exploited vulnerabilities from more than one source, and never present a correlation as a confirmed finding.
- Keep a complete, exportable audit ledger of every host and port contacted, so scope compliance is provable, not asserted.
- Demonstrate portfolio-level full-stack engineering, safety design, accessibility, and testing that is a coherent sibling to ReconLedger.

### 1.5 Success measures

| Measure | MVP target | How measured |
| --- | --- | --- |
| Scope safety | Zero probes to any out-of-scope or public destination | Process-wide socket block in CI plus ScanGuard destination tests and the audit ledger |
| Non-DoS | Concurrency and packet rate never exceed configured caps | Governor unit tests and observed connection counts under load |
| Client isolation | No browser request from the dashboard reaches a scanned host | Playwright network assertions over every request the client issues |
| Graceful completion | A scan finishes with warnings when at least one module succeeds | Scan and module state assertions |
| Evidence quality | 100% of findings carry module, retrieval time, and raw evidence | Schema validation and export tests |
| Correlation honesty | Every CVE match is labeled unconfirmed with its sources and confidence | Finding schema validation and report tests |
| Usability | A first-time user can define a scope and launch a valid scan without documentation | Two unmoderated testers complete the defined task; failures logged in the README |
| Accessibility | No critical automated WCAG 2.2 AA violations in core flows | axe/Playwright checks plus keyboard review |

### 1.6 Non-goals and hard boundary

> **Hard scope rule:** ScanLedger must send packets only to destinations that are inside the allowed private ranges and inside an active, attested scope profile. It must never probe a public or globally routable address, a hostname that resolves to one, a broadcast or multicast address, or a cloud metadata address. Every target destination passes the ScanGuard before a socket is opened.

- Exploitation of any kind - exploit payloads, Metasploit-style modules, web-app attack payloads, or sending a crafted request to confirm a vulnerability. Vulnerabilities are correlated from versions, never proven by attack. This is the Phase 3 boundary and belongs to a separate authorized tool.
- Credential attacks - brute forcing, password spraying, default-credential login attempts, or any authentication attempt against a target service.
- Denial of service, stress testing, flooding, or traffic amplification, in or out of scope.
- Scanning the public internet or any routable address, under any framing.
- Raw-socket or SYN scanning that needs elevated privileges. The MVP is unprivileged TCP connect scanning only; raw modes are out of scope.
- Writing to, modifying, or authenticating against a target service. Observation is read-only.
- A production multi-tenant SaaS, team permissions, SSO, or scanning as a hosted cloud service.
- Any client-side behavior that causes the user browser to contact a scanned host, including clickable host links, service favicons, embedded frames, previews, or speculative connections.

## 2. Users and primary workflow

### 2.1 Primary users

| Persona | Need | Design implication |
| --- | --- | --- |
| Cybersecurity student | Learn a disciplined Phase 2 process and stay in scope | Teach scanning vs enumeration in context; make scope and the ledger unmissable |
| Junior analyst | Map a lab quickly and repeatably | Fast scope profiles, reusable scans, filters, inventory export |
| Instructor or reviewer | Evaluate method, safety, and technical quality | Visible scope, attestation, governed rates, audit ledger, tests, and the exploitation refusal |

### 2.2 Primary workflow

1. Read the three-sentence first-run explanation of active scanning, the private-scope rule, and what the tool will not do.
2. Create or pick a named lab scope profile - the private ranges and hosts you are authorized to scan.
3. Enter a target that is a subset of that scope: a host, an IP, or a CIDR; resolve any inline validation error.
4. Choose scan modules and a governed intensity profile, and review each module's readiness.
5. Confirm ownership or written authorization for the scope and optionally record an engagement note.
6. Launch the scan and watch each module move through queued, running, done, failed, skipped, and not-applicable states, with a live count of hosts and ports touched.
7. Inspect the host-and-service map, expand raw evidence, review correlated CVEs, and search or filter findings.
8. Reopen history, compare a newer scan against an earlier one, and export the inventory, the report, and the audit ledger.

### 2.3 Important edge cases

- A target is syntactically valid but falls partly or wholly outside the active scope profile; the scan is refused before any packet.
- A hostname resolves to a public address, or to a mix of in-scope and out-of-scope addresses; the target is rejected, not partially scanned.
- A host is alive but every scanned port is closed or filtered; this is an explicit result, not an error.
- Nmap is not installed; MVP behavior is unchanged because live Nmap execution is out of scope and Nmap XML import accepts existing files only.
- A service banner is ambiguous or absent, so version detection returns low confidence rather than a guess.
- NVD enrichment for a CVE is not yet available under the 2026 risk-based model; correlation falls back to other sources and says so.
- An imported Nmap file contains a host outside the active scope; the import flags it and never silently trusts it.
- A scan is cancelled mid-flight; in-flight probes stop and the ledger records the partial extent accurately.

## 3. Discovery decisions and product principles

### 3.1 Decisions confirmed with the product owner

| Decision | Selected direction | Reason |
| --- | --- | --- |
| App shape | Lab-locked active scanner | A real scanner confined to a private lab is the honest analog to ReconLedger and the strongest portfolio artifact |
| Safety model | Structural scope lock, not policy text | The whole product only makes sense if a probe physically cannot leave the authorized private scope |
| Scan technique | Unprivileged TCP connect scanning | Works on Windows without admin or raw sockets; keeps the MVP portable and low-risk |
| Vulnerability handling | Multi-source correlation, never exploitation | Phase 2 stops before Phase 3; NVD 2026 gaps require more than one source |
| License | MIT | Chosen by the owner, matching the ReconLedger repository |

### 3.2 Product principles

- Safety is structural. Scope is enforced at the only socket path to a target, is tested like authentication code, and is proven by the audit ledger.
- Reachable is not authorized. A private address still requires an attested scope profile before it is scanned.
- A scanner must not be a weapon. The intensity governor is a first-class feature, not a setting; the tool cannot flood its own lab.
- Correlate, do not exploit. A version-to-CVE match is a lead labeled unconfirmed, never a proven vulnerability.
- Unknown is not absent. A skipped or failed module cannot justify a closed-port, no-vulnerability, or removed-in-diff conclusion.
- The ledger is the product. Findings and the record of what was probed matter more than raw speed.
- The interface teaches the workflow. Scope, module descriptions, and empty states help the user explain what happened and why it was allowed.

## 4. Scope and release plan

### 4.1 MVP - complete lab scanning workflow, no external accounts

- Named lab scope profiles with private-range validation and an authorization attestation.
- Target input (host, IP, CIDR) classified, canonicalized, and checked against the active scope.
- Host discovery, TCP connect port scanning, service and version detection, and safe read-only protocol enumeration.
- Vulnerability correlation from NVD plus CISA KEV, labeled unconfirmed, with confidence and sources.
- Nmap XML import normalized into the same host and service model, with scope validation on imported hosts.
- Persistent background scans, per-module SSE progress, cache, history, diff, global search, host-and-service workspace, and three exports plus the audit ledger.
- A responsive, accessible light and dark dashboard, documentation, screenshots, migrations, and automated tests.

### 4.2 Release 1.1 - heavier and credentialed enumeration

- SMB enumeration of shares and users, read-only, with strict limits.
- SNMP enumeration with user-supplied community strings, read-only.
- UDP scanning with its own governor tuning.
- Guarded external-scanner orchestration after a separate design review, including Nmap `-sV` or `-sC` only if the subprocess boundary can be constrained and audited.
- OpenVAS/Greenbone and other external scanner result import.
- Authenticated, read-only enumeration behind an explicit gate.

### 4.3 Module matrix

| Module | Release | Target | Dependency | Normalized output |
| --- | --- | --- | --- | --- |
| Host discovery | MVP | IP, CIDR, host | None (native TCP) | Live/again hosts with the evidence that proved liveness |
| Port scan (TCP connect) | MVP | IP, host | None (native) | Open/closed/filtered ports per host with timing |
| Service detection | MVP | Open port | None (native only in MVP) | Service name, product, version, confidence, banner evidence |
| Protocol enumeration | MVP | Open service | None (native) | Read-only metadata: HTTP headers/title/robots, TLS cert subject/SAN/issuer/validity, generic banner |
| CVE correlation | MVP | Detected service+version | NVD, CISA KEV (network) | Candidate CVEs with CVSS where available, KEV flag, confidence, sources, unconfirmed label |
| Nmap import | MVP | Nmap XML file | None | Hosts/ports/services normalized into the native model, with per-host scope validation |
| SMB enumeration | 1.1 | Open 139/445 | None | Shares and users, read-only |
| SNMP enumeration | 1.1 | Open 161/udp | Community string | System and interface data, read-only |
| UDP scan | 1.1 | IP, host | None | Open/open-filtered UDP ports |

### 4.4 Scope and target rules

| Input | Validation and canonical form | Scan behavior |
| --- | --- | --- |
| Scope profile | One or more CIDRs/hosts, each inside the allowed private ranges; named; at least one active before any scan | Defines the only destinations a scan may touch; every target is checked to be a subset |
| Host | Resolved through the controlled local resolver; every resolved address must be in-scope private; literal IP/CIDR input is preferred for MVP labs | Rejected if any resolved address is public or out of scope (blocks DNS rebinding); public DoH or arbitrary recursive resolvers are not used |
| IPv4/IPv6 | ipaddress canonical text; must be inside allowed private ranges and the active scope | Scanned only when both checks pass |
| CIDR | Strict network address; MVP limits IPv4 to /16 or narrower and IPv6 to /64 or narrower; expanded and each address validated before probing | Every expanded address must be in-scope; the scan refuses if any is not |

Allowed private ranges (deny-by-default for everything else): IPv4 RFC1918 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16; IPv6 unique-local fc00::/7; loopback 127.0.0.0/8 and ::1 only for explicit local self-test scope profiles. Carrier-grade NAT 100.64.0.0/10 and link-local 169.254.0.0/16 are off by default and may be enabled per profile, but the cloud-metadata address 169.254.169.254 and its IPv6 equivalent are always denied. Multicast, broadcast, the unspecified address, and all globally routable addresses are always denied, as are the documentation ranges 192.0.2.0/24, 198.51.100.0/24, and 203.0.113.0/24 (R15, R16, R17).

## 5. User experience requirements

### UX-01 - First-run explanation

**Requirement.** Show a three-sentence panel before the first scan that defines active scanning, states the private-scope-only rule and the exploitation refusal, and explains valid input.

- The text is visible without opening help and can be restored from Help.
- It states plainly that the tool sends real packets and only to authorized private lab hosts.
- It includes examples: a scope like 10.0.0.0/24, a host like 10.0.0.5, and the loopback self-test target 127.0.0.1.

### UX-02 - Scope profiles

**Requirement.** Let the user create, name, edit, and activate lab scope profiles, and require an active profile before any scan.

- A profile lists CIDRs and hosts; each is validated to be inside the allowed private ranges on entry.
- A profile that contains anything outside the allowed ranges cannot be saved, and the error names the offending entry.
- The active profile is always visible while composing a scan.

### UX-03 - Target input

**Requirement.** Provide one target input with live classification and actionable inline validation, checked against the active scope.

- Valid targets are classified as host, IP, or CIDR before launch and previewed in canonical form.
- A target outside the active scope, a public address, or a hostname resolving out of scope shows a clear error and does not enable launch.
- The normalized target and its resolved in-scope addresses are shown before the user confirms.

### UX-04 - Authorization gate

**Requirement.** Require an unchecked ownership/written-permission attestation and offer an engagement note before every scan.

- Launch stays disabled until the attestation is checked.
- The attestation text, timestamp, scope profile, normalized target, and note are saved with the scan.
- The attestation and note appear in the report and the audit ledger export.

### UX-05 - Intensity profile

**Requirement.** Let the user pick a governed intensity profile and show the caps that profile enforces.

- Profiles (for example polite, normal, thorough) map to concrete concurrency, packet-rate, and timeout caps, all below a hard ceiling.
- The UI states the ceilings and that they cannot be exceeded, so the tool cannot be tuned into a flood.
- The chosen profile is recorded with the scan and shown in the ledger.

### UX-06 - Module readiness

**Requirement.** List scan modules before launch with description, target applicability, and readiness.

- Ready, native, needs-external-tool, not-applicable, and release-1.1 states use text and iconography, not color alone.
- A user may select a module whose optional dependency is missing; launch explains it will be skipped rather than failing the scan.
- External documentation links open in a new tab with safe rel attributes.

### UX-07 - Per-module progress

**Requirement.** Display progress for every selected module and a live tally of hosts and ports contacted.

- States are queued, running, done, failed, skipped, not-applicable, and done-cached, each with started/finished times and a plain reason for non-success.
- A running counter shows hosts probed and ports touched so the user always knows the scan's current footprint.
- SSE updates are announced politely to assistive technology; if SSE drops, polling keeps the page current and a cancel control is always reachable.

### UX-08 - Host-and-service map

**Requirement.** Present findings as a host-centric map grouped into Live Hosts, Ports and Services, Enumeration, and Vulnerabilities.

- Every finding shows its module, retrieval timestamp, summary, and a collapsed raw-evidence control.
- Raw banners, headers, and imported XML render as inert text; nothing from a target is executed or auto-loaded in the browser.
- Vulnerability findings show confidence, sources, the KEV flag, and an explicit unconfirmed label, and link to the service evidence they came from.
- Empty categories explain whether nothing was found, modules were skipped, or the category did not apply.

### UX-09 - Service inventory workspace

**Requirement.** Provide a sortable, filterable, keyboard-accessible host-and-service table suitable for Phase 3 handoff.

- Columns include host, port, protocol, state, service, product, version, confidence, and CVE-candidate count.
- Rows are normalized and deduplicated across native probes and imports.
- Copy selected, copy filtered, and CSV download give clear success and failure feedback and are protected against spreadsheet formula injection.
- Sorting and filters stay usable at tablet width without horizontal information loss.

### UX-10 - Search and filters

**Requirement.** Support global search across summaries, values, module names, service and version strings, and safe raw evidence.

- Search is debounced, case-insensitive, and combines with category, module, host, and state filters.
- The result count and active filters stay visible, and Clear all restores the unfiltered scan.
- No-results copy distinguishes nothing in the scan from nothing matching the filters.

### UX-11 - History and diff

**Requirement.** Allow any past scan to be reopened and two scans on the same scope to be compared.

- History shows scope, target, completion state, time, selected modules, warning count, and note preview.
- Diff labels evidence as added, changed, closed, or unchanged using stable fingerprints; a newly closed port is only reported when the module actually ran in both scans.
- If a module did not complete in both scans, its potential closures are labeled indeterminate, never closed.
- Scans on different scopes or targets cannot be compared.

### UX-12 - Deliberate interface states

**Requirement.** Design explicit initial, loading, empty, partial-success, fatal-error, offline, and out-of-scope-refusal states.

- Every state explains what happened and the next safe action.
- A scope refusal names exactly which target or address was out of scope and why.
- Retry operates at the module level where possible and preserves completed evidence.
- No state relies on indefinite animation; elapsed time and last update are visible for long-running scans.

### UX-13 - No client-originated target traffic

**Requirement.** The dashboard must never cause the user browser to contact a scanned host. Scanning is the backend's job alone.

- Host and service URLs render as inert, copyable text; nothing links directly to a scanned host.
- No favicon, image, iframe, media, preview, prefetch, preconnect, or DNS-prefetch may reference a scanned host.
- External links open with rel="noopener noreferrer" under a document-level no-referrer policy.
- A Playwright test asserts that no request issued by the client resolves to a scanned host or its addresses.

### UX-14 - Theme, responsiveness, and accessibility

**Requirement.** Meet WCAG 2.2 AA for core flows and support light and dark themes down to a 768-pixel tablet viewport.

- All interactive elements are keyboard reachable with visible focus, logical order, and descriptive names.
- Contrast, status semantics, error association, table headers, dialogs, and disclosure controls pass automated and manual review.
- Theme honors prefers-color-scheme on first visit and persists an explicit choice; reduced-motion disables non-essential transitions.

## 6. Functional and data requirements

### FR-01 - Scan creation and orchestration

**Requirement.** Create a persistent scan only after scope, target, module selection, intensity, and authorization validation succeed.

- POST /api/scans returns 202 with a scan identifier and initial per-module states.
- A durable SQLite queue claims queued work transactionally and prevents duplicate execution.
- The active scope is resolved and every target address is validated and recorded before any module is dispatched; no module runs while the in-scope destination set is empty.
- On restart, abandoned running module records become interrupted and the scan resumes or completes with warnings under idempotency rules.
- Global and per-host concurrency limits and the intensity ceiling are applied by the orchestrator, not by individual modules.

### FR-02 - Scan module contract

**Requirement.** Each module is an isolated unit implementing one typed contract and receiving only a guarded connector.

- Required metadata: name, display name, supported target types, category, optional dependency, timeout, rate policy, and cache policy.
- run(context) returns normalized Finding records and probe metadata, or raises a typed module error.
- Adding a module is registration through discovery/configuration, not a change to orchestration logic.
- Modules receive the ScanGuard connector and cannot open unrestricted sockets, use target-capable HTTP clients, or spawn network-capable subprocesses directly. Any future external scanner runner is a separate guarded adapter, not a module shortcut.

### FR-03 - ScanGuard - the only path to a target

**Requirement.** Route every target-bound probe through one policy-enforcing connector that denies by default.

- A destination is allowed only when it is inside the allowed private ranges and inside the active scope profile.
- Hostnames are resolved through the controlled local resolver; every resolved address is checked, and the target is rejected if any address is out of scope. The MVP must not use public DoH or arbitrary recursive resolvers for target names.
- CIDRs are expanded and every address validated before the first packet; the scan refuses rather than skipping an out-of-scope member.
- Loopback-inappropriate, multicast, broadcast, unspecified, cloud-metadata, and public destinations are denied even inside a mis-configured profile.
- The guard records every allowed and denied destination in the audit ledger.

### FR-04 - Intensity governor

**Requirement.** Bound the scan's footprint so it cannot degrade or deny service to an in-scope host.

- Global concurrent connections, per-host concurrent connections, and new-connections-per-second are capped, with a hard ceiling the profile cannot exceed.
- Per-port connect timeout, per-host budget, and per-scan budget are enforced; exceeding a budget ends that unit cleanly with a recorded reason.
- Connection errors trigger adaptive backoff for that host rather than retry storms.
- Governor decisions are visible in module diagnostics.

### FR-05 - Outbound provider gateway (CVE data)

**Requirement.** Route all third-party CVE traffic through one allowlisted HTTPS gateway, separate from the ScanGuard.

- Only NVD and CISA KEV hosts (and release-1.1 additions) are allowed; the user cannot supply a provider URL.
- No scanned host name, IP, or banner is ever sent to a provider; only product and version strings needed for correlation leave the machine.
- Redirects are disabled by default; retries use bounded exponential backoff with full jitter; a missing optional provider degrades gracefully.
- An identifying User-Agent naming the application, version, and repository is sent on every request.

### FR-06 - Response cache

**Requirement.** Cache provider responses and normalized correlation results by product, version, source, and schema version.

- Fresh cache entries eliminate outbound calls and produce a done-cached state.
- TTLs are provider-aware: NVD and KEV default to 24 hours; a forced refresh still obeys provider rate limits.
- Negative results may be cached briefly; authentication failures and malformed responses are not cached as success.

### FR-07 - Host discovery and port scanning

**Requirement.** Determine live hosts and open ports using unprivileged asyncio TCP connect probes, through the ScanGuard.

- Host discovery probes a small configurable common-port set and records the evidence that proved a host alive.
- Port scanning supports top-100, top-1000, a custom list, or full 1-65535, with open, closed, and filtered states distinguished by connection outcome.
- All concurrency and rate limits come from the governor; no module opens its own socket.
- ICMP and live Nmap-based discovery are outside the MVP unless a later guarded adapter is designed, reviewed, and tested as a separate boundary.

### FR-08 - Service detection and enumeration

**Requirement.** Identify services and gather read-only metadata on open ports without authenticating or writing.

- A bounded banner grab and minimal protocol probes infer service, product, and version with a confidence level. Live Nmap service detection is not part of the MVP because it would bypass the ScanGuard socket path.
- HTTP(S) enumeration collects status, server header, page title, security headers, and robots.txt; TLS collects certificate subject, SAN, issuer, and validity.
- No probe authenticates, submits a form, writes data, or sends an exploit payload.
- Ambiguous or absent evidence yields low confidence, never a fabricated version.

### FR-09 - Vulnerability correlation

**Requirement.** Correlate detected services and versions to known vulnerabilities from more than one source, and never claim confirmation.

- Detected product and version map to a CPE where possible and query NVD; every match is cross-checked against the CISA KEV catalog and flagged if known-exploited.
- Because NVD moved to a risk-based enrichment model in 2026, some CVEs may be listed before NVD adds severity, CPEs, or affected-product detail. Missing NVD enrichment is stated explicitly and does not imply no risk; additional sources may be added in release 1.1.
- Each correlation carries candidate CVE identifiers, CVSS where available, the KEV flag, a confidence level, the contributing sources, and an unconfirmed label.
- No correlation triggers an active check against the target.

### FR-10 - External scan import

**Requirement.** Ingest an Nmap XML file and normalize it into the native host and service model.

- Parsing uses strict limits on size, element counts, and nesting; malformed or oversized files are rejected with a typed error and never trusted.
- Every host in the import is validated against the active scope; out-of-scope hosts are flagged and excluded from the trusted inventory, not silently accepted.
- Imported findings are marked with their origin so the ledger distinguishes what ScanLedger probed from what was imported.
- Imported XML is treated as untrusted text and never rendered as markup.

### FR-11 - Findings, provenance, and the audit ledger

**Requirement.** Store each observation as a typed Finding, and record every probe in an append-only ledger.

- Finding fields: id, scan_id, host, port, category, kind, title, summary, normalized_value, raw_evidence, module, observed_at, confidence, sources, and fingerprint.
- fingerprint is derived from module, kind, host, port, and a canonical identity key so mutable attributes can be marked changed in a diff.
- The ledger records, per probe, the destination, port, module, timestamp, allowed/denied decision, and outcome, and is exportable as the engagement record.
- All timestamps are stored UTC ISO 8601 and shown in local time with UTC available.

### FR-12 - Exports

**Requirement.** Generate deterministic Markdown, JSON, host-service CSV, and audit-ledger exports from persisted evidence.

- Markdown supports summary and full modes; summary caps rows per category and points to the JSON for the complete record.
- Markdown includes scope, attestation time, intensity profile, methodology and limits, module status, findings by category, and generation time.
- CSV is UTF-8 with a header row and formula-injection protection; JSON carries a documented schema version.
- The audit-ledger export lists every host and port contacted and every denied destination, so scope compliance is provable; all exports regenerate from the database without new probes.

### FR-13 - History, deletion, and retention

**Requirement.** Persist scans locally with user-controlled deletion and configurable retention enforced by a sweep.

- Default retention is 90 days for scans and findings and provider-TTL for cache entries.
- Delete scan requires confirmation and removes dependent module runs, findings, and ledger rows transactionally.
- A Clear cache action reports what will be deleted before confirmation.
- Retention and cache expiry run at startup and after every scan reaches a terminal state, not as a manual step.

### 6.1 Finding schema

| Field | Type | Purpose |
| --- | --- | --- |
| id / scan_id | UUID / UUID | Local evidence identity and parent scan |
| host / port | string / int? | The in-scope host and port the evidence concerns |
| category | enum | live_host, port_service, enumeration, vulnerability |
| kind | string | Machine-readable subtype such as port.open, http.header, tls.cert, cve.candidate |
| title / summary | string | Human-readable evidence statement |
| normalized_value | JSON | Typed canonical data used by filters, the inventory, exports, and diff |
| raw_evidence | JSON or text | Sanitized banner, header, certificate, or imported fragment, displayed inertly |
| module | string | Stable module name that produced the finding |
| observed_at | datetime | UTC time the evidence was retrieved |
| confidence | enum? | Required for inferred versions and CVE correlations |
| sources | JSON | Providers or the import that contributed (for correlations) |
| fingerprint | SHA-256 | Stable identity for deduplication and diff |

## 7. Technical architecture

### 7.1 Architecture summary

React with TypeScript is justified by the dashboard's live progress, compound filtering, evidence disclosure, host map, and diff. FastAPI, Pydantic, and an asyncio scan engine keep request, response, and module contracts typed while making many concurrent connect probes natural. SQLite is sufficient for a local single-user tool and can own scans, evidence, the ledger, and cache when writes are short and serialized. A small SQLite-backed worker avoids Redis while preserving queued work and restart recovery, and Server-Sent Events are simpler than WebSockets for one-way progress with a status endpoint as fallback. The two egress boundaries are the key safety decision: the ScanGuard is the only path to a target socket and the outbound gateway is the only path to a provider, and no module or browser code may open an unguarded connection. These boundaries are reviewed and tested like authentication code.

### 7.2 Component responsibilities

| Component | Responsibility |
| --- | --- |
| React client | Scope management, target validation preview, module selection and intensity, authorization form, SSE/polling, host map, evidence UI, search, inventory, history, diff, and exports |
| FastAPI service | Typed API, validation, module and scope catalogs, report/export and ledger generation, origin controls, errors, and coordination with the scan runner |
| SQLite + SQLAlchemy | Scans, module runs, host and service results, findings, ledger, cache, scope profiles, attestations, migrations, indexes, and transactional state |
| Scan runner | Claim scans, resolve and validate scope before dispatch, schedule modules, apply the governor and concurrency, resume interrupted scans, publish events, run retention |
| ScanGuard | The sole target-socket path: private-range and scope enforcement, resolver validation, CIDR expansion checks, denial of forbidden destinations, and ledger recording |
| Intensity governor | Global and per-host concurrency, packet-rate ceilings, budgets, and adaptive backoff |
| Outbound gateway | HTTPS-only allowlist for CVE providers, redirect validation, timeouts, retry, rate limiting, caching, and data-minimized requests |
| Scan modules | Native probing and parsing behind the guard; typed errors; no direct target networking or scanner subprocesses |
| Correlation engine | Version-to-CVE matching over provider and cache data; no target I/O |

### 7.3 Scan and module state model

| Level | States | Rule |
| --- | --- | --- |
| Scan | queued, running, completed, completed_with_warnings, failed, canceled | failed only when orchestration cannot run or no module produces a valid terminal result; canceled stops in-flight probes |
| Module | queued, running, done, failed, skipped, not_applicable, interrupted | done stores finding_count and cache_hit; every other terminal state stores a safe reason |
| Progress | event sequence + updated_at + footprint counters | SSE is advisory; GET status is authoritative and supports reconnect with last event ID |

### 7.4 Core API contract

| Method and route | Purpose | Key response |
| --- | --- | --- |
| GET /api/modules | Module catalog and readiness | Target support, state, dependency, release |
| GET /api/scopes | List scope profiles | Profiles with validation state |
| POST /api/scopes | Create a validated scope profile | ScopeRead or typed error |
| PUT /api/scopes/{id}  DELETE /api/scopes/{id} | Edit or remove a profile | Updated profile or 204 |
| POST /api/scans | Validate scope+authorization and queue a scan | 202 ScanRead with module states |
| GET /api/scans | Paginated/filterable history | ScanSummary list |
| GET /api/scans/{id} | Authoritative scan status | ScanDetail and module runs |
| GET /api/scans/{id}/events | Live one-way progress | SSE events with sequence IDs and footprint counters |
| POST /api/scans/{id}/cancel | Kill switch | Halts in-flight probes; updated states |
| GET /api/scans/{id}/hosts | Host-and-service workspace | Normalized rows and facets |
| GET /api/scans/{id}/findings | Search/filter/sort findings | Paginated FindingRead |
| GET /api/scans/{id}/export?format={md\|json}&mode={summary\|full} | Report/tool export | Download generated from DB |
| GET /api/scans/{id}/hosts.csv | Phase 3 inventory handoff | Formula-safe UTF-8 CSV |
| GET /api/scans/{id}/ledger | Audit ledger export | Every probed and denied destination |
| GET /api/scans/{id}/diff?against={scan_id} | Evidence-aware comparison | Added/changed/closed/indeterminate groups |
| POST /api/scans/{id}/modules/{name}/retry | Retry one eligible failure | Updated module state |
| POST /api/scans/import/nmap | Ingest external Nmap XML | Normalized scan with scope-flagged hosts |
| GET /api/cache  DELETE /api/cache | Cache inventory and purge | Counts/summary; 204 after confirmed deletion |
| DELETE /api/scans/{id} | Delete a local scan | 204 after dependent evidence removal |

### 7.5 Persistence model

| Table | Key fields and notes |
| --- | --- |
| scope_profiles | id, name, entries_json (validated CIDRs/hosts), enabled flags, created/updated timestamps |
| scans | id, scope_id, target_input, target_normalized, target_type, resolved_addrs_json, intensity_profile, status, note, attestation_text/version/time, selected_modules_json, timestamps |
| module_runs | id, scan_id, module, status, attempt_count, cache_hit, finding_count, safe_error_code/message, started/finished timestamps |
| host_results | id, scan_id, host/address, state, discovery_evidence, timestamps |
| service_results | id, scan_id, host, port, protocol, state, service, product, version, confidence, evidence |
| findings | Finding schema fields; indexes on scan/category/module/host/port/fingerprint and an FTS5 projection for search (FTS5 tables and triggers are created by explicit migration, not autogenerate) |
| cve_matches | id, service_result_id, cve_id, cvss, kev_flag, confidence, sources_json, unconfirmed flag |
| scan_ledger | id, scan_id, destination, port, module, decision (allowed/denied), reason, outcome, created_at; append-only |
| cache_entries | cache_key, source, schema_version, status, response_json, normalized_json, retrieved_at, expires_at |
| scan_events | monotonic sequence, scan_id, module, event_type, payload_json, created_at; retained for reconnect and diagnostics |
| schema_version | Alembic migration state with batch mode enabled, because SQLite cannot alter or drop columns in place; startup never relies on create_all |

### 7.6 ScanGuard interface contract

```text
ScanGuard
  allowed_ranges: immutable private-range set (RFC1918, ULA, loopback; opt-in CGNAT/link-local)
  active_scope: validated CIDRs/hosts for this scan
  resolver: controlled DNS resolver used for hostname targets

  validate_target(target) -> InScopeAddressSet | Rejection
    resolves hostnames, expands CIDRs, checks every address against
    allowed_ranges AND active_scope, denies forbidden classes, records to ledger

  connect(address, port) -> guarded socket
    the ONLY way a module reaches a target; re-checks the destination,
    applies the governor, and records the probe before the socket opens
```

**Design advice.** No module may import socket APIs, `asyncio.open_connection`, target-capable HTTP clients, or scanner subprocesses directly. Expose only `ScanGuard.connect` for targets and the outbound gateway for providers, and fail the build if any other network primitive is imported outside those approved boundary modules. If live Nmap orchestration is considered later, it must be a guarded adapter with prevalidated literal targets, fixed safe flags, ledger recording, and its own design review.

### 7.7 Recommended repository structure

```text
scanledger/
  README.md
  LICENSE            (MIT)
  .env.example
  .gitignore
  .github/workflows/ci.yml
  docker-compose.yml
  backend/
    pyproject.toml
    alembic.ini
    app/
      main.py
      config.py
      api/{scans,scopes,modules,exports,imports,diffs}.py
      models/{api,domain,db}.py
      db/{session,tables}.py
      scan/{runner,service,events,governor}.py
      guard/{scanguard,ranges,resolver,ledger}.py
      modules/
        base.py
        registry.py
        host_discovery.py
        port_scan.py
        service_detect.py
        protocol_enum.py
        cve_correlate.py
        nmap_import.py
      services/{outbound,cache,retry,diff,search,reports,retention}.py
      security/{targets,redaction,origins,exports}.py
    alembic/versions/
    tests/{unit,integration,fixtures}/
  frontend/
    package.json
    vite.config.ts
    src/
      api/generated/   (TypeScript client from OpenAPI)
      components/
      features/{scope,launch,progress,findings,inventory,history,diff}/
      pages/  styles/  test/
    e2e/
  docs/screenshots/
  docs/PRD.md          (Markdown copy of this document)
```

## 8. Safety, security, and privacy requirements

### 8.1 Scope enforcement

- All target-bound code lives behind the ScanGuard; a repository test fails if any module imports sockets, target-capable HTTP clients, or network-capable subprocesses directly.
- The allowed private ranges are code-defined constants. The user can define scope profiles only as subsets of those ranges; the user cannot supply a resolver, a redirect destination, or a raw address outside them.
- Hostname targets are resolved through the controlled resolver and every resolved address is validated, so a lab hostname that points at a public IP is rejected rather than scanned.
- CIDR targets are expanded and every address validated before probing; the scan refuses if any member is out of scope.
- The cloud-metadata address, multicast, broadcast, the unspecified address, and all public addresses are denied even inside a mis-configured profile.
- The test suite blocks sockets process-wide, so any code path that opens a connection outside the ScanGuard or the outbound gateway fails the build.

### 8.2 Intensity and denial-of-service safety

- Concurrency and packet-rate ceilings are enforced by the governor and cannot be exceeded by any intensity profile or configuration.
- Per-host and per-scan budgets bound total work; adaptive backoff replaces retry storms when a host shows errors.
- The default profile is conservative, and the UI states that the ceilings exist specifically so the tool cannot deny service to its own lab.

### 8.3 Input, content, and export safety

- Reject URL schemes, ports in host fields, control characters, overlong input, and any target outside the active scope at the input boundary.
- Parse untrusted banners, headers, certificates, and imported XML with strict size, count, and nesting limits and typed errors.
- Render all target-derived evidence as inert text; never inject a banner, header, or imported fragment into the DOM as markup.
- Protect CSV cells beginning with =, +, -, @, tab, or carriage return against formula execution.
- Enforce local-origin and JSON content-type checks on state-changing requests.
- Render host and service references as inert text and disable favicons, previews, and speculative connections for any scanned host, so the browser never contacts a target.

### 8.4 Secrets, logging, and provider etiquette

- Load any optional keys (for example an NVD API key) from environment or a local .env excluded from source control; commit .env.example with names and links only.
- Never send a scanned host name, address, or banner to a third-party provider; only product and version strings needed for correlation leave the machine.
- Redact secrets and sensitive headers from structured logs; the readiness endpoint reports only configured or not-configured, never a key value.
- Bind to 127.0.0.1 by default; a non-loopback bind requires an explicit insecure-development acknowledgement in configuration.
- Send an identifying User-Agent to CVE providers, honor Retry-After, and stay within documented provider limits.

### 8.5 Future exploitation requests

**Required response.** If a future request asks to add exploitation, credential attacks, denial-of-service behavior, raw-socket scanning, or scanning of public addresses, the maintainer or implementation AI must refuse the change because it violates the product's approved threat model and the Phase 2 boundary. Recommend a separate, clearly labeled Phase 3 lab tool with its own authorization controls and review rather than weakening ScanLedger.

## 9. Non-functional requirements

| Area | Requirement |
| --- | --- |
| Compatibility | Python 3.11+; current evergreen Chromium/Firefox; tablet viewport from 768 px; Windows, macOS, and Linux developer setup documented, with unprivileged TCP connect scanning working on Windows without admin |
| Performance | Local API p95 under 200 ms for stored-scan reads with 10,000 findings; search/filter feedback under 300 ms; scan throughput bounded by the governor, not by blocking I/O |
| Concurrency | Default one scan at a time; governor ceilings for global and per-host connections and connections-per-second; configurable below the hard ceiling without code changes |
| Process model | The durable worker runs in-process, so the API is served by a single worker process; a multi-process launch is rejected at startup unless an external worker is configured |
| Timeouts | Documented connect, per-host, and per-scan budgets with per-module overrides; CVE-provider requests default to a 30-second timeout |
| Reliability | No successful findings are lost because another module fails; state transitions are transactional and idempotent; the ledger is append-only |
| Observability | Structured logs with scan/module/probe correlation IDs, latency, attempt, cache outcome, and safe error code; no secrets and no exfiltration of target data |
| Maintainability | Strict type checking, formatting/linting, migrations, a documented module contract, and fixture-based provider and Nmap schemas |
| Accessibility | WCAG 2.2 AA core-flow target with keyboard, screen-reader, contrast, focus, reduced-motion, and semantic-table review |
| Licensing | MIT license; notices for bundled dependencies and assets |

## 10. Testing and definition of done

### 10.1 Automated test strategy

- ScanGuard tests are the crown jewels: a public IP is rejected, a hostname resolving to a public IP is rejected, a metadata/multicast/broadcast/unspecified address is rejected, a CIDR partly outside scope is rejected, and an out-of-scope host in an import is flagged and excluded.
- A process-wide socket block is enabled for the whole suite, and a test proves the ScanGuard connector and the outbound gateway are the only code paths that can open a socket.
- Governor tests prove global and per-host concurrency and the connections-per-second ceiling are honored under load, and that no profile can exceed the hard ceiling.
- Module unit tests use mocked transports: host discovery and port-state logic, banner/version parsing with confidence, HTTP/TLS enumeration parsing, Nmap XML import with scope flagging, and CVE correlation with mocked NVD and KEV responses including a missing-NVD-enrichment case.
- Orchestration tests cover cache hits, negative cache, timeout/budget, partial completion, cancellation halting in-flight probes, restart recovery, and duplicate-scan claims.
- Diff tests prove that a module which did not run in both scans produces indeterminate results, never a false closed-port or removed-vulnerability.
- A client network test asserts the dashboard issues no browser request to a scanned host, including favicons, images, and speculative connections.
- A contract check regenerates the TypeScript client from the OpenAPI schema and fails on drift; CI performs no live network calls.

### 10.2 Required module test cases

| Module | Mock cases | Pass condition |
| --- | --- | --- |
| ScanGuard | Public IP, rebinding hostname, metadata IP, multicast/broadcast, CIDR partly out of scope, valid in-scope host | Every unsafe destination denied and ledgered; only in-scope destinations reach connect |
| Port scan | Open, closed, filtered, timeout, host budget exceeded | States correct; governor ceilings honored; no socket outside the guard |
| CVE correlation | NVD match, NVD missing-enrichment, KEV hit, no match, provider 429/malformed | Matches labeled unconfirmed with sources and confidence; missing enrichment stated; failure never fails the scan |
| Nmap import | Valid XML, oversized/malformed XML, out-of-scope host, duplicate host | Malformed rejected; out-of-scope flagged and excluded; normalized identity stable |

### 10.3 Definition of done

- Every MVP requirement and acceptance criterion is implemented or explicitly removed through an approved PRD revision.
- Fresh install succeeds from README instructions on Windows without undocumented global dependencies.
- The repository contains .env.example and no committed secrets; secret scan passes.
- Database migrations create and upgrade a clean SQLite database with batch mode.
- All automated tests, type checks, linters, and production builds pass in CI without live provider or target access.
- A recorded lab walkthrough demonstrates a scope refusal of a public address, a successful in-scope scan, a cached correlation, history/diff, and all exports including the ledger.
- README contains the legal notice, architecture overview, native Windows setup, provider/key notes, limitations, real screenshots, and the exploitation-refusal policy.
- Manual checks confirm no out-of-scope traffic in the ledger, no client requests to a scanned host, no HTML execution of evidence, and no CSV formula execution.
- Core flows pass keyboard and WCAG AA review in both themes at desktop and tablet widths.

### 10.4 Verification walkthrough acceptance

1. Start the API and client locally with no optional keys. Confirm all MVP modules are ready and release 1.1 modules show not-installed.
2. Define a lab scope of 127.0.0.0/8 (and, if provided, the analyst's lab CIDR). Attempt to scan a public address and confirm the ScanGuard refuses it and the refusal names the reason.
3. Run a Vulhub or similar intentionally-vulnerable container on 127.0.0.1, launch a scan of 127.0.0.1 across all MVP modules, and observe independent module states and the live footprint counter.
4. Confirm Live Hosts, Ports and Services, and Enumeration populate from native probes, and Vulnerabilities shows unconfirmed CVE candidates with sources and any KEV flags.
5. Filter and copy the service inventory, expand safe raw evidence, and search for a port, product, or CVE.
6. Re-run the same scan within cache TTL and confirm correlation is served from cache with a done-cached state.
7. Compare two scans and confirm additions and changes are traceable and modules that did not complete are not reported as closed.
8. Download Markdown, JSON, CSV, and the audit ledger; confirm the ledger shows only in-scope destinations were probed and the public address appears as denied.
9. Import an Nmap XML file that includes an out-of-scope host and confirm that host is flagged and excluded from the trusted inventory.

## 11. Risks and mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| A probe reaches an out-of-scope or public host | The core promise and the law are violated | ScanGuard deny-by-default, resolver and CIDR validation, process-wide socket block, append-only ledger, attestation |
| The tool floods or denies service to a lab host | Damage to the user's own environment | Intensity governor with hard ceilings, per-host budgets, adaptive backoff, conservative default profile |
| NVD 2026 enrichment gaps | Missing severity, CPE, or affected-product detail creates false confidence | Multi-source correlation (NVD + CISA KEV), explicit missing-enrichment state, unconfirmed labels, room for more sources in 1.1 |
| Client-side contact with a scanned host | The browser touches a target the backend governed carefully | Inert host references, disabled previews and speculative connections, no-referrer policy, Playwright network assertions |
| Live external scanner integration risk | A future Nmap adapter could bypass the ScanGuard if designed casually | Keep live Nmap out of MVP; require a guarded adapter design review, fixed safe flags, prevalidated literal targets, and ledger recording before release 1.1 |
| Untrusted imported scan files | Parser abuse or poisoned inventory | Strict parse limits, scope validation on every imported host, evidence treated as untrusted text |
| False-positive vulnerabilities | Misleading risk claims | Correlation-only, confidence levels, KEV flag, observed-vs-inferred distinction, unconfirmed label |
| Raw-socket/privilege portability | Broken scans or an admin requirement on Windows | Unprivileged TCP connect default; raw modes explicitly out of scope |
| SQLite write contention | Progress delays under concurrency | Short transactions, WAL mode, one writer path, modest default concurrency |
| Duplicate scan execution under multi-process launch | Two workers claim one scan; doubled probes | Single-process default, transactional claim, startup rejection of an unsupported process model |
| Frontend/backend contract drift | Broken dashboard during changes | Generated TypeScript types from OpenAPI and a CI contract check |

## 12. Ranked roadmap and engineering advice

### 12.1 What to build next

| Rank | Milestone | Why this order |
| --- | --- | --- |
| 1 | Ship the guarded vertical slice | ScanGuard, governor, scope profiles, host discovery, and port scan, with a minimal UI and the ledger, before any other module - the safety boundary must exist and be proven first |
| 2 | Add service detection and enumeration | Turn open ports into identified services and read-only metadata with confidence |
| 3 | Add multi-source CVE correlation | NVD plus CISA KEV, unconfirmed labels, and the missing-enrichment state |
| 4 | Add inventory, history, diff, exports, and import | Make repeated scanning meaningfully better than one-off tools, and interoperate with Nmap |
| 5 | Add release 1.1 heavier enumeration | SMB, SNMP, UDP, and authenticated read-only enumeration once the governed foundation is proven |

### 12.2 Senior engineering advice

- Build and fully test the ScanGuard and the governor in isolation before any module. They are the product's security boundary and its promise not to be a weapon; review them like authentication code.
- Define the Finding schema, the ledger, and the error taxonomy before polishing the dashboard. The map, diff, exports, and audit record all depend on stable evidence.
- Build a guarded three-module slice (discovery, port scan, service detection) with a thin UI before broadening. Proving safety, persistence, progress, and the ledger end to end matters more than module count.
- Treat the browser as part of the boundary. A backend that never leaves scope says nothing about a favicon the dashboard loads from a scanned host.
- Keep correlation honest. The most damaging mistake a junior scanner makes is reporting a correlated CVE as a confirmed finding; the unconfirmed label and KEV flag are features, not decoration.
- Keep a Markdown copy of this document in the repository so an implementation assistant can read it and requirement changes are reviewable in version control.

## 13. References

These sources establish the methodology context and current provider assumptions. Provider terms, endpoints, and data policies must be rechecked immediately before implementation because they can change.

R1. [NIST SP 800-115, Technical Guide to Information Security Testing and Assessment](https://csrc.nist.gov/pubs/sp/800/115/final)
R2. The Portable Course - Phases of Penetration Testing (local course module supplied with this review)
R3. [NVD CVE API 2.0 documentation](https://nvd.nist.gov/developers/vulnerabilities)
R4. [NVD API rate limits and API key request](https://nvd.nist.gov/developers/request-an-api-key)
R5. [NVD risk-based prioritization announcement (2025-2026)](https://nvd.nist.gov/general/news)
R6. [CISA Known Exploited Vulnerabilities (KEV) Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
R7. [Nmap Reference Guide](https://nmap.org/book/man.html)
R8. [MITRE ATT&CK T1046 - Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
R9. [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
R10. [Common Platform Enumeration (CPE)](https://nvd.nist.gov/products/cpe)
R11. [CVSS specification](https://www.first.org/cvss/)
R12. [W3C Web Content Accessibility Guidelines (WCAG) 2.2](https://www.w3.org/TR/WCAG22/)
R13. [MITRE ATT&CK - Discovery tactic](https://attack.mitre.org/tactics/TA0007/)
R14. [Computer Fraud and Abuse Act overview](https://www.justice.gov/criminal/criminal-ccips)
R15. [RFC 1918 - Address Allocation for Private Internets](https://www.rfc-editor.org/rfc/rfc1918)
R16. [RFC 4193 - Unique Local IPv6 Unicast Addresses](https://www.rfc-editor.org/rfc/rfc4193)
R17. [RFC 6598 - IANA-Reserved IPv4 Prefix for Shared Address Space (CGNAT)](https://www.rfc-editor.org/rfc/rfc6598)
R18. [RFC 5737 - IPv4 Address Blocks Reserved for Documentation](https://www.rfc-editor.org/rfc/rfc5737)
R19. [Alembic - batch (move-and-copy) migrations for SQLite](https://alembic.sqlalchemy.org/en/latest/batch.html)
R20. [SQLite FTS5 full-text search extension](https://www.sqlite.org/fts5.html)

## Appendix A. Requirements discovery record

The PRD was created after the following decisions were confirmed. They are incorporated as requirements rather than left open.

| Question | Answer | Effect on PRD |
| --- | --- | --- |
| What shape should the Phase 2 app take? | Lab-locked active scanner | A real scanner confined to private scope, with structural enforcement as the central design |
| How is the passive-only model replaced? | Inverted into a scope lock | ScanGuard becomes the sole target-socket path; only private, in-scope, attested destinations are reachable |
| What is delivered now? | Full PRD + AI handoff | This document plus a separate ready-to-paste implementation prompt and a Markdown copy of the PRD |

## Appendix B. Implementation AI handoff protocol

The ready-to-paste prompt is delivered as ScanLedger_AI_Implementation_Handoff.md, and a Markdown copy of this document is delivered as ScanLedger_PRD.md so the implementation assistant can read the requirements without opening a Word file. Its required sequence is:

1. Read this entire PRD and treat it as the source of truth. Where the prompt and the PRD disagree, the PRD wins.
2. Summarize the product, the scope-lock boundary, the MVP release boundary, and the architecture, and identify contradictions or risks.
3. Review the pre-answered project questions in the prompt, then ask up to five consequential questions that neither the PRD nor those answers resolve.
4. Wait for all answers and continue short follow-up cycles until the requirements are implementable.
5. Propose a milestone plan and wait for approval before creating code or files.
6. Build in reviewable checkpoints, ScanGuard and governor first, because a repository of this size does not fit in a single response and an assistant compressing it will quietly thin the code.
7. Re-check each provider's current documentation immediately before implementing that module, especially NVD status labels, NVD rate limits, and the CISA KEV feed schema.
8. State plainly which verification steps could not be executed, and never describe an unexecuted step as passing.

> **Handoff guardrail:** The implementation AI is explicitly instructed to refuse any later request for exploitation, credential attacks, denial-of-service behavior, raw-socket scanning, or scanning of public addresses, and to recommend a separate authorized Phase 3 lab tool instead.

## Appendix C. Relationship to ReconLedger

ScanLedger is the Phase 2 sibling of ReconLedger, the Phase 1 passive-reconnaissance workbench. The two are deliberately built on the same architecture - React and TypeScript over async FastAPI, SQLite with SQLAlchemy async, Alembic batch migrations, FTS5 search, an in-process durable worker, and SSE progress - so the pair reads as one engineered suite and demonstrates consistent design across a tool family. That consistency is itself a portfolio argument.

The tools are mirror images on safety. ReconLedger must never contact the target and routes all traffic to third-party providers through an outbound gateway. ScanLedger may contact only the target, and only a private, in-scope, attested one, through the ScanGuard. ScanLedger keeps ReconLedger's outbound gateway too, but uses it solely for CVE data, never for target contact.

They also compose. ReconLedger's output - authorized domains and IP ranges - is the natural input to a ScanLedger scope, and ScanLedger's output - a host and service inventory with correlated, unconfirmed vulnerabilities - is the natural handoff to Phase 3. ScanLedger adopts every implementation-readiness practice ReconLedger reached in its version 1.1 revision from its first version: the structural network boundary, the browser-side isolation rule, batch-mode migrations with explicit FTS5, the single-process guard, provider documentation rechecks, bounded Markdown exports, a realistic usability measure, and an honest-verification clause.

| Dimension | ReconLedger (Phase 1) | ScanLedger (Phase 2) |
| --- | --- | --- |
| Boundary | Never contact the target | Contact only a private, in-scope, attested target |
| Enforcement | Outbound gateway to allowlisted providers | ScanGuard as the sole target-socket path, plus the outbound gateway for CVE data |
| Primary risk | Leaking target contact from the client | Scanning out of scope or denying service to the lab |
| Evidence | Source-attributed passive findings | Host/service findings plus an append-only audit ledger |
| Handoff | Domains and ranges out | Scope in; service inventory and unconfirmed CVEs out |

