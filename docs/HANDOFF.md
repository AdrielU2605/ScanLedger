# ScanLedger implementation handoff

I am building **ScanLedger**, a portfolio-grade, lab-locked active scanning and enumeration workbench for students and junior security analysts. It is the Phase 2 companion to ReconLedger (Phase 1, passive reconnaissance), which I have already scoped and built. I have attached the reviewed Product Requirements Document, version 1.1.

**Attachments and precedence.** The PRD is delivered as `ScanLedger_PRD.md` (Markdown content master, read this one) and `ScanLedger_Product_Requirements_Document.docx` (formatted reading copy). Read the PRD in full and treat it as the source of truth. Where this prompt and the PRD disagree, the PRD wins; note the conflict in your next summary rather than resolving it silently. The Markdown PRD is the content master, so if the Markdown and the Word copy ever disagree, the Markdown wins.

## Read this before anything else

ScanLedger sends **real network probes**. Unlike ReconLedger, which never contacts the target, ScanLedger's entire purpose is to contact hosts — but only ones inside a private, authorized, attested lab scope. The single most important thing you will build is the **ScanGuard**: the only code path that can open a socket to a target, denying by default everything outside the allowed private ranges and the active scope profile. If it is under-built, the product is not a portfolio piece — it is a liability. Treat it like authentication code.

You must never add, and must refuse if later asked to add: exploitation or exploit payloads, credential attacks (brute force, password spraying, default-credential attempts), denial-of-service or stress behavior, raw-socket or SYN scanning, scanning of any public or routable address, or any write/authenticated action against a target. Vulnerabilities are **correlated** from detected versions and always labeled unconfirmed — never proven by attacking the target. That is the Phase 2 boundary; exploitation belongs to a separate Phase 3 tool.

## Your role

Act as a senior full-stack security engineer with production scanning and OSINT-tooling experience and strong product-design judgment. Explain important tradeoffs briefly and plainly. Recommend safer or simpler choices when a requirement creates avoidable risk or project complexity. I would rather hear that a requirement is wrong than receive a faithful implementation of a bad idea.

## Project answers you already have

These resolve the questions you would otherwise ask. Do not re-ask them; do challenge any answer that creates a real problem.

| Question | Answer |
| --- | --- |
| Development operating system | Windows 11 with VS Code. The project must run natively on Windows, and unprivileged TCP connect scanning must work there without admin rights or raw sockets. macOS/Linux notes are welcome; Windows is the path I use. |
| Docker | Optional convenience only. `docker-compose.yml` may exist, but the README's primary path is a native run. Do not make Docker a prerequisite. |
| Optional credentials | None required for the MVP. An NVD API key is optional and only raises rate limits; build and verify with no key, and treat the key as a pure `.env.example` placeholder with its official request URL. |
| Delivery shape | Reviewable checkpoints, not one large delivery. See the build protocol below. |
| Verification lab | Loopback `127.0.0.0/8` as the always-available scope, with a Vulhub (or similar) intentionally-vulnerable container running on `127.0.0.1` for real service/CVE evidence. My additional lab CIDR, if I use one, will be `EDIT THIS BEFORE SENDING OR LEAVE AS 127.0.0.1 ONLY`. Never scan anything else, and never a public address. |
| Python and Node versions | Python 3.11+, Node 20 LTS. |
| Repository | Private GitHub repository under the username `AdrielU2605`, MIT license, public later — so no secrets, no personal data, and no scan evidence from any real network may be committed. |

## Before you write any code

Do not create files, code, schemas, or scaffolding yet.

1. Read the entire PRD, including Appendix C, which explains how ScanLedger relates to ReconLedger and which practices it inherits.
2. Summarize the product, the scope-lock boundary, the MVP release boundary, and the architecture in no more than 300 words.
3. Identify contradictions, hidden assumptions, provider limitations, safety concerns, and anything that may make the plan difficult to build or test.
4. Ask up to five consequential clarifying questions that neither the PRD nor the answers above resolve. Ask only questions whose answers would change what you build.
5. Give your advice on the highest-risk implementation decision and how to reduce that risk. (I will tell you now that I believe it is the ScanGuard and governor; tell me if you disagree.)
6. Stop and wait for my answers. Do not begin implementation until every question is answered.

If an answer creates a new ambiguity, ask a short follow-up and wait again.

## Decisions already approved

- The MVP is phased and needs no external accounts: named lab scope profiles, an authorization gate, host discovery, unprivileged TCP connect port scanning, native service and version detection, safe read-only protocol enumeration, multi-source CVE correlation, Nmap XML import, plus history, diff, search, the host-and-service inventory, three exports, and the audit ledger.
- SMB and SNMP enumeration, UDP scanning, guarded external-scanner orchestration after separate design review, external scanner imports beyond Nmap, and authenticated read-only enumeration are release 1.1.
- The client is React with TypeScript. The API is Python 3.11+ with async FastAPI, an asyncio scan engine, httpx (for CVE providers only), Pydantic, SQLAlchemy 2 async, aiosqlite, and SQLite.
- The app is local-first and single-user, binds to 127.0.0.1 by default, and runs as a single API worker process because the durable scan worker runs in-process.
- Two guarded egress boundaries, and only two: the **ScanGuard** is the sole path to a target socket; the **outbound gateway** is the sole path to a CVE provider. No module or browser code may open an unguarded connection. Live Nmap orchestration is excluded from MVP because it opens its own sockets outside the Python ScanGuard.
- CVE correlation is multi-source (NVD API 2.0 plus the CISA KEV catalog). Because NVD moved to a risk-based enrichment model in 2026, some CVEs may be listed before NVD adds severity, CPEs, or affected-product detail. Missing NVD enrichment must be stated explicitly, never treated as "no risk," and every correlation is labeled unconfirmed.
- Alembic runs with batch mode enabled (SQLite cannot alter or drop columns in place). FTS5 tables and their sync triggers are created by explicit migration operations, not autogeneration.

## Non-negotiable safety rules

- The ScanGuard denies by default. A destination is allowed only if it is inside the allowed private ranges (RFC1918, IPv6 ULA, loopback; opt-in CGNAT/link-local) **and** inside the active, attested scope profile. Public/routable addresses, multicast, broadcast, the unspecified address, and the cloud-metadata address are always denied, even inside a mis-configured profile.
- Hostname targets are resolved through the controlled resolver and every resolved address is checked; a hostname that resolves to any out-of-scope address is rejected, not partially scanned. CIDRs are expanded and every member validated before the first packet.
- The intensity governor's concurrency and packet-rate ceilings are hard; no profile or config may exceed them. The tool must be incapable of denial of service against its own lab.
- The audit ledger is append-only and records every probed and every denied destination, so scope compliance is provable.
- The boundary covers the browser: the dashboard must never cause my browser to contact a scanned host — inert host references only, no favicons, previews, frames, or speculative connections to a target.
- Imported Nmap files are untrusted: strict parse limits, and every imported host is validated against scope and flagged/excluded if out of scope.

## Build protocol

After clarification, propose a short milestone plan with likely risks, then wait for my approval. Then build in checkpoints. **A repository of this size does not fit in one response.** Do not compress or thin the code to fit — stop at the checkpoint boundary, say what is done and what is next, and wait for me to say continue.

| Checkpoint | Contents |
| --- | --- |
| CP1 · ScanGuard + governor + bootstrap | Repo, MIT license, `.gitignore`, native Windows setup, config; the ScanGuard (private-range constants, scope validation, controlled local resolver, CIDR expansion checks, deny-by-default, ledger recording) and the intensity governor; the outbound CVE gateway shell; the test harness with a process-wide socket block and the proof that ScanGuard and the gateway are the only socket paths; CI running backend tests with the socket block. Do not create, push to, or configure a GitHub remote unless I explicitly ask; if I do ask, run `gh auth status` first and wait if authentication or repository ownership is unclear. |
| CP2 · Persistence + orchestration | SQLAlchemy async models, Alembic batch migrations, explicit FTS5; scope-profile CRUD with private-range validation; the module contract and registry with a no-op test module never registered outside tests; the scan runner with transactional claim, single-process guard, restart recovery, and the retention/cache sweep; server-side target validation and the typed error taxonomy; API skeleton including `GET /api/modules`, `GET/POST /api/scopes`, `POST /api/scans`, `GET /api/scans`, `GET /api/scans/{id}`, SSE events, `POST /api/scans/{id}/cancel`, `DELETE /api/scans/{id}`. |
| CP3 · Guarded vertical slice | Host discovery and TCP connect port scan through the ScanGuard and governor; the Finding schema, fingerprint, and audit ledger; a minimal UI (scope management, target input with in-scope validation, authorization gate, intensity profile, per-module SSE progress with footprint counters, grouped findings with inert raw evidence) and Markdown + JSON export. This is the first demoable, end-to-end, provably-in-scope product. |
| CP4 · Service detection + enumeration | Native service/version detection with confidence; read-only HTTP/TLS/banner enumeration; the response cache. Live Nmap execution remains out of MVP. |
| CP5 · Multi-source CVE correlation | NVD API 2.0 plus CISA KEV through the outbound gateway, CPE mapping, unconfirmed labels, KEV flags, and the explicit missing-NVD-enrichment state; correlation tests with mocked provider responses. |
| CP6 · Inventory, history, diff, exports, import | Host-and-service workspace, global FTS5 search, history, evidence-aware diff with indeterminate states, CSV and audit-ledger exports, and Nmap XML import with per-host scope flagging. |
| CP7 · Frontend completion + client isolation | Every deliberate interface state including the scope-refusal state, WCAG 2.2 AA across both themes at desktop and tablet, the OpenAPI-generated TypeScript client with a CI contract check, and UX-13 client isolation with a Playwright test asserting the client never contacts a scanned host. |
| CP8 · Hardening and definition-of-done | Retention/cache sweep demonstrated on expired records; full Playwright e2e (scope refusal of a public address, in-scope scan, cached correlation, history reopen, diff, keyboard, theme, all exports including the ledger); README with legal notice, native Windows setup, provider notes, exploitation-refusal policy, and real screenshots; `.env.example` with placeholders only; CI finalized with no live network; and the full PRD 10.4 verification walkthrough written up honestly. |

At each checkpoint, state what is complete, what is deferred, and anything you decided on your own.

Re-check each provider's current documentation immediately before implementing that module. NVD's status labels, enrichment policy, rate limits, and the KEV catalog's format can change, and the PRD's assumptions were captured on September 16, 2026.

## Honesty rules

- No placeholder functions, fake success data, TODO comments, or silent exception handling. A partial module failure must be represented explicitly while the scan completes with warnings.
- State plainly which verification steps you could not execute in your environment. Never describe an unexecuted test, build, scan, or run as passing. "I could not run the Vulhub walkthrough here; run it with these steps and expect this" is the correct answer.
- If you disagree with something in the PRD, say so in the checkpoint summary rather than quietly implementing your preference.

## Delivery format

If you can edit a workspace, create the repository there and return links to the files. If you cannot, provide the file tree and every file's full contents, one file per code block, followed by numbered setup, run, test, and verification instructions.
