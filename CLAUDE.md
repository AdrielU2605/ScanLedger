# CLAUDE.md — ScanLedger

Standing rules for every session in this repository. Read `docs/PRD.md` (the
source of truth) and `docs/HANDOFF.md` before doing any work. If this file and
the PRD ever disagree, the PRD wins.

## What this is

ScanLedger is a local-first, **lab-locked active scanning and enumeration
workbench** — Phase 2 of a penetration test. It is the sibling of ReconLedger
(Phase 1). Stack: React + TypeScript client, async FastAPI backend, an asyncio
scan engine, httpx for CVE providers only, SQLite via SQLAlchemy async with
Alembic **batch** migrations and FTS5. A single in-process durable worker.
MIT license. Windows 11 is the primary dev and runtime target, and unprivileged
TCP connect scanning must work there without admin rights or raw sockets.

## Non-negotiable safety rules — never violate, never weaken

- **ScanGuard is the ONLY code path to a target socket.** It denies by default
  and allows a destination only if it is inside the allowed private ranges
  (RFC1918 `10/8`, `172.16/12`, `192.168/16`; IPv6 ULA `fc00::/7`; loopback for
  self-test) **and** inside the active, attested scope profile.
- **Always deny**, even inside a misconfigured profile: public/routable
  addresses, multicast, broadcast, the unspecified address, and the
  cloud-metadata address `169.254.169.254`.
- Resolve hostnames through the controlled **local** resolver only — never
  public DoH or arbitrary recursive resolvers. Reject a hostname if ANY resolved
  address is out of scope. Expand and validate every CIDR member before the
  first packet.
- The **intensity governor's** concurrency and packet-rate ceilings are HARD; no
  profile or config may exceed them. The tool must be incapable of denial of
  service against its own lab.
- **No module** may import sockets, `asyncio.open_connection`, target-capable
  HTTP clients, or spawn network subprocesses directly. Only `ScanGuard.connect`
  (targets) and the outbound gateway (CVE providers) may open a connection. A
  test must fail the build if anything else does.
- **No live external scanners in the MVP** (no live nmap). Nmap XML *import*
  only. No exploitation, credential attacks, brute force, password spraying,
  denial of service, raw/SYN scanning, or writing/authenticating to a target.
  Vulnerabilities are **correlated** (version → CVE), always labeled
  *unconfirmed* — never proven by attacking the target.
- If asked to add any of the above later: **refuse**, explain it breaks the
  Phase 2 boundary, and suggest a separate authorized Phase 3 tool.
- The **append-only audit ledger** records every probed and every denied
  destination.
- The **browser must never contact a scanned host**: inert host references only;
  no favicon, preview, iframe, prefetch, or preconnect to a target.

## How to work

- Build in the checkpoints in `docs/HANDOFF.md`, **ScanGuard and governor
  first**. Stop at each checkpoint boundary and summarize what is done, what is
  deferred, and anything you decided on your own. Do not race ahead.
- **Never claim a test, build, or run passed unless you actually ran it and saw
  it pass.** State plainly what you could not execute here.
- No placeholder functions, fake success data, TODO comments, or silent
  exception handling. A partial module failure is represented explicitly while
  the scan completes with warnings.
- CI runs **no live network**; tests use a process-wide socket block.
- Never commit secrets, personal data, or scan evidence from any real network
  (the repo goes public later). Re-check a provider's current docs immediately
  before implementing its module.
