# ScanLedger

A local-first, **lab-locked** active scanning and enumeration workbench — Phase 2
of a penetration test, and the sibling of [ReconLedger](https://github.com/AdrielU2605)
(Phase 1, passive reconnaissance).

> **Authorized lab use only.** ScanLedger sends real network probes. Point it only
> at systems you own or are explicitly authorized to test, inside a private lab you
> control. It refuses to scan any public or routable address. Scanning systems you
> do not own or are not contracted to test is a crime in most countries; in the U.S.
> that is the Computer Fraud and Abuse Act. *"It was reachable" is never the same as
> "it was allowed."*

## Status

Early development. **Checkpoint 1 of 8 is complete**: the security boundary
(ScanGuard + intensity governor), the outbound CVE-provider gateway shell, and the
test harness that enforces both. There is no scanning workflow, database, or user
interface yet — those arrive in CP2–CP8.

See [docs/PRD.md](docs/PRD.md) for the full requirements baseline and
[docs/HANDOFF.md](docs/HANDOFF.md) for the checkpoint plan.

## What the boundary guarantees

ScanLedger has exactly two egress paths, and no other code may open a connection:

| Boundary | Purpose | Enforced in |
| --- | --- | --- |
| **ScanGuard** | The only path to a target socket | `backend/app/guard/` |
| **Outbound gateway** | The only path to a CVE provider | `backend/app/services/outbound.py` |

ScanGuard denies by default. A destination is reachable only when all of the
following hold:

1. It is **not** in an always-denied class — public/globally routable, multicast,
   broadcast, unspecified, documentation ranges, or the cloud-metadata address
   `169.254.169.254`. These are denied even inside a mis-configured scope profile.
2. It is inside the **allowed private ranges** — RFC1918 (`10/8`, `172.16/12`,
   `192.168/16`), IPv6 ULA (`fc00::/7`), and loopback. CGNAT and link-local are
   off by default and require per-profile opt-in.
3. It is inside the **active scope profile** — a private address is not
   automatically authorized.

A hostname is resolved through the OS resolver and **every** resolved address is
re-validated; if any one of them is out of scope the hostname is refused whole,
never partially scanned. CIDR targets are proven in-scope by subnet containment
before the first packet, and are limited to /16 or narrower (IPv4) and /64 or
narrower (IPv6).

Every decision — allowed and denied alike — is written to the append-only audit
ledger, so scope compliance is provable rather than asserted.

The **intensity governor** caps global and per-host concurrency, connections per
second, connect timeout, and per-host/per-scan budgets. `HARD_CEILING` is a code
constant; every intensity profile is validated against it at import time, so a
profile that exceeds a ceiling cannot be constructed at all. The tool is designed
to be incapable of denial of service against its own lab.

## What ScanLedger will never do

Exploitation of any kind, credential attacks (brute force, password spraying,
default-credential attempts), denial of service or stress testing, raw-socket or
SYN scanning, scanning any public address, or writing to/authenticating against a
target. Vulnerabilities are **correlated** from detected versions and always
labeled *unconfirmed* — never proven by attacking the target.

That is the Phase 2 boundary. Requests to add any of the above will be refused;
exploitation belongs to a separate, authorized Phase 3 tool with its own review.

## Setup (Windows, native)

Windows 11 is the primary development and runtime target. Unprivileged TCP connect
scanning works without administrator rights or raw sockets. Requires Python 3.11+.

```powershell
cd backend
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

macOS/Linux is the same with `.venv/bin/python` in place of `.venv\Scripts\python.exe`.

Copy `.env.example` to `.env` if you want to change defaults. No credentials are
required: an NVD API key is optional and only raises provider rate limits.

## Running the checks

```powershell
cd backend
.venv\Scripts\python.exe tools\check_network_imports.py
.venv\Scripts\python.exe -m ruff check .
.venv\Scripts\python.exe -m pytest -q
```

The test suite runs with a **process-wide socket block**: any attempt to create an
outbound TCP socket outside `ScanGuard.connect` raises. `tools/check_network_imports.py`
additionally fails the build if any module outside the two boundary files imports a
network primitive (`socket`, `httpx`, `urllib`, …) or calls an event-loop connection
helper (`open_connection`, `create_connection`, `sock_connect`, …).

CI runs both checks on Windows and Ubuntu, and performs no live network access.

## License

MIT — see [LICENSE](LICENSE).
