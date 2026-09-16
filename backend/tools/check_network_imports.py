"""Static proof that ScanGuard and the outbound gateway are the only network paths.

Walks every module under ``backend/app`` and fails if any file outside the two
approved boundary modules imports a raw network primitive or calls one of the
event-loop connection helpers (PRD 7.6, 8.1; CLAUDE.md: "a test must fail the
build if anything else does").

Run standalone:  python tools/check_network_imports.py
Run under test:  tests/unit/test_static_import_boundary.py
"""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent
APP_ROOT = BACKEND_ROOT / "app"

# The only two files permitted to touch raw networking, plus the resolver that
# ScanGuard owns. Adding a file here is a security decision, not a convenience.
BOUNDARY_FILES: frozenset[Path] = frozenset(
    {
        APP_ROOT / "guard" / "scanguard.py",
        APP_ROOT / "guard" / "resolver.py",
        APP_ROOT / "services" / "outbound.py",
    }
)

FORBIDDEN_IMPORT_ROOTS: frozenset[str] = frozenset(
    {
        "socket",
        "socketserver",
        "ssl",
        "httpx",
        "requests",
        "aiohttp",
        "urllib",
        "telnetlib",
        "ftplib",
    }
)

FORBIDDEN_CALL_ATTRIBUTES: frozenset[str] = frozenset(
    {
        "open_connection",
        "create_connection",
        "sock_connect",
        "create_datagram_endpoint",
        "start_server",
        "create_subprocess_exec",
        "create_subprocess_shell",
    }
)


@dataclass(frozen=True)
class Violation:
    path: Path
    line: int
    message: str

    def __str__(self) -> str:
        return f"{self.path.relative_to(BACKEND_ROOT)}:{self.line}: {self.message}"


def _check_file(path: Path) -> list[Violation]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    violations: list[Violation] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in FORBIDDEN_IMPORT_ROOTS:
                    violations.append(
                        Violation(path, node.lineno, f"forbidden import of {alias.name!r}")
                    )
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in FORBIDDEN_IMPORT_ROOTS:
                violations.append(
                    Violation(path, node.lineno, f"forbidden import from {node.module!r}")
                )
        elif isinstance(node, ast.Attribute):
            if node.attr in FORBIDDEN_CALL_ATTRIBUTES:
                violations.append(Violation(path, node.lineno, f"forbidden use of '.{node.attr}'"))

    return violations


def check_tree(
    root: Path = APP_ROOT, boundary_files: frozenset[Path] = BOUNDARY_FILES
) -> list[Violation]:
    approved = {path.resolve() for path in boundary_files}
    violations: list[Violation] = []
    for path in sorted(root.rglob("*.py")):
        if path.resolve() in approved:
            continue
        violations.extend(_check_file(path))
    return violations


def main() -> int:
    violations = check_tree()
    if violations:
        print("Network boundary violations found:", file=sys.stderr)
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        return 1
    approved = sorted(path.name for path in BOUNDARY_FILES)
    print(f"OK - no network primitives outside the boundary modules: {', '.join(approved)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
