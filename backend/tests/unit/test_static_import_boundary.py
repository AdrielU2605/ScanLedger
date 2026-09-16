"""The build-breaking proof that no module reaches the network on its own.

CLAUDE.md: "No module may import sockets, asyncio.open_connection,
target-capable HTTP clients, or spawn network subprocesses directly. [...] A
test must fail the build if anything else does."
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from tools.check_network_imports import BOUNDARY_FILES, check_tree


def test_no_network_primitives_outside_the_boundary_modules() -> None:
    violations = check_tree()
    assert not violations, "\n".join(str(violation) for violation in violations)


def test_boundary_file_list_is_exactly_the_two_egress_paths() -> None:
    """Adding a file here must be a deliberate, visible security decision."""
    names = {path.parent.name + "/" + path.name for path in BOUNDARY_FILES}
    assert names == {
        "guard/scanguard.py",
        "guard/resolver.py",
        "services/outbound.py",
    }


def test_the_checker_actually_catches_a_violation(tmp_path: Path) -> None:
    """A checker that never fails is worthless - prove it fails on real misuse."""
    offender = tmp_path / "rogue_module.py"
    offender.write_text(
        textwrap.dedent(
            """
            import socket

            def probe(host, port):
                return socket.create_connection((host, port))
            """
        ),
        encoding="utf-8",
    )

    violations = check_tree(root=tmp_path, boundary_files=frozenset())
    messages = [violation.message for violation in violations]

    assert any("forbidden import of 'socket'" in message for message in messages)
    assert any("create_connection" in message for message in messages)


def test_checker_respects_the_boundary_allowance(tmp_path: Path) -> None:
    approved = tmp_path / "scanguard.py"
    approved.write_text("import socket\n", encoding="utf-8")

    assert check_tree(root=tmp_path, boundary_files=frozenset({approved})) == []


def test_httpx_is_confined_to_the_outbound_gateway(tmp_path: Path) -> None:
    module = tmp_path / "cve_module.py"
    module.write_text("import httpx\n", encoding="utf-8")

    violations = check_tree(root=tmp_path, boundary_files=frozenset())
    assert any("httpx" in violation.message for violation in violations)
