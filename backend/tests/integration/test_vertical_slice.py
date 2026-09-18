"""The CP3 vertical slice, end to end (PRD 12.1 rank 1).

Creates a scan through the API, lets the real runner execute the real probe
modules against a loopback listener the test owns, then checks the evidence,
the audit ledger, and both exports. This is the first test that proves the
whole path - scope, attestation, guard, governor, modules, ledger, exports -
holds together.
"""

from __future__ import annotations

import json
import socket
from collections.abc import AsyncIterator, Iterator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.api.deps import AppState
from app.main import create_app
from app.models.domain import ScanStatus
from app.modules.registry import ModuleRegistry, register_builtin_modules
from app.scan.events import EventPublisher
from app.scan.runner import ScanRunner
from tests.conftest import allow_socket_creation

SessionFactory = async_sessionmaker[AsyncSession]


@pytest.fixture
def listening_port() -> Iterator[int]:
    with allow_socket_creation():
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    try:
        yield int(listener.getsockname()[1])
    finally:
        listener.close()


@pytest.fixture
def native_registry() -> ModuleRegistry:
    return register_builtin_modules(ModuleRegistry())


@pytest.fixture
async def slice_client(
    engine: AsyncEngine, session_factory: SessionFactory, native_registry: ModuleRegistry
) -> AsyncIterator[tuple[AsyncClient, ScanRunner]]:
    events = EventPublisher(session_factory)
    runner = ScanRunner(session_factory, native_registry, events)
    state = AppState(
        engine=engine,
        session_factory=session_factory,
        registry=native_registry,
        events=events,
        runner=runner,
    )
    transport = ASGITransport(app=create_app(state=state))
    async with AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http, runner


async def run_a_scan(client: AsyncClient, runner: ScanRunner, port: int) -> str:
    scope = await client.post(
        "/api/scopes", json={"name": "self-test", "entries": ["127.0.0.0/24"]}
    )
    assert scope.status_code == 201, scope.text

    queued = await client.post(
        "/api/scans",
        json={
            "scope_id": scope.json()["id"],
            "target": "127.0.0.1",
            "modules": ["host_discovery", "port_scan"],
            "intensity_profile": "polite",
            "attestation_accepted": True,
            "note": "CP3 vertical slice walkthrough",
            "module_options": {
                "discovery_ports": [port],
                "port_selection": "custom",
                "ports": [port],
            },
        },
    )
    assert queued.status_code == 202, queued.text
    scan_id = queued.json()["id"]

    assert await runner.claim_next_scan() == scan_id
    assert await runner.execute_scan(scan_id) is ScanStatus.COMPLETED
    return scan_id


class TestVerticalSlice:
    async def test_a_scan_runs_and_records_what_it_found(
        self, slice_client: tuple[AsyncClient, ScanRunner], listening_port: int
    ) -> None:
        client, runner = slice_client
        scan_id = await run_a_scan(client, runner, listening_port)

        detail = (await client.get(f"/api/scans/{scan_id}")).json()
        assert detail["status"] == "completed"
        assert {run["module"]: run["status"] for run in detail["module_runs"]} == {
            "host_discovery": "done",
            "port_scan": "done",
        }

        findings = (await client.get(f"/api/scans/{scan_id}/findings")).json()
        kinds = {item["kind"] for item in findings["items"]}
        assert {"host.live", "port.open", "port.summary"} <= kinds

        open_finding = next(i for i in findings["items"] if i["kind"] == "port.open")
        assert open_finding["port"] == listening_port
        assert open_finding["host"] == "127.0.0.1"
        assert open_finding["confidence"] == "high"
        assert open_finding["fingerprint"]

    async def test_the_ledger_proves_only_in_scope_destinations_were_probed(
        self, slice_client: tuple[AsyncClient, ScanRunner], listening_port: int
    ) -> None:
        client, runner = slice_client
        scan_id = await run_a_scan(client, runner, listening_port)

        ledger = (await client.get(f"/api/scans/{scan_id}/ledger")).json()
        assert ledger, "a scan that probed a host must leave ledger entries"
        assert all(entry["destination"].startswith("127.0.0.") for entry in ledger)
        assert all(entry["decision"] == "allowed" for entry in ledger)
        assert any(
            entry["port"] == listening_port and entry["outcome"] == "connected" for entry in ledger
        )

    async def test_a_refused_public_target_is_ledgered_and_never_scanned(
        self, slice_client: tuple[AsyncClient, ScanRunner]
    ) -> None:
        client, _ = slice_client
        scope = await client.post(
            "/api/scopes", json={"name": "self-test", "entries": ["127.0.0.0/24"]}
        )
        refusal = await client.post(
            "/api/scans",
            json={
                "scope_id": scope.json()["id"],
                "target": "8.8.8.8",
                "modules": ["port_scan"],
                "attestation_accepted": True,
            },
        )

        assert refusal.status_code == 422
        assert refusal.json()["details"]["destination"] == "8.8.8.8"
        assert (await client.get("/api/scans")).json()["total"] == 0

    async def test_json_export_carries_the_complete_record(
        self, slice_client: tuple[AsyncClient, ScanRunner], listening_port: int
    ) -> None:
        client, runner = slice_client
        scan_id = await run_a_scan(client, runner, listening_port)

        export = (
            await client.get(f"/api/scans/{scan_id}/export", params={"format": "json"})
        ).json()

        assert export["schema_version"] == 1
        assert export["scan"]["target_normalized"] == "127.0.0.1"
        assert export["scope"]["entries"] == ["127.0.0.0/24"]
        assert export["authorization"]["attestation_text"].startswith("I own the systems")
        assert len(export["modules"]) == 2
        assert export["findings"]
        assert export["ledger"]

    async def test_markdown_export_states_scope_authorization_and_limits(
        self, slice_client: tuple[AsyncClient, ScanRunner], listening_port: int
    ) -> None:
        client, runner = slice_client
        scan_id = await run_a_scan(client, runner, listening_port)

        response = await client.get(
            f"/api/scans/{scan_id}/export", params={"format": "md", "mode": "full"}
        )
        assert response.status_code == 200
        body = response.text

        assert "# ScanLedger report" in body
        assert "## Authorization" in body
        assert "I own the systems" in body
        assert "self-test - 127.0.0.0/24" in body
        assert "No raw sockets, no SYN scanning" in body
        # Unknown must never read as absent.
        assert "never *absent*" in body
        assert "## Audit ledger" in body
        assert str(listening_port) in body

    async def test_exports_regenerate_without_probing(
        self, slice_client: tuple[AsyncClient, ScanRunner], listening_port: int
    ) -> None:
        """Two exports of one scan are identical apart from the generation time."""
        client, runner = slice_client
        scan_id = await run_a_scan(client, runner, listening_port)

        first = (await client.get(f"/api/scans/{scan_id}/export", params={"format": "json"})).json()
        second = (
            await client.get(f"/api/scans/{scan_id}/export", params={"format": "json"})
        ).json()

        first.pop("generated_at")
        second.pop("generated_at")
        assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)

    async def test_progress_events_include_the_footprint(
        self, slice_client: tuple[AsyncClient, ScanRunner], listening_port: int
    ) -> None:
        client, runner = slice_client
        scan_id = await run_a_scan(client, runner, listening_port)

        events = await runner._events.events_since(scan_id, 0)
        footprints = [event for event in events if event.event_type == "footprint"]
        assert footprints, "the user must be able to see the scan's footprint"
        assert footprints[-1].payload["hosts_probed"] >= 1
        assert footprints[-1].payload["ports_touched"] >= 1

    async def test_an_invalid_export_format_is_refused(
        self, slice_client: tuple[AsyncClient, ScanRunner], listening_port: int
    ) -> None:
        client, runner = slice_client
        scan_id = await run_a_scan(client, runner, listening_port)

        response = await client.get(f"/api/scans/{scan_id}/export", params={"format": "pdf"})
        assert response.status_code == 422
