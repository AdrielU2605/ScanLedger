"""A refusal that prevents a scan must still be provable (PRD 10.4 step 8).

The most important thing the ledger can show is a destination ScanLedger would
not touch. Because a refused target never becomes a scan, that evidence has to
be reachable without one.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.api.deps import AppState
from app.main import create_app
from app.modules.registry import ModuleRegistry, register_builtin_modules
from app.scan.events import EventPublisher
from app.scan.runner import ScanRunner

SessionFactory = async_sessionmaker[AsyncSession]


@pytest.fixture
async def client(
    engine: AsyncEngine, session_factory: SessionFactory
) -> AsyncIterator[AsyncClient]:
    registry = register_builtin_modules(ModuleRegistry())
    events = EventPublisher(session_factory)
    state = AppState(
        engine=engine,
        session_factory=session_factory,
        registry=registry,
        events=events,
        runner=ScanRunner(session_factory, registry, events),
    )
    transport = ASGITransport(app=create_app(state=state))
    async with AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


async def make_scope(client: AsyncClient) -> str:
    response = await client.post(
        "/api/scopes", json={"name": "self-test", "entries": ["127.0.0.0/24"]}
    )
    assert response.status_code == 201
    return str(response.json()["id"])


async def attempt(client: AsyncClient, scope_id: str, target: str) -> int:
    response = await client.post(
        "/api/scans",
        json={
            "scope_id": scope_id,
            "target": target,
            "modules": ["port_scan"],
            "attestation_accepted": True,
        },
    )
    return response.status_code


class TestRefusalsAreProvable:
    async def test_a_public_target_appears_as_denied_without_any_scan(
        self, client: AsyncClient
    ) -> None:
        scope_id = await make_scope(client)
        assert await attempt(client, scope_id, "8.8.8.8") == 422

        assert (await client.get("/api/scans")).json()["total"] == 0

        refusals = (await client.get("/api/ledger/refusals")).json()
        assert refusals["total"] == 1
        entry = refusals["items"][0]
        assert entry["destination"] == "8.8.8.8"
        assert entry["decision"] == "denied"
        assert "public/globally routable" in entry["reason"]
        assert entry["scan_id"] is None
        assert entry["scope_id"] == scope_id

    @pytest.mark.parametrize(
        ("target", "fragment"),
        [
            ("169.254.169.254", "cloud-metadata"),
            ("224.0.0.1", "multicast"),
            ("10.10.0.5", "outside the active scope profile"),
        ],
    )
    async def test_each_refusal_class_is_recorded_with_its_reason(
        self, client: AsyncClient, target: str, fragment: str
    ) -> None:
        scope_id = await make_scope(client)
        assert await attempt(client, scope_id, target) == 422

        refusals = (await client.get("/api/ledger/refusals")).json()
        assert refusals["items"][0]["destination"] == target
        assert fragment in refusals["items"][0]["reason"]

    async def test_the_ledger_can_be_filtered_by_decision_and_scope(
        self, client: AsyncClient
    ) -> None:
        scope_id = await make_scope(client)
        await attempt(client, scope_id, "8.8.8.8")

        everything = (await client.get("/api/ledger")).json()
        denied = (await client.get("/api/ledger", params={"decision": "denied"})).json()
        by_scope = (await client.get("/api/ledger", params={"scope_id": scope_id})).json()
        other_scope = (await client.get("/api/ledger", params={"scope_id": "no-such-scope"})).json()

        assert everything["total"] >= 1
        assert denied["total"] == 1
        assert by_scope["total"] >= 1
        assert other_scope["total"] == 0

    async def test_an_allowed_target_is_recorded_as_allowed(self, client: AsyncClient) -> None:
        scope_id = await make_scope(client)
        assert await attempt(client, scope_id, "127.0.0.1") == 202

        allowed = (await client.get("/api/ledger", params={"decision": "allowed"})).json()
        assert allowed["total"] >= 1
        assert allowed["items"][0]["destination"] == "127.0.0.1"
        assert (await client.get("/api/ledger/refusals")).json()["total"] == 0
