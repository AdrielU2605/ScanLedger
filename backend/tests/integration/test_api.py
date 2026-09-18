"""API tests for scope CRUD, scan creation, and the SSE contract (PRD 7.4)."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.api.deps import AppState
from app.main import create_app
from app.modules.registry import ModuleRegistry
from app.scan.events import EventPublisher
from app.scan.runner import ScanRunner

SessionFactory = async_sessionmaker[AsyncSession]


@pytest.fixture
async def client(
    engine: AsyncEngine, session_factory: SessionFactory, registry: ModuleRegistry
) -> AsyncIterator[AsyncClient]:
    events = EventPublisher(session_factory)
    state = AppState(
        engine=engine,
        session_factory=session_factory,
        registry=registry,
        events=events,
        runner=ScanRunner(session_factory, registry, events),
    )
    app = create_app(state=state)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


async def create_scope(client: AsyncClient, **overrides: object) -> dict:
    payload = {"name": "self-test", "entries": ["127.0.0.0/24"], **overrides}
    response = await client.post("/api/scopes", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


class TestScopes:
    async def test_create_and_list(self, client: AsyncClient) -> None:
        created = await create_scope(client)
        assert created["entries"] == ["127.0.0.0/24"]

        listed = await client.get("/api/scopes")
        assert listed.status_code == 200
        assert [item["id"] for item in listed.json()] == [created["id"]]

    @pytest.mark.parametrize("entry", ["8.8.8.8", "203.0.113.0/24", "0.0.0.0/0", "100.64.0.0/16"])
    async def test_a_profile_outside_the_private_ranges_cannot_be_saved(
        self, client: AsyncClient, entry: str
    ) -> None:
        response = await client.post("/api/scopes", json={"name": "bad", "entries": [entry]})
        assert response.status_code == 422
        body = response.json()
        assert body["code"] == "scope_invalid"
        # The error must name the offending entry (UX-02).
        assert entry in body["message"]

    async def test_duplicate_names_are_refused(self, client: AsyncClient) -> None:
        await create_scope(client)
        response = await client.post(
            "/api/scopes", json={"name": "self-test", "entries": ["127.0.0.1"]}
        )
        assert response.status_code == 422

    async def test_update_and_delete(self, client: AsyncClient) -> None:
        created = await create_scope(client)
        updated = await client.put(
            f"/api/scopes/{created['id']}",
            json={"name": "renamed", "entries": ["10.10.0.0/24"]},
        )
        assert updated.status_code == 200
        assert updated.json()["name"] == "renamed"

        deleted = await client.delete(f"/api/scopes/{created['id']}")
        assert deleted.status_code == 204
        assert (await client.get("/api/scopes")).json() == []

    async def test_deleting_a_scope_with_scans_is_refused(self, client: AsyncClient) -> None:
        """A stored scan must never lose the scope it was authorized against."""
        scope = await create_scope(client)
        await client.post(
            "/api/scans",
            json={
                "scope_id": scope["id"],
                "target": "127.0.0.1",
                "modules": ["noop"],
                "attestation_accepted": True,
            },
        )

        response = await client.delete(f"/api/scopes/{scope['id']}")
        assert response.status_code == 409
        assert response.json()["code"] == "scope_in_use"

    async def test_unknown_scope_is_404(self, client: AsyncClient) -> None:
        response = await client.put(
            "/api/scopes/does-not-exist", json={"name": "x", "entries": ["127.0.0.1"]}
        )
        assert response.status_code == 404


class TestModules:
    async def test_catalog_lists_registered_modules(self, client: AsyncClient) -> None:
        response = await client.get("/api/modules")
        assert response.status_code == 200
        assert [entry["name"] for entry in response.json()] == ["noop"]
        assert response.json()[0]["readiness"] == "ready"


class TestScans:
    async def test_queue_scan_returns_202_with_module_states(self, client: AsyncClient) -> None:
        scope = await create_scope(client)
        response = await client.post(
            "/api/scans",
            json={
                "scope_id": scope["id"],
                "target": "127.0.0.1",
                "modules": ["noop"],
                "attestation_accepted": True,
                "note": "lab walkthrough",
            },
        )

        assert response.status_code == 202, response.text
        body = response.json()
        assert body["status"] == "queued"
        assert body["target_normalized"] == "127.0.0.1"
        assert body["resolved_addresses"] == ["127.0.0.1"]
        assert [run["module"] for run in body["module_runs"]] == ["noop"]
        assert body["module_runs"][0]["status"] == "queued"
        assert body["attestation_text"].startswith("I own the systems")

    async def test_launch_without_attestation_is_refused(self, client: AsyncClient) -> None:
        scope = await create_scope(client)
        response = await client.post(
            "/api/scans",
            json={
                "scope_id": scope["id"],
                "target": "127.0.0.1",
                "modules": ["noop"],
                "attestation_accepted": False,
            },
        )
        assert response.status_code == 422
        assert response.json()["code"] == "attestation_required"

    @pytest.mark.parametrize(
        ("target", "reason_fragment"),
        [
            ("8.8.8.8", "public/globally routable"),
            ("169.254.169.254", "cloud-metadata"),
            ("10.10.0.5", "outside the active scope profile"),
        ],
    )
    async def test_out_of_scope_targets_are_refused_and_named(
        self, client: AsyncClient, target: str, reason_fragment: str
    ) -> None:
        scope = await create_scope(client)
        response = await client.post(
            "/api/scans",
            json={
                "scope_id": scope["id"],
                "target": target,
                "modules": ["noop"],
                "attestation_accepted": True,
            },
        )

        assert response.status_code == 422
        body = response.json()
        assert body["code"] == "target_out_of_scope"
        assert body["details"]["destination"] == target
        assert reason_fragment in body["details"]["reason"]

    async def test_a_refused_target_queues_no_scan(self, client: AsyncClient) -> None:
        scope = await create_scope(client)
        await client.post(
            "/api/scans",
            json={
                "scope_id": scope["id"],
                "target": "8.8.8.8",
                "modules": ["noop"],
                "attestation_accepted": True,
            },
        )
        assert (await client.get("/api/scans")).json()["total"] == 0

    async def test_unknown_module_is_refused(self, client: AsyncClient) -> None:
        scope = await create_scope(client)
        response = await client.post(
            "/api/scans",
            json={
                "scope_id": scope["id"],
                "target": "127.0.0.1",
                "modules": ["not-a-module"],
                "attestation_accepted": True,
            },
        )
        assert response.status_code == 422
        assert response.json()["code"] == "module_unknown"

    async def test_history_list_and_detail(self, client: AsyncClient) -> None:
        scope = await create_scope(client)
        queued = await client.post(
            "/api/scans",
            json={
                "scope_id": scope["id"],
                "target": "127.0.0.1",
                "modules": ["noop"],
                "attestation_accepted": True,
            },
        )
        scan_id = queued.json()["id"]

        listing = await client.get("/api/scans", params={"limit": 10})
        assert listing.json()["total"] == 1

        detail = await client.get(f"/api/scans/{scan_id}")
        assert detail.status_code == 200
        assert detail.json()["id"] == scan_id

    async def test_cancel_sets_the_flag_the_runner_honors(self, client: AsyncClient) -> None:
        scope = await create_scope(client)
        scan_id = (
            await client.post(
                "/api/scans",
                json={
                    "scope_id": scope["id"],
                    "target": "127.0.0.1",
                    "modules": ["noop"],
                    "attestation_accepted": True,
                },
            )
        ).json()["id"]

        response = await client.post(f"/api/scans/{scan_id}/cancel")
        assert response.status_code == 200
        assert response.json()["cancel_requested"] is True

    async def test_delete_removes_the_scan(self, client: AsyncClient) -> None:
        scope = await create_scope(client)
        scan_id = (
            await client.post(
                "/api/scans",
                json={
                    "scope_id": scope["id"],
                    "target": "127.0.0.1",
                    "modules": ["noop"],
                    "attestation_accepted": True,
                },
            )
        ).json()["id"]

        assert (await client.delete(f"/api/scans/{scan_id}")).status_code == 204
        assert (await client.get(f"/api/scans/{scan_id}")).status_code == 404

    async def test_unknown_scan_is_404(self, client: AsyncClient) -> None:
        assert (await client.get("/api/scans/nope")).status_code == 404


class TestReadiness:
    async def test_readiness_never_returns_a_key_value(self, client: AsyncClient) -> None:
        body = (await client.get("/api/readiness")).json()
        assert body["nvd_api_key_configured"] in (True, False)
        assert "nvd_api_key" not in body
