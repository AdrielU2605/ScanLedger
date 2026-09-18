"""ScanLedger API application.

The durable worker runs in this process, which is why only one API process may
serve a database: ``ScanRunner.acquire_worker_lock`` refuses to start a second
one rather than letting two workers claim the same scan and double the probes
sent at the lab (PRD 9).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.api import findings as findings_router
from app.api import ledger as ledger_router
from app.api import modules as modules_router
from app.api import scans as scans_router
from app.api import scopes as scopes_router
from app.api.deps import AppState
from app.config import APP_NAME, APP_VERSION, ProviderSettings, Settings
from app.db.session import create_engine, create_session_factory, verify_fts5_available
from app.models.errors import AppError
from app.modules.registry import default_registry, register_builtin_modules
from app.scan.events import EventPublisher
from app.scan.runner import ScanRunner
from app.services.retention import DEFAULT_RETENTION_DAYS


def build_state(settings: Settings) -> AppState:
    register_builtin_modules()
    engine = create_engine(settings.database_url)
    session_factory = create_session_factory(engine)
    events = EventPublisher(session_factory)
    runner = ScanRunner(
        session_factory,
        default_registry,
        events,
        retention_days=DEFAULT_RETENTION_DAYS,
    )
    return AppState(
        engine=engine,
        session_factory=session_factory,
        registry=default_registry,
        events=events,
        runner=runner,
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    state: AppState = app.state.scanledger
    await verify_fts5_available(state.engine)
    await state.runner.start()
    try:
        yield
    finally:
        await state.runner.stop()
        await state.engine.dispose()


def create_app(settings: Settings | None = None, *, state: AppState | None = None) -> FastAPI:
    application = FastAPI(title=APP_NAME, version=APP_VERSION, lifespan=lifespan)
    application.state.scanledger = state or build_state(settings or Settings())

    @application.exception_handler(AppError)
    async def handle_app_error(_request: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(status_code=exc.http_status, content=exc.to_payload())

    @application.get("/api/readiness")
    async def readiness() -> dict[str, str | bool]:
        """Configured/not-configured only - never a key value (PRD 8.4)."""
        providers = ProviderSettings()
        return {
            "app": APP_NAME,
            "version": APP_VERSION,
            "nvd_api_key_configured": providers.nvd_key_configured,
        }

    application.include_router(modules_router.router)
    application.include_router(scopes_router.router)
    application.include_router(scans_router.router)
    application.include_router(findings_router.router)
    application.include_router(ledger_router.router)
    return application


app = create_app()
