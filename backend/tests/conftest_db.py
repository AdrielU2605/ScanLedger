"""Database and application fixtures for CP2 tests.

Every test gets a real SQLite file migrated by Alembic - not ``create_all`` -
so the migration itself is exercised by the whole suite rather than by one
isolated test.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from alembic import command
from app.db.session import create_engine, create_session_factory
from app.models.domain import ModuleCategory, TargetType
from app.modules.base import ModuleContext, ModuleMetadata, ModuleResult, ScanModule
from app.modules.registry import ModuleRegistry

BACKEND_ROOT = Path(__file__).resolve().parent.parent


class NoOpModule(ScanModule):
    """A module that touches nothing.

    It exists only so the orchestrator can be proven end to end before any
    real probe module exists, and it is registered exclusively in tests.
    """

    metadata = ModuleMetadata(
        name="noop",
        display_name="No-op test module",
        description="Produces no findings; used to exercise orchestration in tests.",
        category=ModuleCategory.DISCOVERY,
        supported_targets=frozenset({TargetType.IP, TargetType.CIDR, TargetType.HOST}),
        timeout_seconds=5.0,
    )

    def __init__(self) -> None:
        self.calls = 0

    async def run(self, context: ModuleContext) -> ModuleResult:
        self.calls += 1
        return ModuleResult()


@pytest.fixture
def database_url(tmp_path: Path) -> str:
    return f"sqlite+aiosqlite:///{(tmp_path / 'scanledger_test.db').as_posix()}"


@pytest.fixture
def migrated_database(database_url: str) -> Iterator[str]:
    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")
    yield database_url


@pytest.fixture
async def engine(migrated_database: str) -> AsyncIterator[AsyncEngine]:
    created = create_engine(migrated_database)
    try:
        yield created
    finally:
        await created.dispose()


@pytest.fixture
def session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return create_session_factory(engine)


@pytest.fixture
def noop_module() -> NoOpModule:
    return NoOpModule()


@pytest.fixture
def registry(noop_module: NoOpModule) -> ModuleRegistry:
    """An isolated registry - the application's default registry stays empty."""
    isolated = ModuleRegistry()
    isolated.register(noop_module)
    return isolated
