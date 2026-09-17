"""Async engine and session factory.

SQLite specifics that matter here (PRD 11, risk "SQLite write contention"):
WAL mode so a reader never blocks the writer, foreign keys ON (SQLite leaves
them off per-connection by default, which would silently break the cascade
deletes the retention sweep depends on), and a busy timeout so a brief write
overlap waits instead of raising.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

BUSY_TIMEOUT_MS = 5000


def _apply_sqlite_pragmas(dbapi_connection: Any, _record: Any) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
    finally:
        cursor.close()


def create_engine(database_url: str) -> AsyncEngine:
    engine = create_async_engine(database_url, future=True, pool_pre_ping=True)
    event.listen(engine.sync_engine, "connect", _apply_sqlite_pragmas)
    return engine


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, autoflush=False)


async def session_scope(
    factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    """One short transaction per unit of work - commit on success, roll back on error."""
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except BaseException:
            await session.rollback()
            raise


async def verify_fts5_available(engine: AsyncEngine) -> None:
    """Fail loudly at startup if this SQLite build cannot do full-text search.

    Search is a core requirement (UX-10), and a build without FTS5 would only
    surface as a confusing runtime error much later.
    """
    async with engine.connect() as connection:
        result = await connection.execute(
            text(
                "select count(*) from pragma_compile_options "
                "where compile_options like 'ENABLE_FTS5%'"
            )
        )
        if not result.scalar():
            raise RuntimeError(
                "this SQLite build has no FTS5 support, which ScanLedger's search requires - "
                "install a CPython build whose bundled SQLite enables FTS5"
            )
