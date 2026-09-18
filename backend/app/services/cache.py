"""Provider response cache (PRD FR-06).

Keyed by product, version, source, and schema version, so a schema change
invalidates old entries rather than silently reusing a shape the code no
longer understands.

What is deliberately *not* cached as a success: an authentication failure or a
malformed response. Caching those would turn a transient provider problem into
a day-long "no vulnerabilities found", which is exactly the false reassurance
the PRD warns about. A genuine "no match" may be cached briefly, because that
is a real answer.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.tables import CacheEntryRow

SCHEMA_VERSION = 1
DEFAULT_TTL_SECONDS = 24 * 60 * 60
NEGATIVE_TTL_SECONDS = 60 * 60

STATUS_HIT = "ok"
STATUS_EMPTY = "empty"

NON_CACHEABLE_STATUSES = frozenset({"auth_failed", "malformed", "rate_limited", "error"})


@dataclass(frozen=True)
class CachedResponse:
    status: str
    normalized: dict[str, Any] | None
    retrieved_at: datetime
    expires_at: datetime

    @property
    def is_empty_result(self) -> bool:
        return self.status == STATUS_EMPTY


def build_cache_key(*, source: str, product: str, version: str | None) -> str:
    return f"{source}:{SCHEMA_VERSION}:{product.lower()}:{(version or '*').lower()}"


class ResponseCache:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def get(self, cache_key: str, *, now: datetime | None = None) -> CachedResponse | None:
        """Return a fresh entry, or None when absent or expired."""
        moment = now or datetime.now(UTC)
        async with self._session_factory() as session:
            row = await session.get(CacheEntryRow, cache_key)
            if row is None:
                return None

            expires = row.expires_at
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=UTC)
            if expires <= moment:
                return None

            retrieved = row.retrieved_at
            if retrieved.tzinfo is None:
                retrieved = retrieved.replace(tzinfo=UTC)

            return CachedResponse(
                status=row.status,
                normalized=row.normalized_json,
                retrieved_at=retrieved,
                expires_at=expires,
            )

    async def store(
        self,
        cache_key: str,
        *,
        source: str,
        status: str,
        normalized: dict[str, Any] | None = None,
        response: dict[str, Any] | None = None,
        ttl_seconds: int | None = None,
        now: datetime | None = None,
    ) -> bool:
        """Store a result. Returns False when the status is not cacheable."""
        if status in NON_CACHEABLE_STATUSES:
            return False

        moment = now or datetime.now(UTC)
        ttl = ttl_seconds
        if ttl is None:
            ttl = NEGATIVE_TTL_SECONDS if status == STATUS_EMPTY else DEFAULT_TTL_SECONDS
        expires = moment + timedelta(seconds=ttl)

        async with self._session_factory() as session:
            row = await session.get(CacheEntryRow, cache_key)
            if row is None:
                row = CacheEntryRow(cache_key=cache_key, source=source, schema_version=0)
                session.add(row)

            row.source = source
            row.schema_version = SCHEMA_VERSION
            row.status = status
            row.response_json = response
            row.normalized_json = normalized
            row.retrieved_at = moment
            row.expires_at = expires
            await session.commit()
        return True

    async def summary(self) -> dict[str, Any]:
        """What a Clear cache action would delete, before it is confirmed."""
        async with self._session_factory() as session:
            rows = list((await session.execute(select(CacheEntryRow))).scalars())

        now = datetime.now(UTC)
        fresh = 0
        for row in rows:
            expires = row.expires_at
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=UTC)
            if expires > now:
                fresh += 1

        by_source: dict[str, int] = {}
        for row in rows:
            by_source[row.source] = by_source.get(row.source, 0) + 1

        return {
            "entries": len(rows),
            "fresh": fresh,
            "expired": len(rows) - fresh,
            "by_source": by_source,
        }

    async def clear(self) -> int:
        async with self._session_factory() as session:
            rows = list((await session.execute(select(CacheEntryRow))).scalars())
            for row in rows:
                await session.delete(row)
            await session.commit()
            return len(rows)
