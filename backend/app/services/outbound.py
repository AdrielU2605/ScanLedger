"""Outbound CVE-provider gateway - the only path to a third-party host (FR-05).

This boundary is entirely separate from ScanGuard: ScanGuard reaches targets,
this gateway reaches CVE providers, and nothing reaches both. The user cannot
supply a provider URL; only the allowlist below is reachable.

No scanned host name, address, or banner is ever sent to a provider. Only the
product and version strings needed for correlation leave the machine, and the
callers in ``app/services/providers`` are structured so nothing else can.

Provider facts below were re-verified against the live services on 2026-09-18,
immediately before implementing this module, as the handoff requires.
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

NVD_HOST = "services.nvd.nist.gov"
KEV_HOST = "www.cisa.gov"

ALLOWED_PROVIDER_HOSTS: frozenset[str] = frozenset({NVD_HOST, KEV_HOST})

DEFAULT_TIMEOUT_SECONDS = 30.0

# Verified 2026-09-18: the documented public limit is 5 requests per rolling
# 30 seconds, rising to 50 with an API key. ScanLedger stays a little under
# both, because being throttled mid-scan is worse than being slightly slower.
PUBLIC_REQUESTS_PER_WINDOW = 5
KEYED_REQUESTS_PER_WINDOW = 50
RATE_WINDOW_SECONDS = 30.0

MAX_ATTEMPTS = 4
BASE_BACKOFF_SECONDS = 1.0
MAX_BACKOFF_SECONDS = 30.0


class DisallowedProviderHost(Exception):
    """A URL outside the provider allowlist was refused before any request."""


class ProviderUnavailable(Exception):
    """The provider could not be reached, or answered in a way we will not cache."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        self.status = status
        super().__init__(message)


class ProviderRateLimited(ProviderUnavailable):
    """The provider asked us to slow down."""


@dataclass
class ProviderResponse:
    status_code: int
    payload: Any


class _SlidingWindowLimiter:
    """Keeps requests inside a provider's documented rolling window."""

    def __init__(self, limit: int, window_seconds: float) -> None:
        self._limit = limit
        self._window = window_seconds
        self._timestamps: list[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._timestamps = [t for t in self._timestamps if now - t < self._window]
                if len(self._timestamps) < self._limit:
                    self._timestamps.append(now)
                    return
                await asyncio.sleep(self._window - (now - self._timestamps[0]) + 0.05)


class OutboundGateway:
    """The sole path to a CVE provider. Redirects off, allowlist enforced."""

    def __init__(
        self,
        *,
        user_agent: str,
        nvd_api_key: str | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.user_agent = user_agent
        self.timeout = timeout
        self.follow_redirects = False
        self._api_key = nvd_api_key
        self._client = client
        self._limiter = _SlidingWindowLimiter(
            KEYED_REQUESTS_PER_WINDOW if nvd_api_key else PUBLIC_REQUESTS_PER_WINDOW,
            RATE_WINDOW_SECONDS,
        )

    @property
    def api_key_configured(self) -> bool:
        return bool(self._api_key)

    def check_url(self, url: str) -> str:
        """Return *url* if it targets an allowlisted provider over HTTPS, else raise."""
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise DisallowedProviderHost(f"{url!r} is not https - provider calls must be HTTPS")
        host = (parts.hostname or "").lower()
        if host not in ALLOWED_PROVIDER_HOSTS:
            raise DisallowedProviderHost(
                f"{host!r} is not an allowlisted CVE provider "
                f"(allowed: {', '.join(sorted(ALLOWED_PROVIDER_HOSTS))})"
            )
        return url

    def headers(self, url: str) -> dict[str, str]:
        """Identifying headers (PRD 8.4). The API key goes only to NVD."""
        headers = {"User-Agent": self.user_agent, "Accept": "application/json"}
        if self._api_key and urlsplit(url).hostname == NVD_HOST:
            headers["apiKey"] = self._api_key
        return headers

    async def get_json(self, url: str, params: dict[str, str] | None = None) -> ProviderResponse:
        """One allowlisted GET, rate limited, with bounded jittered retry."""
        self.check_url(url)
        client = self._client or httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=self.follow_redirects
        )
        owns_client = self._client is None

        try:
            last_error: Exception | None = None
            for attempt in range(1, MAX_ATTEMPTS + 1):
                await self._limiter.acquire()
                try:
                    response = await client.get(url, params=params, headers=self.headers(url))
                except httpx.HTTPError as exc:
                    last_error = ProviderUnavailable(f"could not reach the provider: {exc}")
                else:
                    if response.status_code == 200:
                        try:
                            return ProviderResponse(200, response.json())
                        except ValueError as exc:
                            # Malformed success is not a success, and CP2's cache
                            # deliberately refuses to store it as one.
                            raise ProviderUnavailable(
                                f"the provider returned unreadable JSON: {exc}", status=200
                            ) from exc

                    if response.status_code in (403, 429):
                        last_error = ProviderRateLimited(
                            "the provider is rate limiting ScanLedger",
                            status=response.status_code,
                        )
                        await self._sleep_before_retry(attempt, response)
                        continue

                    if 500 <= response.status_code < 600:
                        last_error = ProviderUnavailable(
                            f"the provider returned {response.status_code}",
                            status=response.status_code,
                        )
                        await self._sleep_before_retry(attempt, response)
                        continue

                    raise ProviderUnavailable(
                        f"the provider returned {response.status_code}",
                        status=response.status_code,
                    )

                if attempt < MAX_ATTEMPTS:
                    await self._sleep_before_retry(attempt, None)

            raise last_error or ProviderUnavailable("the provider could not be reached")
        finally:
            if owns_client:
                await client.aclose()

    async def _sleep_before_retry(self, attempt: int, response: httpx.Response | None) -> None:
        """Honour Retry-After when given; otherwise exponential backoff with jitter."""
        if response is not None:
            retry_after = response.headers.get("Retry-After")
            if retry_after:
                try:
                    await asyncio.sleep(min(float(retry_after), MAX_BACKOFF_SECONDS))
                    return
                except ValueError:
                    pass

        ceiling = min(BASE_BACKOFF_SECONDS * (2 ** (attempt - 1)), MAX_BACKOFF_SECONDS)
        await asyncio.sleep(random.uniform(0, ceiling))
