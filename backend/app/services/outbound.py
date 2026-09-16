"""Outbound CVE-provider gateway - the only path to a third-party host (FR-05).

This boundary is entirely separate from ScanGuard: ScanGuard reaches targets,
this gateway reaches CVE providers, and nothing reaches both. The user cannot
supply a provider URL; only the allowlist below is reachable.

CP1 scope: the allowlist boundary, the identifying User-Agent, and redirect
policy. Request execution, retry/backoff, and caching land in CP5, at which
point the endpoints and rate limits below are re-verified against the
providers' live documentation (PRD 13, handoff: re-check before implementing).
"""

from __future__ import annotations

from urllib.parse import urlsplit

# Captured from provider documentation on 2026-09-16 (PRD R3-R6).
# Re-verify immediately before CP5 - NVD and CISA may change host or path.
ALLOWED_PROVIDER_HOSTS: frozenset[str] = frozenset(
    {
        "services.nvd.nist.gov",
        "www.cisa.gov",
    }
)

DEFAULT_TIMEOUT_SECONDS = 30.0


class DisallowedProviderHost(Exception):
    """A URL outside the provider allowlist was refused before any request."""


class OutboundGateway:
    """The sole path to a CVE provider. Redirects off, allowlist enforced."""

    def __init__(self, *, user_agent: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> None:
        self.user_agent = user_agent
        self.timeout = timeout
        self.follow_redirects = False

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

    def headers(self) -> dict[str, str]:
        """Identifying headers sent on every provider request (PRD 8.4)."""
        return {"User-Agent": self.user_agent, "Accept": "application/json"}
