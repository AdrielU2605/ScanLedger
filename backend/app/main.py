"""ScanLedger API bootstrap.

CP1 exposes readiness only. The scan, scope, and module routes from PRD 7.4
arrive in CP2 once persistence and the orchestrator exist.
"""

from __future__ import annotations

from fastapi import FastAPI

from app.config import APP_NAME, APP_VERSION, ProviderSettings

app = FastAPI(title=APP_NAME, version=APP_VERSION)


@app.get("/api/readiness")
async def readiness() -> dict[str, str | bool]:
    """Report configured/not-configured only - never a key value (PRD 8.4)."""
    providers = ProviderSettings()
    return {
        "app": APP_NAME,
        "version": APP_VERSION,
        "nvd_api_key_configured": providers.nvd_key_configured,
    }
