"""Shared application state and FastAPI dependencies."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.modules.registry import ModuleRegistry
from app.scan.events import EventPublisher
from app.scan.runner import ScanRunner


@dataclass
class AppState:
    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]
    registry: ModuleRegistry
    events: EventPublisher
    runner: ScanRunner


def get_state(request: Request) -> AppState:
    state: AppState = request.app.state.scanledger
    return state
