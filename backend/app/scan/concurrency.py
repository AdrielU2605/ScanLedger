"""Bounded fan-out for probe modules.

The governor caps how many connections may be *in flight*, but nothing stops a
module from creating a task per probe up front. A /16 with a hundred ports is
millions of tasks, so work is issued in bounded waves instead.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable, Coroutine, Iterable
from typing import TypeVar

T = TypeVar("T")

DEFAULT_WAVE_SIZE = 256


async def in_bounded_waves(
    factories: Iterable[Callable[[], Coroutine[None, None, T]]],
    *,
    wave_size: int = DEFAULT_WAVE_SIZE,
) -> AsyncIterator[T | BaseException]:
    """Run coroutine factories in waves, yielding each result as a wave lands."""
    wave: list[Coroutine[None, None, T]] = []

    async def drain(pending: list[Coroutine[None, None, T]]) -> list[T | BaseException]:
        return await asyncio.gather(*pending, return_exceptions=True)

    for factory in factories:
        wave.append(factory())
        if len(wave) >= wave_size:
            for outcome in await drain(wave):
                yield outcome
            wave = []

    if wave:
        for outcome in await drain(wave):
            yield outcome
