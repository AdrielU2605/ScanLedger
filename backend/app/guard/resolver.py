"""Controlled hostname resolution for ScanGuard (PRD 4.4, 7.3, 8.1).

Hostname targets are resolved through the operating system's configured stub
resolver only. ScanLedger never performs DNS-over-HTTPS and never selects a
recursive resolver of its own, so the lab's own DNS (or hosts file) is the only
authority for a lab name.

This module performs NO scope filtering. It returns every address the OS
returned, and ScanGuard re-validates all of them - which is what makes DNS
rebinding ineffective: a name is rejected outright if any of its addresses is
out of scope, rather than being partially scanned.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass

from app.guard.ranges import IPAddress


class ResolutionError(Exception):
    """The hostname could not be resolved to any address."""


@dataclass(frozen=True)
class ResolvedName:
    hostname: str
    addresses: tuple[IPAddress, ...]


async def resolve_hostname(hostname: str) -> ResolvedName:
    """Resolve *hostname* via the OS resolver, returning every address it gave."""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ResolutionError(f"could not resolve {hostname!r}: {exc}") from exc

    addresses = tuple(dict.fromkeys(ipaddress.ip_address(info[4][0]) for info in infos))
    if not addresses:
        raise ResolutionError(f"{hostname!r} resolved to no addresses")
    return ResolvedName(hostname=hostname, addresses=addresses)
