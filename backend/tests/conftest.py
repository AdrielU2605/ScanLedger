"""Process-wide socket block for the whole suite (PRD 10.1).

Every test runs with outbound TCP socket construction blocked. The block is
applied at socket *construction* rather than at ``connect``, deliberately: on
Windows the default ProactorEventLoop performs its connect through overlapped
WinSock calls that never pass through ``socket.socket.connect``, so patching
connect would leave a hole on this project's primary platform.

``ScanGuard.connect`` sets ``NETWORK_GUARD_ACTIVE`` around the one socket it
creates, so exactly one application code path can build an outbound socket -
and a test proves that any other path raises.
"""

from __future__ import annotations

import inspect
import socket
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from app.guard.scanguard import NETWORK_GUARD_ACTIVE

pytest_plugins = ["tests.conftest_db"]

_real_socket_init = socket.socket.__init__

BLOCK_MESSAGE = (
    "blocked by the ScanLedger test socket block: an outbound TCP socket may only be "
    "created inside ScanGuard.connect() (see backend/tests/conftest.py)"
)

_SELF_PIPE_FRAMES = 6

# Windows has no AF_UNIX socketpair, so CPython falls back to a loopback pair;
# the fallback helper is the frame that actually builds the socket.
_SELF_PIPE_FUNCTIONS = frozenset({"socketpair", "_fallback_socketpair"})


def _is_event_loop_self_pipe() -> bool:
    """True when asyncio is building its own self-pipe via socket.socketpair().

    On Windows there is no AF_UNIX socketpair, so the stdlib emulates one with a
    real loopback AF_INET pair - which the block would otherwise refuse, leaving
    no usable event loop. The exemption is deliberately narrow: it matches the
    stdlib's own ``socketpair`` frame only, so ``asyncio.open_connection`` and
    ``loop.create_connection`` (which build their sockets elsewhere) stay blocked.
    """
    frame = inspect.currentframe()
    for _ in range(_SELF_PIPE_FRAMES):
        if frame is None:
            return False
        code = frame.f_code
        if code.co_name in _SELF_PIPE_FUNCTIONS and code.co_filename.replace("\\", "/").endswith(
            "/socket.py"
        ):
            return True
        frame = frame.f_back
    return False


def _guarded_socket_init(
    self: socket.socket,
    family: int = socket.AF_INET,
    type: int = socket.SOCK_STREAM,  # noqa: A002 - mirrors the stdlib signature
    proto: int = 0,
    fileno: int | None = None,
) -> None:
    is_new_outbound_tcp = (
        fileno is None
        and family in (socket.AF_INET, socket.AF_INET6)
        and type == socket.SOCK_STREAM
    )
    if is_new_outbound_tcp and not NETWORK_GUARD_ACTIVE.get() and not _is_event_loop_self_pipe():
        raise RuntimeError(BLOCK_MESSAGE)
    _real_socket_init(self, family, type, proto, fileno)


@pytest.fixture(autouse=True)
def block_sockets(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(socket.socket, "__init__", _guarded_socket_init)
    yield


@contextmanager
def allow_socket_creation() -> Iterator[None]:
    """Test-infrastructure escape hatch for building a local listening socket.

    Kept as narrow as possible - wrap the construction call itself, never a
    whole test - so the block is active again while the test body runs. Only
    test infrastructure uses this; no application code may set
    NETWORK_GUARD_ACTIVE outside ScanGuard.connect().
    """
    token = NETWORK_GUARD_ACTIVE.set(True)
    try:
        yield
    finally:
        NETWORK_GUARD_ACTIVE.reset(token)
