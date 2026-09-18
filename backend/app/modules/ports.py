"""Port selections and target expansion for the probe modules (PRD FR-07).

On "top-1000": Nmap's top-1000 is a frequency ranking that lives in Nmap's
``nmap-services`` data file, which carries the Nmap license. Copying it into an
MIT repository would be a licensing problem, so ScanLedger offers a curated
``top-100`` of genuinely common service ports and ``well-known`` (1-1024)
instead. Both are honest about what they are, which a mislabelled "top-1000"
would not be.
"""

from __future__ import annotations

from collections.abc import Iterator

from app.guard.ranges import IPAddress
from app.guard.scanguard import ValidatedTarget
from app.models.errors import ModuleError

# Common service ports, roughly ordered by how often they matter in a lab.
TOP_100_PORTS: tuple[int, ...] = (
    21,
    22,
    23,
    25,
    53,
    67,
    68,
    69,
    80,
    81,
    88,
    110,
    111,
    113,
    119,
    123,
    135,
    137,
    138,
    139,
    143,
    161,
    162,
    179,
    389,
    427,
    443,
    445,
    465,
    500,
    512,
    513,
    514,
    515,
    543,
    544,
    548,
    554,
    587,
    631,
    636,
    646,
    873,
    990,
    993,
    995,
    1025,
    1026,
    1027,
    1080,
    1099,
    1194,
    1433,
    1434,
    1521,
    1723,
    1883,
    2049,
    2082,
    2083,
    2181,
    2375,
    2376,
    2483,
    3000,
    3128,
    3268,
    3306,
    3389,
    3690,
    4444,
    4505,
    4506,
    4786,
    5000,
    5060,
    5432,
    5555,
    5601,
    5672,
    5900,
    5901,
    5985,
    5986,
    6000,
    6379,
    6667,
    7001,
    8000,
    8008,
    8080,
    8081,
    8088,
    8443,
    8888,
    9000,
    9042,
    9090,
    9200,
    9300,
    11211,
    27017,
)

# A small set used only to decide whether a host is alive.
DEFAULT_DISCOVERY_PORTS: tuple[int, ...] = (80, 443, 22, 445, 3389, 8080, 21, 3306)

WELL_KNOWN_RANGE = range(1, 1025)
FULL_RANGE = range(1, 65536)

PORT_SELECTIONS = ("top-100", "well-known", "full", "custom")

# An IPv4 /16 is the widest target the PRD allows and is enumerable; an IPv6
# /64 is not, so a module refuses it with a reason instead of hanging.
MAX_EXPANDED_ADDRESSES = 65536


def resolve_ports(options: dict[str, object]) -> tuple[int, ...]:
    """Turn the scan's module options into the concrete port list to probe."""
    selection = str(options.get("port_selection", "top-100"))

    if selection == "top-100":
        return TOP_100_PORTS
    if selection == "well-known":
        return tuple(WELL_KNOWN_RANGE)
    if selection == "full":
        return tuple(FULL_RANGE)
    if selection == "custom":
        raw = options.get("ports")
        if not isinstance(raw, list) or not raw:
            raise ModuleError(
                "the 'custom' port selection needs a non-empty 'ports' list in module options"
            )
        ports = []
        for value in raw:
            try:
                port = int(value)
            except (TypeError, ValueError):
                raise ModuleError(f"{value!r} is not a valid port number") from None
            if not 0 < port <= 65535:
                raise ModuleError(f"port {port} is outside 1-65535")
            ports.append(port)
        return tuple(sorted(set(ports)))

    raise ModuleError(
        f"unknown port selection {selection!r}; expected one of {', '.join(PORT_SELECTIONS)}"
    )


def resolve_discovery_ports(options: dict[str, object]) -> tuple[int, ...]:
    raw = options.get("discovery_ports")
    if raw is None:
        return DEFAULT_DISCOVERY_PORTS
    if not isinstance(raw, list) or not raw:
        raise ModuleError("'discovery_ports' must be a non-empty list of port numbers")
    try:
        return tuple(int(value) for value in raw)
    except (TypeError, ValueError):
        raise ModuleError("'discovery_ports' must contain port numbers") from None


def iter_target_addresses(target: ValidatedTarget) -> Iterator[IPAddress]:
    """Every address the validated target covers.

    Only addresses ScanGuard already proved in scope are produced here, and
    ``guard.connect`` re-checks each one anyway.
    """
    if target.network is None:
        yield from target.addresses
        return

    network = target.network
    if network.num_addresses > MAX_EXPANDED_ADDRESSES:
        raise ModuleError(
            f"{network} contains {network.num_addresses} addresses, more than the "
            f"{MAX_EXPANDED_ADDRESSES} this module will enumerate - narrow the target"
        )

    if network.num_addresses <= 2:
        yield network.network_address
        return
    yield from network.hosts()
