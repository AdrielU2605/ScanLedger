"""Banner-to-service inference (PRD FR-08).

Patterns are deliberately conservative. Every one of them extracts a version
only when the banner states it outright; nothing here guesses a version from a
port number or a product name, because a fabricated version would flow
straight into CVE correlation and become a fabricated vulnerability.

Ambiguous or absent evidence yields low confidence, never a guess.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.models.domain import Confidence


@dataclass(frozen=True)
class ServiceGuess:
    service: str
    product: str | None
    version: str | None
    confidence: Confidence


@dataclass(frozen=True)
class BannerPattern:
    service: str
    product: str
    pattern: re.Pattern[str]


# Each pattern's first group, when present, is the version.
BANNER_PATTERNS: tuple[BannerPattern, ...] = (
    BannerPattern("ssh", "OpenSSH", re.compile(r"SSH-[\d.]+-OpenSSH[_-]([\w.]+)", re.I)),
    BannerPattern("ssh", "Dropbear", re.compile(r"SSH-[\d.]+-dropbear[_-]?([\w.]*)", re.I)),
    BannerPattern("ftp", "vsftpd", re.compile(r"vsftpd\s+([\d.]+)", re.I)),
    BannerPattern("ftp", "ProFTPD", re.compile(r"ProFTPD\s+([\d.]+)", re.I)),
    BannerPattern("ftp", "FileZilla Server", re.compile(r"FileZilla Server\s+([\d.]+)", re.I)),
    BannerPattern("smtp", "Postfix", re.compile(r"\bPostfix\b(?:\s+([\d.]+))?", re.I)),
    BannerPattern("smtp", "Exim", re.compile(r"\bExim\s+([\d.]+)", re.I)),
    BannerPattern("imap", "Dovecot", re.compile(r"\bDovecot\b(?:\s+([\d.]+))?", re.I)),
    BannerPattern("mysql", "MySQL", re.compile(r"([\d]+\.[\d]+\.[\d]+)[\w-]*\x00", re.I)),
    BannerPattern("mysql", "MariaDB", re.compile(r"([\d.]+)-MariaDB", re.I)),
    BannerPattern("redis", "Redis", re.compile(r"redis_version:([\d.]+)", re.I)),
    BannerPattern("postgresql", "PostgreSQL", re.compile(r"PostgreSQL\s+([\d.]+)", re.I)),
    BannerPattern("telnet", "Telnet", re.compile(r"^\xff[\xfb-\xfe]", re.S)),
)

# Used only to name a likely service when the banner says nothing. Never used
# to invent a product or version.
WELL_KNOWN_SERVICE_NAMES: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}

HTTP_SERVER_HEADER = re.compile(r"^server:\s*(.+)$", re.I | re.M)
HTTP_PRODUCT_VERSION = re.compile(r"^([A-Za-z][\w.+-]*)(?:/([\w.]+))?")


def identify_from_banner(banner: str, port: int) -> ServiceGuess | None:
    """Infer a service from a raw banner, or None if it says nothing useful."""
    for entry in BANNER_PATTERNS:
        match = entry.pattern.search(banner)
        if match is None:
            continue
        version = match.group(1) if match.groups() and match.group(1) else None
        return ServiceGuess(
            service=entry.service,
            product=entry.product,
            # A named product with a stated version is the only high-confidence
            # case; a product with no version stays medium.
            version=version,
            confidence=Confidence.HIGH if version else Confidence.MEDIUM,
        )
    return None


def identify_from_http_server_header(header_value: str) -> ServiceGuess:
    """Parse a Server: header such as 'nginx/1.18.0 (Ubuntu)'."""
    match = HTTP_PRODUCT_VERSION.match(header_value.strip())
    if match is None:
        return ServiceGuess("http", None, None, Confidence.LOW)

    product = match.group(1)
    version = match.group(2)
    return ServiceGuess(
        service="http",
        product=product,
        version=version,
        confidence=Confidence.HIGH if version else Confidence.MEDIUM,
    )


def service_name_for_port(port: int) -> ServiceGuess | None:
    """A likely service name from the port alone - never a product or version.

    Confidence is always low: this is a convention, not an observation.
    """
    name = WELL_KNOWN_SERVICE_NAMES.get(port)
    if name is None:
        return None
    return ServiceGuess(service=name, product=None, version=None, confidence=Confidence.LOW)
