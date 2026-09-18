"""Product name to CPE mapping (PRD FR-09).

A curated table rather than a general fuzzy matcher, because the failure modes
are asymmetric: a wrong CPE produces confident vulnerabilities for software the
host is not running, which is the single most damaging mistake a junior scanner
makes. Entries here were chosen for the services a lab actually runs.

A product that is not in the table is not silently guessed at. Correlation
falls back to a keyword search and says, on the finding itself, that the match
came from a keyword rather than an exact CPE.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

VERSION_PATTERN = re.compile(r"^\d+(?:\.\d+)*")


@dataclass(frozen=True)
class CpeIdentity:
    vendor: str
    product: str


# Detected product string (lower case) -> CPE vendor and product.
CURATED_CPE_MAP: dict[str, CpeIdentity] = {
    "openssh": CpeIdentity("openbsd", "openssh"),
    "dropbear": CpeIdentity("dropbear_ssh_project", "dropbear_ssh"),
    "apache": CpeIdentity("apache", "http_server"),
    "apache httpd": CpeIdentity("apache", "http_server"),
    "httpd": CpeIdentity("apache", "http_server"),
    "nginx": CpeIdentity("f5", "nginx"),
    "lighttpd": CpeIdentity("lighttpd", "lighttpd"),
    "iis": CpeIdentity("microsoft", "internet_information_services"),
    "microsoft-iis": CpeIdentity("microsoft", "internet_information_services"),
    "vsftpd": CpeIdentity("vsftpd_project", "vsftpd"),
    "proftpd": CpeIdentity("proftpd", "proftpd"),
    "filezilla server": CpeIdentity("filezilla-project", "filezilla_server"),
    "pure-ftpd": CpeIdentity("pureftpd", "pure-ftpd"),
    "mysql": CpeIdentity("oracle", "mysql"),
    "mariadb": CpeIdentity("mariadb", "mariadb"),
    "postgresql": CpeIdentity("postgresql", "postgresql"),
    "redis": CpeIdentity("redis", "redis"),
    "mongodb": CpeIdentity("mongodb", "mongodb"),
    "elasticsearch": CpeIdentity("elastic", "elasticsearch"),
    "postfix": CpeIdentity("postfix", "postfix"),
    "exim": CpeIdentity("exim", "exim"),
    "dovecot": CpeIdentity("dovecot", "dovecot"),
    "samba": CpeIdentity("samba", "samba"),
    "openssl": CpeIdentity("openssl", "openssl"),
    "tomcat": CpeIdentity("apache", "tomcat"),
    "apache tomcat": CpeIdentity("apache", "tomcat"),
    "jenkins": CpeIdentity("jenkins", "jenkins"),
    "grafana": CpeIdentity("grafana", "grafana"),
    "jetty": CpeIdentity("eclipse", "jetty"),
    "node.js": CpeIdentity("nodejs", "node.js"),
    "werkzeug": CpeIdentity("palletsprojects", "werkzeug"),
    "gunicorn": CpeIdentity("gunicorn", "gunicorn"),
    "squid": CpeIdentity("squid-cache", "squid"),
    "haproxy": CpeIdentity("haproxy", "haproxy"),
    "openvpn": CpeIdentity("openvpn", "openvpn"),
    "vnc": CpeIdentity("realvnc", "vnc"),
    "memcached": CpeIdentity("memcached", "memcached"),
}


def normalize_version(version: str | None) -> str | None:
    """Reduce a banner version to the numeric core NVD indexes.

    ``8.9p1`` becomes ``8.9`` and ``1.18.0 (Ubuntu)`` becomes ``1.18.0``. The
    trailing detail is meaningful to the vendor but is not what NVD's CPE
    version field carries.
    """
    if not version:
        return None
    match = VERSION_PATTERN.match(version.strip())
    return match.group(0) if match else None


def lookup(product: str | None) -> CpeIdentity | None:
    if not product:
        return None
    return CURATED_CPE_MAP.get(product.strip().lower())


def build_cpe_name(identity: CpeIdentity, version: str | None) -> str:
    """A CPE 2.3 URI. A missing version becomes the wildcard, not a guess."""
    return f"cpe:2.3:a:{identity.vendor}:{identity.product}:{version or '*'}:*:*:*:*:*:*:*"


def cpe_for(product: str | None, version: str | None) -> str | None:
    identity = lookup(product)
    if identity is None:
        return None
    return build_cpe_name(identity, normalize_version(version))
