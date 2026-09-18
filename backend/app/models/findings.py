"""The Finding record every module returns (PRD 6.1, FR-11).

The fingerprint is what makes a diff honest: it is derived from the stable
identity of an observation (module, kind, host, port, and a canonical identity
key) and deliberately NOT from mutable attributes, so a service whose version
changed is reported as *changed* rather than as one removal plus one addition.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.models.domain import Confidence, FindingCategory


def compute_fingerprint(
    *, module: str, kind: str, host: str, port: int | None, identity_key: str
) -> str:
    parts = "|".join([module, kind, host, "" if port is None else str(port), identity_key])
    return hashlib.sha256(parts.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Finding:
    host: str
    category: FindingCategory
    kind: str
    title: str
    summary: str
    module: str
    identity_key: str
    port: int | None = None
    normalized_value: dict[str, Any] = field(default_factory=dict)
    raw_evidence: str | None = None
    confidence: Confidence | None = None
    sources: tuple[str, ...] = ()
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def fingerprint(self) -> str:
        return compute_fingerprint(
            module=self.module,
            kind=self.kind,
            host=self.host,
            port=self.port,
            identity_key=self.identity_key,
        )

    def normalized_value_json(self) -> str:
        return json.dumps(self.normalized_value, sort_keys=True, separators=(",", ":"))
