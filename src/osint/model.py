"""Findings, sources, and the datum types that drive PII handling."""
from __future__ import annotations

import dataclasses
import datetime as dt
import enum


class DatumType(enum.Enum):
    DOMAIN = "domain"
    IP = "ip"
    EMAIL = "email"          # PII
    PHONE = "phone"          # PII
    USERNAME = "username"
    TECH = "technology"
    ORG = "organization"

    @property
    def is_pii(self) -> bool:
        return self in (DatumType.EMAIL, DatumType.PHONE)


@dataclasses.dataclass(frozen=True, slots=True)
class Finding:
    type: DatumType
    value: str
    source: str                 # which collector produced it (provenance)
    collected: dt.date
    confidence: float = 0.5     # [0,1]

    def key(self) -> str:
        return f"{self.type.value}\x1f{self.value.lower()}"


class Source:
    """A collector. Real sources hit APIs/DNS/etc.; here they are pluggable so the
    engine is testable offline and each source is attributable."""
    name: str

    def collect(self, target: str) -> list[Finding]:  # pragma: no cover - protocol
        raise NotImplementedError
