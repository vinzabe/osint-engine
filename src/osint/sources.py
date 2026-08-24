"""Example collectors. Real ones hit crt.sh / DNS / web; these are deterministic
fixtures so the engine is testable offline and every source stays attributable.
"""
from __future__ import annotations

import datetime as dt

from .model import DatumType, Finding, Source


class StaticSource(Source):
    """A source backed by a fixed finding list — the test/offline double."""

    def __init__(self, name: str, findings: list[Finding]) -> None:
        self.name = name
        self._findings = findings

    def collect(self, target: str) -> list[Finding]:  # noqa: ARG002
        return list(self._findings)


def demo_sources(today: dt.date) -> tuple[Source, ...]:
    ct = StaticSource("cert-transparency", [
        Finding(DatumType.DOMAIN, "www.example.com", "cert-transparency", today, 0.9),
        Finding(DatumType.DOMAIN, "api.example.com", "cert-transparency", today, 0.9),
    ])
    dns = StaticSource("dns", [
        Finding(DatumType.DOMAIN, "www.example.com", "dns", today, 0.8),
        Finding(DatumType.IP, "93.184.216.34", "dns", today, 0.85),
    ])
    web = StaticSource("web-scrape", [
        Finding(DatumType.EMAIL, "admin@example.com", "web-scrape", today, 0.6),
        Finding(DatumType.TECH, "nginx", "web-scrape", today, 0.7),
    ])
    return (ct, dns, web)
