"""OSINT source adapters.

Each source produces SourceRecord(s). A SourceRecord is a small set of
related entities + the type of relationship that ties them, with a
per-source confidence weight (0..1).

Design constraint: sources are pluggable; the bundled implementations
read from offline JSON fixtures so the engine is hermetic + deterministic
in tests. Real HTTP collectors (whois, crt.sh, GitHub, IntelX, HIBP, ...)
slot in by subclassing Source and implementing `fetch()`.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .entity import Entity, EntityType


@dataclass
class SourceRecord:
    """A single observation from a source.

    `entities` is the set of entities co-observed in one record.
    `relations` are pairs (a_idx, b_idx, relation_label).
    `confidence` weights how trustworthy this source is in general.
    `evidence` is free-form provenance (URL, breach name, ...).
    """
    source: str
    entities: List[Entity]
    relations: List[Tuple[int, int, str]]
    confidence: float
    evidence: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not (0.0 < self.confidence <= 1.0):
            raise ValueError("confidence must be in (0, 1]")
        for a, b, _ in self.relations:
            if not (0 <= a < len(self.entities) and 0 <= b < len(self.entities)):
                raise ValueError(f"bad relation index in {self.source}")
            if a == b:
                raise ValueError(f"self-relation in {self.source}")


class Source(ABC):
    """Pluggable OSINT source."""
    name: str = "base"
    confidence: float = 0.5

    @abstractmethod
    def fetch(self, query: str) -> Iterator[SourceRecord]:
        """Yield SourceRecord(s) for the given query (a domain / email / etc.)."""
        ...


# ---------------------------------------------------------------------------
# Fixture-backed sources

class _FixtureSource(Source):
    """Common fixture loader. Subclasses define `_parse_record()`."""
    fixture_filename: str = ""

    def __init__(self, fixture_dir: str | Path):
        self.fixture_dir = Path(fixture_dir)
        self._data: Optional[Dict[str, List[Dict[str, Any]]]] = None

    def _load(self) -> Dict[str, List[Dict[str, Any]]]:
        if self._data is None:
            path = self.fixture_dir / self.fixture_filename
            if not path.exists():
                self._data = {}
            else:
                self._data = json.loads(path.read_text())
        return self._data

    def fetch(self, query: str) -> Iterator[SourceRecord]:
        data = self._load()
        for raw in data.get(query, []):
            try:
                yield self._parse_record(raw, query)
            except Exception as e:
                # Bad fixture row: skip but never crash the pipeline
                continue

    @abstractmethod
    def _parse_record(self, raw: Dict[str, Any], query: str) -> SourceRecord:
        ...


class WhoisSource(_FixtureSource):
    name = "whois"
    confidence = 0.85
    fixture_filename = "whois.json"

    def _parse_record(self, raw, query) -> SourceRecord:
        ents: List[Entity] = []
        rels: List[Tuple[int, int, str]] = []
        domain = Entity.make(EntityType.DOMAIN, raw["domain"])
        ents.append(domain)
        if raw.get("registrant_email"):
            ents.append(Entity.make(EntityType.EMAIL, raw["registrant_email"]))
            rels.append((0, len(ents) - 1, "registered_by"))
        if raw.get("registrant_name"):
            ents.append(Entity.make(EntityType.PERSON, raw["registrant_name"]))
            rels.append((0, len(ents) - 1, "registrant_name"))
        if raw.get("registrant_org"):
            ents.append(Entity.make(EntityType.ORG, raw["registrant_org"]))
            rels.append((0, len(ents) - 1, "registrant_org"))
        for ns in raw.get("nameservers", []) or []:
            try:
                ents.append(Entity.make(EntityType.DOMAIN, ns))
                rels.append((0, len(ents) - 1, "uses_ns"))
            except ValueError:
                pass
        return SourceRecord(self.name, ents, rels, self.confidence,
                                evidence={"raw": raw})


class DNSSource(_FixtureSource):
    name = "dns"
    confidence = 0.9
    fixture_filename = "dns.json"

    def _parse_record(self, raw, query) -> SourceRecord:
        ents = [Entity.make(EntityType.DOMAIN, raw["domain"])]
        rels = []
        for ip in raw.get("a", []) or []:
            ents.append(Entity.make(EntityType.IP, ip))
            rels.append((0, len(ents) - 1, "resolves_to"))
        for mx in raw.get("mx", []) or []:
            try:
                ents.append(Entity.make(EntityType.DOMAIN, mx))
                rels.append((0, len(ents) - 1, "mx"))
            except ValueError:
                pass
        return SourceRecord(self.name, ents, rels, self.confidence,
                                evidence={"raw": raw})


class CertificateTransparencySource(_FixtureSource):
    name = "ct"
    confidence = 0.9
    fixture_filename = "ct.json"

    def _parse_record(self, raw, query) -> SourceRecord:
        ents = [Entity.make(EntityType.DOMAIN, raw["domain"])]
        rels = []
        for san in raw.get("san_domains", []) or []:
            try:
                e = Entity.make(EntityType.SUBDOMAIN, san)
            except ValueError:
                continue
            ents.append(e)
            rels.append((0, len(ents) - 1, "ct_san"))
        return SourceRecord(self.name, ents, rels, self.confidence,
                                evidence={"raw": raw})


class GitHubSource(_FixtureSource):
    name = "github"
    confidence = 0.7
    fixture_filename = "github.json"

    def _parse_record(self, raw, query) -> SourceRecord:
        ents: List[Entity] = []
        rels = []
        # The query maps to a username; we record the user, their repos,
        # any embedded emails, and any leaked secrets-as-hashes.
        ents.append(Entity.make(EntityType.USERNAME, raw["username"]))
        for repo in raw.get("repos", []) or []:
            ents.append(Entity.make(EntityType.REPO, repo))
            rels.append((0, len(ents) - 1, "owns_repo"))
        for email in raw.get("commit_emails", []) or []:
            try:
                ents.append(Entity.make(EntityType.EMAIL, email))
                rels.append((0, len(ents) - 1, "commits_as"))
            except ValueError:
                pass
        for h in raw.get("leaked_hashes", []) or []:
            try:
                ents.append(Entity.make(EntityType.HASH, h))
                rels.append((0, len(ents) - 1, "leaked_artifact"))
            except ValueError:
                pass
        return SourceRecord(self.name, ents, rels, self.confidence,
                                evidence={"raw": raw})


class PasteSource(_FixtureSource):
    """Pastebin-like dump of co-mentioned identifiers."""
    name = "paste"
    confidence = 0.55
    fixture_filename = "paste.json"

    def _parse_record(self, raw, query) -> SourceRecord:
        ents: List[Entity] = []
        rels = []
        # entities is a list of {"type": "...", "value": "..."}
        for r in raw.get("entities", []) or []:
            try:
                etype = EntityType(r["type"])
                ents.append(Entity.make(etype, r["value"]))
            except (ValueError, KeyError):
                continue
        for i in range(1, len(ents)):
            rels.append((0, i, "paste_co_mention"))
        return SourceRecord(self.name, ents, rels, self.confidence,
                                evidence={"paste_id": raw.get("paste_id"),
                                            "raw": raw})


class BreachSource(_FixtureSource):
    name = "breach"
    confidence = 0.95
    fixture_filename = "breach.json"

    def _parse_record(self, raw, query) -> SourceRecord:
        ents: List[Entity] = []
        rels = []
        ents.append(Entity.make(EntityType.EMAIL, raw["email"]))
        for breach in raw.get("breaches", []) or []:
            ents.append(Entity.make(EntityType.BREACH, breach))
            rels.append((0, len(ents) - 1, "exposed_in"))
        for h in raw.get("password_hashes", []) or []:
            try:
                ents.append(Entity.make(EntityType.HASH, h))
                rels.append((0, len(ents) - 1, "password_hash"))
            except ValueError:
                pass
        return SourceRecord(self.name, ents, rels, self.confidence,
                                evidence={"raw": raw})


class SocialSource(_FixtureSource):
    """Social handle lookups across platforms."""
    name = "social"
    confidence = 0.65
    fixture_filename = "social.json"

    def _parse_record(self, raw, query) -> SourceRecord:
        ents: List[Entity] = []
        rels = []
        ents.append(Entity.make(EntityType.USERNAME, raw["username"]))
        if raw.get("display_name"):
            ents.append(Entity.make(EntityType.PERSON, raw["display_name"]))
            rels.append((0, len(ents) - 1, "display_name"))
        for email in raw.get("contact_emails", []) or []:
            try:
                ents.append(Entity.make(EntityType.EMAIL, email))
                rels.append((0, len(ents) - 1, "contact_email"))
            except ValueError:
                pass
        for url in raw.get("urls", []) or []:
            try:
                ents.append(Entity.make(EntityType.URL, url))
                rels.append((0, len(ents) - 1, "social_url"))
            except ValueError:
                pass
        return SourceRecord(self.name, ents, rels, self.confidence,
                                evidence={"platform": raw.get("platform"),
                                            "raw": raw})


# Built-in registry
ALL_SOURCE_CLASSES = (
    WhoisSource, DNSSource, CertificateTransparencySource, GitHubSource,
    PasteSource, BreachSource, SocialSource,
)


def load_all_fixtures(fixture_dir: str | Path) -> List[Source]:
    return [cls(fixture_dir) for cls in ALL_SOURCE_CLASSES]
