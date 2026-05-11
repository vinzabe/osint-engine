"""Typed entity model + normalisation.

Entities are the nodes in the correlation graph. Each entity has:
    - type   (EntityType enum)
    - value  (canonical, normalised)
    - meta   (free-form dict from the source)

Normalisation is the key correctness step in OSINT: emails get
lower-cased, IPv4s get re-parsed, domains get punycode-folded and
de-www'd, etc. We do this once at ingest so the graph keys are
canonical and stable.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import re
from typing import Any, Dict, Optional, Tuple


class EntityType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    EMAIL = "email"
    USERNAME = "username"
    URL = "url"
    HASH = "hash"            # generic hash artifact
    BTC_ADDRESS = "btc_address"
    PERSON = "person"
    ORG = "org"
    BREACH = "breach"
    REPO = "repo"


_DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})+$")
_EMAIL_RE = re.compile(r"^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$")
_USERNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._\-]{0,38})$")
_HEX64_RE = re.compile(r"^[a-f0-9]{64}$")
_HEX40_RE = re.compile(r"^[a-f0-9]{40}$")
_HEX32_RE = re.compile(r"^[a-f0-9]{32}$")
_BTC_RE = re.compile(r"^(bc1[ac-hj-np-z02-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")


def _strip_www(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


def _is_ip(value: str) -> Optional[str]:
    try:
        ip = ipaddress.ip_address(value.strip())
        return str(ip)
    except ValueError:
        return None


def normalise(etype: EntityType, value: str) -> str:
    """Canonicalise a raw value for the given entity type.

    Raises ValueError if the value cannot be made canonical for that type.
    """
    if value is None:
        raise ValueError("value is None")
    raw = str(value).strip()
    if not raw:
        raise ValueError("value is empty")

    if etype is EntityType.IP:
        canonical = _is_ip(raw)
        if not canonical:
            raise ValueError(f"not an IP: {raw!r}")
        return canonical

    if etype in (EntityType.DOMAIN, EntityType.SUBDOMAIN):
        v = raw.lower()
        v = v.rstrip(".")
        v = _strip_www(v)
        # Punycode-encode unicode labels (deterministic IDN handling)
        try:
            v = v.encode("idna").decode("ascii")
        except UnicodeError:
            raise ValueError(f"invalid domain: {raw!r}")
        if not _DOMAIN_RE.match(v):
            raise ValueError(f"invalid domain: {raw!r}")
        return v

    if etype is EntityType.EMAIL:
        v = raw.lower()
        if not _EMAIL_RE.match(v):
            raise ValueError(f"invalid email: {raw!r}")
        return v

    if etype is EntityType.USERNAME:
        v = raw.lower().lstrip("@")
        if not _USERNAME_RE.match(v):
            raise ValueError(f"invalid username: {raw!r}")
        return v

    if etype is EntityType.URL:
        # Minimal: lower-case scheme+host, keep path
        m = re.match(r"^(https?)://([^/]+)(/.*)?$", raw, re.I)
        if not m:
            raise ValueError(f"invalid URL: {raw!r}")
        scheme, host, path = m.group(1).lower(), m.group(2).lower(), (m.group(3) or "")
        return f"{scheme}://{host}{path}"

    if etype is EntityType.HASH:
        v = raw.lower()
        if not (_HEX64_RE.match(v) or _HEX40_RE.match(v) or _HEX32_RE.match(v)):
            raise ValueError(f"invalid hex hash: {raw!r}")
        return v

    if etype is EntityType.BTC_ADDRESS:
        if not _BTC_RE.match(raw):
            raise ValueError(f"invalid BTC address: {raw!r}")
        return raw

    if etype is EntityType.REPO:
        # github "owner/repo" form
        v = raw.lower()
        if not re.match(r"^[a-z0-9._\-]+/[a-z0-9._\-]+$", v):
            raise ValueError(f"invalid repo: {raw!r}")
        return v

    if etype in (EntityType.PERSON, EntityType.ORG, EntityType.BREACH):
        # Casefolded, whitespace-collapsed
        v = re.sub(r"\s+", " ", raw).strip()
        if not v:
            raise ValueError(f"empty {etype.value}")
        return v

    raise ValueError(f"unknown entity type {etype!r}")


@dataclass(frozen=True)
class Entity:
    type: EntityType
    value: str    # canonical
    meta: Tuple[Tuple[str, Any], ...] = field(default_factory=tuple)

    @classmethod
    def make(cls, etype: EntityType, raw_value: str,
              meta: Optional[Dict[str, Any]] = None) -> "Entity":
        canonical = normalise(etype, raw_value)
        meta_t = tuple(sorted((meta or {}).items()))
        return cls(type=etype, value=canonical, meta=meta_t)

    @property
    def key(self) -> str:
        """Stable graph node key."""
        return f"{self.type.value}:{self.value}"

    def meta_dict(self) -> Dict[str, Any]:
        return dict(self.meta)
