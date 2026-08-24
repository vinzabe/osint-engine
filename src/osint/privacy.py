"""PII minimisation and retention — the privacy-by-default layer.

Redaction preserves enough to be useful for correlation (a domain, a masked local
part) without storing the raw PII. Retention is enforced at access time.
"""
from __future__ import annotations

import datetime as dt

from .model import DatumType, Finding


def redact(value: str, dtype: DatumType) -> str:
    if dtype is DatumType.EMAIL and "@" in value:
        local, _, domain = value.partition("@")
        keep = local[0] if local else ""
        return f"{keep}{'*' * max(1, len(local) - 1)}@{domain}"
    if dtype is DatumType.PHONE:
        digits = [c for c in value if c.isdigit()]
        if len(digits) >= 4:
            return "*" * (len(digits) - 4) + "".join(digits[-4:])
        return "*" * len(value)
    return value


def apply_privacy(findings: list[Finding], *, include_pii: bool,
                  now: dt.date, retention_days: int) -> list[Finding]:
    """Drop expired findings and redact PII unless explicitly included."""
    cutoff = now - dt.timedelta(days=retention_days)
    out: list[Finding] = []
    for f in findings:
        if f.collected < cutoff:
            continue  # retention: silently dropped, never returned
        if f.type.is_pii and not include_pii:
            out.append(dataclasses_replace(f, value=redact(f.value, f.type)))
        else:
            out.append(f)
    return out


def dataclasses_replace(f: Finding, **kw: object) -> Finding:
    import dataclasses
    return dataclasses.replace(f, **kw)  # type: ignore[arg-type]
