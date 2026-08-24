"""The engine: sweep sources, resolve entities across them, apply privacy.

Entity resolution merges the same datum seen by multiple sources into one finding,
taking the max confidence and RECORDING every contributing source — so a merged
finding is still fully attributable.
"""
from __future__ import annotations

import dataclasses
import datetime as dt

from .model import Finding, Source
from .privacy import apply_privacy


@dataclasses.dataclass(frozen=True, slots=True)
class ResolvedFinding:
    finding: Finding
    sources: tuple[str, ...]      # every source that corroborated this datum

    @property
    def corroborated(self) -> bool:
        return len(self.sources) >= 2


@dataclasses.dataclass(slots=True)
class Engine:
    sources: tuple[Source, ...]

    def sweep(self, target: str, *, now: dt.date, include_pii: bool = False,
              retention_days: int = 365,
              merge_confidence: float = 0.0) -> list[ResolvedFinding]:
        raw: list[Finding] = []
        for src in self.sources:
            raw.extend(src.collect(target))

        # entity resolution: group by (type, value)
        groups: dict[str, list[Finding]] = {}
        for f in raw:
            groups.setdefault(f.key(), []).append(f)

        resolved: list[Finding] = []
        source_map: dict[str, tuple[str, ...]] = {}
        for items in groups.values():
            best = max(items, key=lambda x: x.confidence)
            srcs = tuple(sorted({i.source for i in items}))
            # PII is only merged across sources if corroborated above the gate,
            # to avoid fabricating a high-confidence identity from weak hits.
            conf = best.confidence
            if len(srcs) >= 2:
                conf = min(1.0, conf + 0.2 * (len(srcs) - 1))
            if best.type.is_pii and conf < merge_confidence:
                continue
            merged = dataclasses.replace(best, confidence=round(conf, 3))
            resolved.append(merged)
            source_map[merged.key()] = srcs

        private = apply_privacy(resolved, include_pii=include_pii, now=now,
                                retention_days=retention_days)
        out = [ResolvedFinding(f, source_map.get(f.key(), (f.source,)))
               for f in private]
        out.sort(key=lambda r: r.finding.confidence, reverse=True)
        return out
