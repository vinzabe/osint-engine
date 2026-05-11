"""LLM intel summariser.

Takes the (pivots, clusters, source-coverage) view of a correlation
result and produces a structured intel report:

    {
      "headline": str,
      "primary_actor_hypothesis": str,
      "key_findings": [str, ...],
      "next_pivots": [{"target": str, "rationale": str, "source_to_query": str}],
      "confidence": float,
      "caveats": [str, ...]
    }

The summariser never invents entities. We post-validate that every
"target" in next_pivots appears in the input pivot list (or in any
cluster); the LLM is asked to use canonical entity keys.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
import json
import re
from typing import Any, Dict, List, Optional

from .pivot import Pivot
from .resolver import Cluster


SYSTEM_PROMPT = """You are an OSINT intelligence analyst.

You receive:
  - A list of "pivots" (high-value entities discovered by the engine,
    each with a centrality score, source diversity, and neighbour
    profile).
  - A list of "clusters" (probable single-actor groupings of entities).
  - A summary of which sources contributed to the graph.

You must produce ONE JSON object matching this schema (no extra keys,
no comments, no prose around it):

{
  "headline": string (one sentence),
  "primary_actor_hypothesis": string (a hypothesis about the actor or
      threat the data points to; if insufficient evidence, say so),
  "key_findings": [string, ...],
  "next_pivots": [
      {"target": string (must be one of the entity keys in the input),
       "rationale": string,
       "source_to_query": string (one of: whois, dns, ct, github, paste,
                                            breach, social)}
  ],
  "confidence": float in [0,1],
  "caveats": [string, ...]
}

Rules:
  - You MUST NOT invent entities. Every "target" must be a key shown in
    the input.
  - You MUST recommend defensive next steps (e.g. "alert the SOC", "open
    a takedown ticket"), not offensive ones.
  - If sources disagree or coverage is sparse, say so in caveats and
    lower 'confidence' accordingly.
"""


@dataclass
class IntelReport:
    headline: str
    primary_actor_hypothesis: str
    key_findings: List[str]
    next_pivots: List[Dict[str, str]]
    confidence: float
    caveats: List[str]
    raw_llm_output: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class LLMIntelSummariser:
    VALID_SOURCES = {"whois", "dns", "ct", "github", "paste",
                          "breach", "social"}

    def __init__(self, llm_client: Any, *, model: str = "glm-5.1",
                  temperature: float = 0.2, max_tokens: int = 1500):
        self.client = llm_client
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

    def summarise(self, *, pivots: List[Pivot], clusters: List[Cluster],
                    source_coverage: Dict[str, int],
                    seed_query: Optional[str] = None) -> IntelReport:
        # Compact view of the input for the LLM
        pivot_view = [{
            "key": p.key, "type": p.type, "value": p.value,
            "score": round(p.score, 3),
            "degree": p.degree,
            "betweenness": round(p.betweenness, 3),
            "source_diversity": p.source_diversity,
            "sources": p.sources,
            "neighbour_types": p.neighbour_types,
            "kind": p.kind.value,
            "cluster_id": p.cluster_id,
        } for p in pivots]
        cluster_view = [c.to_dict() for c in clusters]
        # Build set of valid entity keys for post-validation
        valid_keys = {p.key for p in pivots}
        for c in clusters:
            valid_keys.update(c.members)

        user = (
            "Seed query: " + json.dumps(seed_query)
            + "\n\nSource coverage (records per source):\n"
            + json.dumps(source_coverage, indent=2)
            + "\n\nPivots:\n" + json.dumps(pivot_view, indent=2)
            + "\n\nClusters:\n" + json.dumps(cluster_view, indent=2)
            + "\n\nReturn ONLY the JSON object."
        )
        resp = self.client.chat(
            [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user},
            ],
            model=self.model, temperature=self.temperature,
            max_tokens=self.max_tokens,
        )
        raw = (getattr(resp, "content", None) or str(resp)).strip()
        parsed = self._parse_json(raw)
        return self._coerce(parsed, raw=raw, valid_keys=valid_keys)

    @staticmethod
    def _parse_json(raw: str) -> Dict[str, Any]:
        s = raw.strip()
        try:
            return json.loads(s)
        except Exception:
            pass
        m = re.search(r"```json\s*(\{.*?\})\s*```", s, re.S)
        if m:
            try:
                return json.loads(m.group(1))
            except Exception:
                pass
        m = re.search(r"\{.*\}", s, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                pass
        return {}

    def _coerce(self, parsed: Dict[str, Any], *, raw: str,
                  valid_keys: set) -> IntelReport:
        headline = str(parsed.get("headline", ""))[:300]
        actor = str(parsed.get("primary_actor_hypothesis", ""))[:1000]
        findings = parsed.get("key_findings", [])
        if not isinstance(findings, list):
            findings = [str(findings)]
        findings = [str(x) for x in findings][:30]

        next_pivots_raw = parsed.get("next_pivots", [])
        if not isinstance(next_pivots_raw, list):
            next_pivots_raw = []
        next_pivots: List[Dict[str, str]] = []
        for item in next_pivots_raw[:30]:
            if not isinstance(item, dict):
                continue
            target = str(item.get("target", "")).strip()
            if target not in valid_keys:
                # Drop hallucinated entities
                continue
            src = str(item.get("source_to_query", "")).strip().lower()
            if src not in self.VALID_SOURCES:
                src = ""
            next_pivots.append({
                "target": target,
                "rationale": str(item.get("rationale", ""))[:500],
                "source_to_query": src,
            })

        try:
            confidence = float(parsed.get("confidence", 0.0))
        except Exception:
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))

        caveats = parsed.get("caveats", [])
        if not isinstance(caveats, list):
            caveats = [str(caveats)]
        caveats = [str(x) for x in caveats][:30]

        return IntelReport(
            headline=headline, primary_actor_hypothesis=actor,
            key_findings=findings, next_pivots=next_pivots,
            confidence=confidence, caveats=caveats,
            raw_llm_output=raw,
        )
