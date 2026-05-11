# osint-engine

Graph-based OSINT correlation engine for SOC analysts and threat-intel
teams. Pulls from pluggable sources (whois, DNS, certificate
transparency, GitHub, paste sites, breach databases, social), de-duplicates
and normalises entities, builds a weighted multi-source graph, runs
entity resolution + pivot analysis, then asks an LLM to produce a
structured intel report.

```
seed query
  -> Sources (whois | dns | ct | github | paste | breach | social)
  -> Entity normalisation (Entity.make / normalise)
  -> EntityGraph (NetworkX, weighted multi-source edges)
  -> EntityResolver (cluster by strong-edge transitive closure)
  -> PivotEngine (degree + betweenness + source diversity)
  -> LLMIntelSummariser  (validated, no hallucinated entities)
```

## Why this design

- **Normalisation up front.** The most common OSINT bug is failing to
  recognise that `Alice@Corp.com`, `alice@corp.com`, and the same email
  in a breach dump are the same entity. Every value flows through
  `osint.entity.normalise` before it ever touches the graph.
- **Source confidence is preserved.** Each edge carries the set of
  source names that asserted it; weights accumulate so an
  email-username link backed by paste + github + breach is strictly
  stronger than one backed by paste alone.
- **The LLM cannot invent entities.** The summariser post-validates
  every `next_pivot.target` against the engine's entity-key set and
  silently drops hallucinations. Same for the `source_to_query` field.
- **Bad sources do not poison the run.** Each source is wrapped in a
  try/except in the engine; a malformed JSON row or HTTP timeout cannot
  bring down the pipeline.

## Bundled fixtures

`fixtures/` ships a coherent fictional scenario: a phishing-infrastructure
operator (`darkfox42`) linked across two phishing domains, a shared
nameserver and IP, an O365-clone GitHub repo, three breach exposures,
and two social-platform accounts. All identifiers use `*.example` /
RFC-5737 IPs (`198.51.100.0/24`) -- nothing real.

## Quick start

```bash
pip install -r requirements.txt

# Build graph and dump
python -m osint.cli correlate --seed secure-corp-login.example --compact

# Same, plus LLM intel summary
python -m osint.cli summarise --seed secure-corp-login.example
```

## Output

`correlate` returns:

```json
{
  "seed_queries": ["secure-corp-login.example"],
  "n_nodes": 28, "n_edges": 35,
  "n_clusters": 1, "n_pivots": 10,
  "source_coverage": {"whois": 2, "dns": 2, "ct": 2, "github": 1,
                          "paste": 2, "breach": 1, "social": 1},
  "clusters": [{"cluster_id": 0, "score": 0.95,
                    "type_breakdown": {"email": 2, "username": 1, ...}}],
  "pivots": [{"key": "email:darkfox42@protonmail.example",
                  "kind": "combined", "score": 0.96, ...}],
  "graph": {...}
}
```

`summarise` adds:

```json
{
  "headline": "Phishing operator linked across 7 sources",
  "primary_actor_hypothesis": "Single operator using darkfox42 alias",
  "key_findings": ["Two phishing domains share registrant", ...],
  "next_pivots": [
    {"target": "email:darkfox42@protonmail.example",
      "rationale": "Hub identifier across breach and paste",
      "source_to_query": "breach"}
  ],
  "confidence": 0.78,
  "caveats": ["Fixtures are not live data"]
}
```

## Adding a real source

```python
from osint.sources import Source, SourceRecord
from osint.entity import Entity, EntityType

class CrtShSource(Source):
    name = "crt.sh"
    confidence = 0.9
    def fetch(self, query):
        for row in requests.get(f"https://crt.sh/?q={query}&output=json").json():
            ents = [Entity.make(EntityType.DOMAIN, query)]
            for san in (row.get("name_value") or "").splitlines():
                try:
                    ents.append(Entity.make(EntityType.SUBDOMAIN, san))
                except ValueError:
                    pass
            rels = [(0, i, "ct_san") for i in range(1, len(ents))]
            yield SourceRecord(self.name, ents, rels, self.confidence,
                                   evidence={"row": row})
```

Then `engine = CorrelationEngine([..., CrtShSource()])`.

## Layout

```
osint/
  entity.py       Entity + normalise() (lowercase / IDN-fold / IP-canonicalise)
  sources.py     Source ABC + 7 fixture-backed adapters
  graph.py       EntityGraph (NetworkX + multi-source weighted edges)
  resolver.py    EntityResolver -> Cluster (strong-edge components)
  pivot.py       PivotEngine -> Pivot (degree + betweenness + diversity)
  engine.py      CorrelationEngine (orchestrator + multi-hop expansion)
  summariser.py  LLMIntelSummariser -> IntelReport (validated)
  cli.py         osint {correlate, summarise}
fixtures/        whois/dns/ct/github/paste/breach/social JSON
tests/test_osint.py     46 unit + 1 live LLM smoke
```

## Tests

```bash
pytest tests/ -v
LLM_LIVE=1 pytest tests/ -v
```

## License

MIT
