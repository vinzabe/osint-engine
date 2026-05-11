"""High-level CorrelationEngine: orchestrates sources -> graph -> resolver -> pivots."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from .graph import EntityGraph
from .pivot import Pivot, PivotEngine
from .resolver import Cluster, EntityResolver
from .sources import Source, SourceRecord


@dataclass
class CorrelationResult:
    seed_queries: List[str]
    graph: EntityGraph
    clusters: List[Cluster]
    pivots: List[Pivot]
    source_coverage: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "seed_queries": list(self.seed_queries),
            "graph": self.graph.to_dict(),
            "clusters": [c.to_dict() for c in self.clusters],
            "pivots": [p.to_dict() for p in self.pivots],
            "source_coverage": dict(self.source_coverage),
            "n_nodes": len(self.graph),
            "n_edges": self.graph.num_edges(),
            "n_clusters": len(self.clusters),
            "n_pivots": len(self.pivots),
        }


class CorrelationEngine:
    def __init__(self, sources: Iterable[Source],
                  *, resolver: Optional[EntityResolver] = None,
                  pivot_engine: Optional[PivotEngine] = None):
        self.sources = list(sources)
        if not self.sources:
            raise ValueError("at least one source required")
        self.resolver = resolver or EntityResolver()
        self.pivot_engine = pivot_engine or PivotEngine()

    def correlate(self, seed_queries: List[str]) -> CorrelationResult:
        if not seed_queries:
            raise ValueError("seed_queries must be non-empty")
        graph = EntityGraph()
        coverage: Dict[str, int] = {s.name: 0 for s in self.sources}

        # Iterate seeds, then re-query newly-discovered identifiers up to
        # `max_hops` deep to expand the graph naturally.
        queried: set[str] = set()
        queue = list(seed_queries)
        max_hops = 3
        for hop in range(max_hops):
            next_queue: List[str] = []
            for q in queue:
                if q in queried:
                    continue
                queried.add(q)
                for source in self.sources:
                    try:
                        any_record = False
                        for record in source.fetch(q):
                            any_record = True
                            graph.ingest(record)
                            # Stage further-hop queries from the canonical
                            # values of this record's entities.
                            for e in record.entities:
                                if (e.value not in queried
                                          and e.value not in next_queue):
                                    next_queue.append(e.value)
                        if any_record:
                            coverage[source.name] += 1
                    except Exception:
                        # A single bad source must never poison the run
                        continue
            queue = next_queue

        clusters = self.resolver.resolve(graph)
        self.resolver.annotate_graph(graph, clusters)
        pivots = self.pivot_engine.compute(graph)

        return CorrelationResult(
            seed_queries=list(seed_queries), graph=graph,
            clusters=clusters, pivots=pivots,
            source_coverage=coverage,
        )
