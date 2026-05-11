"""Pivot computation: which entities are most worth pursuing next?

We compute three signals and combine them:
    - degree centrality   (how many things this node touches)
    - betweenness         (how often this node bridges otherwise-separate
                           subgraphs -- a hallmark of "linchpin" identifiers)
    - source diversity    (number of distinct sources that mention this node)

The output is a ranked list of Pivot objects. Each Pivot also carries
its 1-hop neighbour types so an analyst can see *why* it's a pivot.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import networkx as nx

from .graph import EntityGraph


class PivotKind(str, Enum):
    HIGH_DEGREE = "high_degree"
    BRIDGE = "bridge"
    MULTI_SOURCE = "multi_source"
    COMBINED = "combined"


@dataclass
class Pivot:
    key: str                          # entity key
    type: str                         # entity type
    value: str                        # canonical value
    score: float                      # combined 0..1 score
    degree: int
    betweenness: float
    source_diversity: int
    sources: List[str]
    neighbour_types: Dict[str, int]
    kind: PivotKind
    cluster_id: Optional[int] = None

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["kind"] = self.kind.value
        return d


class PivotEngine:
    def __init__(self, *, top_k: int = 10,
                  weight_degree: float = 0.4,
                  weight_betweenness: float = 0.4,
                  weight_diversity: float = 0.2):
        s = weight_degree + weight_betweenness + weight_diversity
        if s <= 0:
            raise ValueError("at least one weight must be > 0")
        self.top_k = max(1, int(top_k))
        # Normalise weights
        self.w_deg = weight_degree / s
        self.w_bt = weight_betweenness / s
        self.w_div = weight_diversity / s

    def compute(self, graph: EntityGraph) -> List[Pivot]:
        g = graph.nx
        if g.number_of_nodes() == 0:
            return []
        deg = dict(g.degree())
        # Betweenness on small graphs is cheap; cap k to avoid pathological cost
        if g.number_of_nodes() > 200:
            bt = nx.betweenness_centrality(g, k=200, seed=0,
                                                  weight=None)
        else:
            bt = nx.betweenness_centrality(g, weight=None)

        # Source diversity per node = number of distinct source names
        # appearing on incident edges.
        diversity: Dict[str, int] = {}
        sources_per_node: Dict[str, set] = {}
        for u, v, d in g.edges(data=True):
            srcs = d.get("sources", set())
            for n in (u, v):
                sources_per_node.setdefault(n, set()).update(srcs)
        for k, ss in sources_per_node.items():
            diversity[k] = len(ss)

        max_deg = max(deg.values()) if deg else 1
        max_bt = max(bt.values()) if bt else 1.0
        max_div = max(diversity.values()) if diversity else 1
        max_deg = max(max_deg, 1)
        max_bt = max(max_bt, 1e-9)
        max_div = max(max_div, 1)

        pivots: List[Pivot] = []
        for k, d in g.nodes(data=True):
            n_deg = deg.get(k, 0) / max_deg
            n_bt = bt.get(k, 0.0) / max_bt
            n_div = diversity.get(k, 0) / max_div
            score = self.w_deg * n_deg + self.w_bt * n_bt + self.w_div * n_div
            # Choose the dominant signal as the kind label
            signals = [
                (PivotKind.HIGH_DEGREE, n_deg * self.w_deg),
                (PivotKind.BRIDGE, n_bt * self.w_bt),
                (PivotKind.MULTI_SOURCE, n_div * self.w_div),
            ]
            kind = max(signals, key=lambda x: x[1])[0]
            # If two signals are close, mark as combined
            sorted_sigs = sorted(signals, key=lambda x: x[1], reverse=True)
            if sorted_sigs[0][1] - sorted_sigs[1][1] < 0.05 and score > 0:
                kind = PivotKind.COMBINED

            # Neighbour-type histogram
            ntypes: Dict[str, int] = {}
            for nb in g.neighbors(k):
                t = g.nodes[nb].get("type", "unknown")
                ntypes[t] = ntypes.get(t, 0) + 1

            pivots.append(Pivot(
                key=k, type=d.get("type", "unknown"),
                value=d.get("value", ""),
                score=float(score),
                degree=int(deg.get(k, 0)),
                betweenness=float(bt.get(k, 0.0)),
                source_diversity=int(diversity.get(k, 0)),
                sources=sorted(sources_per_node.get(k, set())),
                neighbour_types=ntypes,
                kind=kind,
                cluster_id=d.get("cluster_id"),
            ))

        pivots.sort(key=lambda p: p.score, reverse=True)
        return pivots[: self.top_k]
