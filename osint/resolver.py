"""Entity resolution.

Two entities should be merged into the same "actor cluster" when:
    - they are the same canonical value (handled by graph dedupe), OR
    - they are linked by a high-confidence shared identifier
      (e.g. same email mentioned in github commits AND in a breach AND in
      whois) -- we approximate this by transitive closure over edges
      whose weight crosses a threshold.

We don't try to do general PII re-identification; the resolver here
finds *clusters of likely-same-actor entities* in graph space, with a
configurable confidence threshold.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set

import networkx as nx

from .graph import EntityGraph, EdgeKind


@dataclass
class Cluster:
    cluster_id: int
    members: List[str]              # entity keys
    type_breakdown: Dict[str, int]  # {"email": 2, "username": 1, ...}
    score: float                    # mean intra-cluster edge weight

    def to_dict(self) -> dict:
        return {
            "cluster_id": self.cluster_id,
            "members": self.members,
            "type_breakdown": self.type_breakdown,
            "score": self.score,
        }


class EntityResolver:
    """Cluster the EntityGraph using a weight threshold + connected components.

    `min_edge_weight` is the cumulative weight required for an edge to be
    considered "strong evidence of co-identity". Edges below this threshold
    still exist in the graph but do not pull entities into the same cluster.
    """

    def __init__(self, *, min_edge_weight: float = 1.0,
                  max_cluster_size: int = 50):
        if min_edge_weight <= 0:
            raise ValueError("min_edge_weight must be > 0")
        if max_cluster_size < 2:
            raise ValueError("max_cluster_size must be >= 2")
        self.min_edge_weight = min_edge_weight
        self.max_cluster_size = max_cluster_size

    def resolve(self, graph: EntityGraph) -> List[Cluster]:
        # Build a subgraph of strong edges
        strong = nx.Graph()
        strong.add_nodes_from(graph.nx.nodes(data=True))
        for u, v, d in graph.nx.edges(data=True):
            if d.get("weight", 0.0) >= self.min_edge_weight:
                strong.add_edge(u, v, **d)

        clusters: List[Cluster] = []
        for cid, comp in enumerate(nx.connected_components(strong)):
            if len(comp) < 2:
                continue
            if len(comp) > self.max_cluster_size:
                continue
            sub = strong.subgraph(comp)
            weights = [d.get("weight", 0.0) for _, _, d in sub.edges(data=True)]
            score = float(sum(weights) / max(len(weights), 1))
            type_counts: Dict[str, int] = {}
            for k in comp:
                t = strong.nodes[k].get("type", "unknown")
                type_counts[t] = type_counts.get(t, 0) + 1
            clusters.append(Cluster(
                cluster_id=cid,
                members=sorted(comp),
                type_breakdown=type_counts,
                score=score,
            ))
        # Higher-score clusters first
        clusters.sort(key=lambda c: c.score, reverse=True)
        # Re-number after sort for deterministic output
        for i, c in enumerate(clusters):
            c.cluster_id = i
        return clusters

    def annotate_graph(self, graph: EntityGraph,
                          clusters: List[Cluster]) -> None:
        """Stamp cluster_id onto each member node (in-place)."""
        for c in clusters:
            for k in c.members:
                if k in graph.nx:
                    graph.nx.nodes[k]["cluster_id"] = c.cluster_id
