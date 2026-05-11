"""EntityGraph: NetworkX-backed weighted graph of entities + relations.

Each node is an Entity (keyed by `entity.key`).
Each edge carries:
    weight    cumulative confidence (sum of contributing source weights)
    sources   set of source names that asserted this edge
    kinds     set of relation labels seen
    evidence  list of free-form evidence dicts

The graph dedupes nodes by canonical key, so the same entity observed
from three sources is one node with three contributing edges.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import networkx as nx

from .entity import Entity, EntityType
from .sources import SourceRecord


class EdgeKind(str, Enum):
    OBSERVATION = "observation"
    RESOLUTION = "resolution"   # entity-resolution merges


@dataclass
class Edge:
    weight: float
    sources: Set[str] = field(default_factory=set)
    relations: Set[str] = field(default_factory=set)
    kind: EdgeKind = EdgeKind.OBSERVATION
    evidence: List[Dict[str, Any]] = field(default_factory=list)


class EntityGraph:
    def __init__(self):
        self._g: nx.Graph = nx.Graph()

    @property
    def nx(self) -> nx.Graph:
        return self._g

    def add_entity(self, entity: Entity) -> str:
        key = entity.key
        if key in self._g:
            # Merge meta dictionaries (later observations may carry extra keys)
            cur = self._g.nodes[key]
            cur_meta = cur.get("meta", {}) or {}
            cur_meta.update(entity.meta_dict())
            cur["meta"] = cur_meta
        else:
            self._g.add_node(key, type=entity.type.value, value=entity.value,
                                  meta=entity.meta_dict())
        return key

    def add_edge(self, a: Entity, b: Entity, *, weight: float, source: str,
                  relation: str, kind: EdgeKind = EdgeKind.OBSERVATION,
                  evidence: Optional[Dict[str, Any]] = None) -> None:
        ka = self.add_entity(a)
        kb = self.add_entity(b)
        if ka == kb:
            return
        if self._g.has_edge(ka, kb):
            d = self._g.edges[ka, kb]
            d["weight"] = float(d.get("weight", 0.0)) + float(weight)
            d["sources"].add(source)
            d["relations"].add(relation)
            if evidence is not None:
                d["evidence"].append(evidence)
        else:
            self._g.add_edge(ka, kb,
                                weight=float(weight),
                                sources={source},
                                relations={relation},
                                kind=kind.value,
                                evidence=[evidence] if evidence else [])

    def ingest(self, record: SourceRecord) -> None:
        # First, materialise all nodes
        for e in record.entities:
            self.add_entity(e)
        # Then, add edges in declared relations
        for a_idx, b_idx, rel in record.relations:
            a = record.entities[a_idx]
            b = record.entities[b_idx]
            self.add_edge(
                a, b, weight=record.confidence,
                source=record.source, relation=rel,
                evidence={"source": record.source, "relation": rel,
                            **(record.evidence or {})},
            )

    def neighbours(self, key: str) -> List[Tuple[str, Edge]]:
        if key not in self._g:
            return []
        out = []
        for nb in self._g.neighbors(key):
            d = self._g.edges[key, nb]
            out.append((nb, Edge(weight=d["weight"],
                                       sources=set(d["sources"]),
                                       relations=set(d["relations"]),
                                       kind=EdgeKind(d.get("kind",
                                                              EdgeKind.OBSERVATION.value)),
                                       evidence=list(d.get("evidence", [])))))
        return out

    def nodes_by_type(self, etype: EntityType) -> List[str]:
        return [k for k, d in self._g.nodes(data=True) if d.get("type") == etype.value]

    def __len__(self) -> int:
        return self._g.number_of_nodes()

    def num_edges(self) -> int:
        return self._g.number_of_edges()

    def to_dict(self) -> Dict[str, Any]:
        nodes = []
        for k, d in self._g.nodes(data=True):
            nodes.append({"key": k, "type": d.get("type"),
                              "value": d.get("value"),
                              "meta": d.get("meta", {})})
        edges = []
        for u, v, d in self._g.edges(data=True):
            edges.append({"a": u, "b": v,
                              "weight": d.get("weight"),
                              "sources": sorted(d.get("sources", set())),
                              "relations": sorted(d.get("relations", set())),
                              "kind": d.get("kind")})
        return {"nodes": nodes, "edges": edges,
                  "n_nodes": len(nodes), "n_edges": len(edges)}
