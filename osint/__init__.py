"""osint: graph-based OSINT correlation engine.

Pipeline:
    fixture sources (whois/dns/ct/github/paste/breach/social)
        -> Entity records (typed, normalised)
        -> EntityGraph (NetworkX) with weighted, source-attributed edges
        -> ER (entity resolution / clustering)
        -> Pivots (centrality + community detection)
        -> LLM IntelSummariser

All sources here are *fixtures* (offline JSON). The same Source ABC
maps cleanly onto live HTTP collectors -- they're just out of scope for
this offline, deterministic, security-focused build.
"""
from .entity import Entity, EntityType, normalise
from .sources import (
    Source, SourceRecord, WhoisSource, DNSSource, CertificateTransparencySource,
    GitHubSource, PasteSource, BreachSource, SocialSource, load_all_fixtures,
)
from .graph import EntityGraph, Edge, EdgeKind
from .resolver import EntityResolver, Cluster
from .pivot import PivotEngine, Pivot, PivotKind
from .summariser import LLMIntelSummariser, IntelReport
from .engine import CorrelationEngine, CorrelationResult

__all__ = [
    "Entity", "EntityType", "normalise",
    "Source", "SourceRecord",
    "WhoisSource", "DNSSource", "CertificateTransparencySource",
    "GitHubSource", "PasteSource", "BreachSource", "SocialSource",
    "load_all_fixtures",
    "EntityGraph", "Edge", "EdgeKind",
    "EntityResolver", "Cluster",
    "PivotEngine", "Pivot", "PivotKind",
    "LLMIntelSummariser", "IntelReport",
    "CorrelationEngine", "CorrelationResult",
]
