"""Test suite for the OSINT correlation engine."""
from __future__ import annotations
import json
import os
import sys
import types
from pathlib import Path

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..")))

from osint.entity import Entity, EntityType, normalise  # noqa: E402
from osint.sources import (  # noqa: E402
    SourceRecord, WhoisSource, DNSSource, CertificateTransparencySource,
    GitHubSource, PasteSource, BreachSource, SocialSource, load_all_fixtures,
)
from osint.graph import EntityGraph, EdgeKind  # noqa: E402
from osint.resolver import EntityResolver, Cluster  # noqa: E402
from osint.pivot import PivotEngine, PivotKind  # noqa: E402
from osint.engine import CorrelationEngine  # noqa: E402
from osint.summariser import LLMIntelSummariser, IntelReport  # noqa: E402


FIXTURES = Path(_HERE).resolve().parent / "fixtures"


# ================================================================== entity

def test_normalise_email_lowercases():
    assert normalise(EntityType.EMAIL, "  USER@Example.COM  ") == "user@example.com"


def test_normalise_domain_strips_www_and_lowercases():
    assert normalise(EntityType.DOMAIN, "WWW.Example.com.") == "example.com"


def test_normalise_domain_idn_punycode():
    out = normalise(EntityType.DOMAIN, "bücher.example")
    assert out == "xn--bcher-kva.example"


def test_normalise_ip_canonicalises():
    # Python's ipaddress refuses leading-zero octets (octal-ambiguity CVE);
    # we just exercise plain whitespace stripping here.
    assert normalise(EntityType.IP, "  192.168.1.1 ") == "192.168.1.1"


def test_normalise_ip_v6():
    out = normalise(EntityType.IP, "2001:DB8::1")
    assert out == "2001:db8::1"


def test_normalise_username_strips_at_and_lowers():
    assert normalise(EntityType.USERNAME, "@DarkFox42") == "darkfox42"


def test_normalise_url_lowercases_scheme_and_host():
    out = normalise(EntityType.URL, "HTTPS://Example.COM/Path")
    assert out == "https://example.com/Path"


def test_normalise_hash_validates_hex_lengths():
    assert normalise(EntityType.HASH, "5d41402abc4b2a76b9719d911017c592") == \
            "5d41402abc4b2a76b9719d911017c592"
    with pytest.raises(ValueError):
        normalise(EntityType.HASH, "not-hex")


def test_normalise_repo_format():
    assert normalise(EntityType.REPO, "DarkFox42/Phish-Kit") == "darkfox42/phish-kit"
    with pytest.raises(ValueError):
        normalise(EntityType.REPO, "missing-slash")


def test_normalise_rejects_invalid_inputs():
    with pytest.raises(ValueError):
        normalise(EntityType.EMAIL, "not-an-email")
    with pytest.raises(ValueError):
        normalise(EntityType.DOMAIN, "")
    with pytest.raises(ValueError):
        normalise(EntityType.IP, "999.999.999.999")


def test_entity_make_canonicalises_and_keys():
    e = Entity.make(EntityType.EMAIL, "  USER@Example.com  ")
    assert e.value == "user@example.com"
    assert e.key == "email:user@example.com"


def test_entity_meta_round_trip():
    e = Entity.make(EntityType.DOMAIN, "example.com",
                       meta={"source": "fixture", "ts": 1234567890})
    assert e.meta_dict() == {"source": "fixture", "ts": 1234567890}


# =================================================================== sources

def test_source_record_validates_relations():
    e1 = Entity.make(EntityType.DOMAIN, "a.example")
    e2 = Entity.make(EntityType.DOMAIN, "b.example")
    SourceRecord("test", [e1, e2], [(0, 1, "rel")], confidence=0.5)
    with pytest.raises(ValueError):
        SourceRecord("test", [e1, e2], [(0, 0, "rel")], confidence=0.5)
    with pytest.raises(ValueError):
        SourceRecord("test", [e1, e2], [(0, 5, "rel")], confidence=0.5)


def test_source_record_rejects_bad_confidence():
    e1 = Entity.make(EntityType.DOMAIN, "a.example")
    e2 = Entity.make(EntityType.DOMAIN, "b.example")
    with pytest.raises(ValueError):
        SourceRecord("t", [e1, e2], [], confidence=0.0)
    with pytest.raises(ValueError):
        SourceRecord("t", [e1, e2], [], confidence=1.5)


def test_whois_source_loads_fixture():
    src = WhoisSource(FIXTURES)
    records = list(src.fetch("secure-corp-login.example"))
    assert len(records) == 1
    rec = records[0]
    assert rec.source == "whois"
    assert any(e.type == EntityType.EMAIL for e in rec.entities)
    assert any(e.type == EntityType.PERSON for e in rec.entities)


def test_dns_source_resolves_to_ip():
    src = DNSSource(FIXTURES)
    rec = next(src.fetch("secure-corp-login.example"))
    ip_ents = [e for e in rec.entities if e.type == EntityType.IP]
    assert len(ip_ents) == 1
    assert ip_ents[0].value == "198.51.100.42"


def test_ct_source_emits_subdomains():
    src = CertificateTransparencySource(FIXTURES)
    rec = next(src.fetch("secure-corp-login.example"))
    subs = [e for e in rec.entities if e.type == EntityType.SUBDOMAIN]
    assert len(subs) == 3


def test_github_source_emits_repos_and_emails():
    src = GitHubSource(FIXTURES)
    rec = next(src.fetch("darkfox42"))
    assert any(e.type == EntityType.REPO for e in rec.entities)
    assert any(e.type == EntityType.EMAIL for e in rec.entities)
    assert any(e.type == EntityType.HASH for e in rec.entities)


def test_paste_source_co_mention_relations():
    src = PasteSource(FIXTURES)
    rec = next(src.fetch("darkfox42@protonmail.example"))
    # All relations should be 'paste_co_mention'
    assert {r[2] for r in rec.relations} == {"paste_co_mention"}


def test_breach_source_emits_breaches_and_hashes():
    src = BreachSource(FIXTURES)
    rec = next(src.fetch("darkfox42@protonmail.example"))
    assert any(e.type == EntityType.BREACH for e in rec.entities)
    assert any(e.type == EntityType.HASH for e in rec.entities)


def test_social_source_emits_url_and_person():
    src = SocialSource(FIXTURES)
    records = list(src.fetch("darkfox42"))
    assert len(records) == 2
    has_person = any(e.type == EntityType.PERSON
                          for r in records for e in r.entities)
    has_url = any(e.type == EntityType.URL
                       for r in records for e in r.entities)
    assert has_person and has_url


def test_source_skips_bad_rows_silently(tmp_path):
    bad = tmp_path / "whois.json"
    bad.write_text(json.dumps({
        "x.example": [
            {"domain": "x.example", "registrant_email": "not-an-email"}
        ]
    }))
    # bad email triggers ValueError inside _parse_record;
    # the source should swallow it
    records = list(WhoisSource(tmp_path).fetch("x.example"))
    assert records == []


def test_source_missing_fixture_yields_nothing(tmp_path):
    src = WhoisSource(tmp_path / "does-not-exist")
    assert list(src.fetch("anything.example")) == []


def test_load_all_fixtures_returns_seven():
    sources = load_all_fixtures(FIXTURES)
    assert {s.name for s in sources} == {
        "whois", "dns", "ct", "github", "paste", "breach", "social"
    }


# ================================================================ graph

def test_graph_dedupes_nodes_by_key():
    g = EntityGraph()
    a = Entity.make(EntityType.DOMAIN, "x.example")
    a2 = Entity.make(EntityType.DOMAIN, "X.EXAMPLE")
    g.add_entity(a)
    g.add_entity(a2)
    assert len(g) == 1


def test_graph_edge_accumulates_weight_and_sources():
    g = EntityGraph()
    a = Entity.make(EntityType.DOMAIN, "x.example")
    b = Entity.make(EntityType.IP, "1.1.1.1")
    g.add_edge(a, b, weight=0.5, source="whois", relation="resolves_to")
    g.add_edge(a, b, weight=0.4, source="dns", relation="resolves_to")
    g.add_edge(a, b, weight=0.1, source="dns", relation="historical_a")
    nbrs = dict(g.neighbours(a.key))
    edge = nbrs[b.key]
    assert edge.weight == pytest.approx(1.0)
    assert edge.sources == {"whois", "dns"}
    assert edge.relations == {"resolves_to", "historical_a"}


def test_graph_ignores_self_loops():
    g = EntityGraph()
    a = Entity.make(EntityType.DOMAIN, "x.example")
    g.add_edge(a, a, weight=1.0, source="t", relation="self")
    assert g.num_edges() == 0


def test_graph_to_dict_shape():
    g = EntityGraph()
    a = Entity.make(EntityType.DOMAIN, "x.example")
    b = Entity.make(EntityType.IP, "1.1.1.1")
    g.add_edge(a, b, weight=0.6, source="dns", relation="resolves_to")
    d = g.to_dict()
    assert d["n_nodes"] == 2
    assert d["n_edges"] == 1
    assert all("key" in n for n in d["nodes"])


# ============================================================== resolver

def test_resolver_rejects_bad_args():
    with pytest.raises(ValueError):
        EntityResolver(min_edge_weight=0)
    with pytest.raises(ValueError):
        EntityResolver(max_cluster_size=1)


def test_resolver_keeps_only_strong_edges():
    g = EntityGraph()
    a = Entity.make(EntityType.EMAIL, "a@x.example")
    b = Entity.make(EntityType.USERNAME, "alice")
    c = Entity.make(EntityType.EMAIL, "c@y.example")
    # Strong link a-b, weak link a-c
    g.add_edge(a, b, weight=2.0, source="paste", relation="x")
    g.add_edge(a, c, weight=0.2, source="paste", relation="y")
    res = EntityResolver(min_edge_weight=1.0)
    clusters = res.resolve(g)
    assert len(clusters) == 1
    assert sorted(clusters[0].members) == sorted([a.key, b.key])


def test_resolver_annotate_graph_stamps_cluster_id():
    g = EntityGraph()
    a = Entity.make(EntityType.EMAIL, "a@x.example")
    b = Entity.make(EntityType.USERNAME, "alice")
    g.add_edge(a, b, weight=2.0, source="paste", relation="x")
    res = EntityResolver(min_edge_weight=1.0)
    clusters = res.resolve(g)
    res.annotate_graph(g, clusters)
    assert g.nx.nodes[a.key]["cluster_id"] == 0
    assert g.nx.nodes[b.key]["cluster_id"] == 0


def test_resolver_drops_oversized_clusters():
    g = EntityGraph()
    hub = Entity.make(EntityType.EMAIL, "hub@x.example")
    for i in range(60):
        leaf = Entity.make(EntityType.USERNAME, f"u{i:04d}")
        g.add_edge(hub, leaf, weight=2.0, source="paste", relation="x")
    res = EntityResolver(min_edge_weight=1.0, max_cluster_size=20)
    clusters = res.resolve(g)
    assert clusters == []  # the giant component is too big


# =============================================================== pivots

def test_pivot_engine_rejects_zero_weights():
    with pytest.raises(ValueError):
        PivotEngine(weight_degree=0, weight_betweenness=0,
                       weight_diversity=0)


def test_pivot_top_k_limits_output():
    g = EntityGraph()
    hub = Entity.make(EntityType.EMAIL, "h@x.example")
    for i in range(15):
        leaf = Entity.make(EntityType.USERNAME, f"u{i:04d}")
        g.add_edge(hub, leaf, weight=0.5, source="paste", relation="x")
    pivots = PivotEngine(top_k=5).compute(g)
    assert len(pivots) == 5


def test_pivot_top_node_is_the_hub():
    g = EntityGraph()
    hub = Entity.make(EntityType.EMAIL, "h@x.example")
    for i in range(6):
        leaf = Entity.make(EntityType.USERNAME, f"u{i:04d}")
        g.add_edge(hub, leaf, weight=0.5, source="paste", relation="x")
    pivots = PivotEngine(top_k=10).compute(g)
    assert pivots[0].key == hub.key


def test_pivot_empty_graph_returns_empty():
    g = EntityGraph()
    assert PivotEngine().compute(g) == []


# =============================================================== engine

def test_engine_requires_sources():
    with pytest.raises(ValueError):
        CorrelationEngine([])


def test_engine_requires_seed():
    eng = CorrelationEngine(load_all_fixtures(FIXTURES))
    with pytest.raises(ValueError):
        eng.correlate([])


def test_engine_full_pipeline_against_fixtures():
    eng = CorrelationEngine(
        load_all_fixtures(FIXTURES),
        resolver=EntityResolver(min_edge_weight=0.7),
        pivot_engine=PivotEngine(top_k=10),
    )
    result = eng.correlate(["secure-corp-login.example"])
    # Must have visited every source
    assert all(v > 0 for v in result.source_coverage.values()), \
            result.source_coverage
    # Must have built a non-trivial graph
    assert len(result.graph) >= 20
    assert result.graph.num_edges() >= 25
    # Must have one large cluster covering at least the email + username
    assert len(result.clusters) >= 1
    big = result.clusters[0]
    assert "email:darkfox42@protonmail.example" in big.members
    assert "username:darkfox42" in big.members
    # Top pivot must be one of the actor identifiers
    top = result.pivots[0]
    assert top.value in {"darkfox42@protonmail.example", "darkfox42",
                              "secure-corp-login.example",
                              "corp-portal-update.example"}


def test_engine_bad_source_does_not_crash():
    """A misbehaving source must not poison the run."""
    class BoomSource:
        name = "boom"
        confidence = 0.5
        def fetch(self, query):
            raise RuntimeError("explode")

    sources = load_all_fixtures(FIXTURES) + [BoomSource()]
    eng = CorrelationEngine(sources)
    result = eng.correlate(["secure-corp-login.example"])
    assert len(result.graph) >= 20  # still works


# ============================================================= summariser

class _FakeLLM:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def chat(self, messages, *, model, temperature, max_tokens):
        self.calls.append({"messages": messages, "model": model})
        return types.SimpleNamespace(content=self.payload)


def _example_pivots_clusters():
    eng = CorrelationEngine(
        load_all_fixtures(FIXTURES),
        resolver=EntityResolver(min_edge_weight=0.7),
        pivot_engine=PivotEngine(top_k=8),
    )
    res = eng.correlate(["secure-corp-login.example"])
    return res


def test_summariser_parses_clean_json():
    res = _example_pivots_clusters()
    target_key = res.pivots[0].key
    payload = json.dumps({
        "headline": "Phishing operator linked across 7 sources",
        "primary_actor_hypothesis": "Single operator using darkfox42 alias",
        "key_findings": ["Two phishing domains share registrant",
                            "Email appears in 3 breaches"],
        "next_pivots": [
            {"target": target_key, "rationale": "Hub identifier",
              "source_to_query": "breach"},
        ],
        "confidence": 0.78,
        "caveats": ["Fixtures, not live data"],
    })
    summ = LLMIntelSummariser(_FakeLLM(payload))
    rep = summ.summarise(pivots=res.pivots, clusters=res.clusters,
                              source_coverage=res.source_coverage,
                              seed_query="secure-corp-login.example")
    assert isinstance(rep, IntelReport)
    assert rep.confidence == 0.78
    assert len(rep.next_pivots) == 1
    assert rep.next_pivots[0]["target"] == target_key


def test_summariser_drops_hallucinated_targets():
    res = _example_pivots_clusters()
    payload = json.dumps({
        "headline": "x", "primary_actor_hypothesis": "y",
        "key_findings": [],
        "next_pivots": [
            {"target": "email:does-not-exist@invented.example",
              "rationale": "made up", "source_to_query": "breach"},
            {"target": res.pivots[0].key,
              "rationale": "real", "source_to_query": "whois"},
        ],
        "confidence": 0.5, "caveats": [],
    })
    rep = LLMIntelSummariser(_FakeLLM(payload)).summarise(
        pivots=res.pivots, clusters=res.clusters,
        source_coverage=res.source_coverage)
    assert len(rep.next_pivots) == 1
    assert rep.next_pivots[0]["target"] == res.pivots[0].key


def test_summariser_drops_invalid_source_to_query():
    res = _example_pivots_clusters()
    payload = json.dumps({
        "headline": "x", "primary_actor_hypothesis": "y",
        "key_findings": [],
        "next_pivots": [
            {"target": res.pivots[0].key,
              "rationale": "ok", "source_to_query": "nonsense-source"},
        ],
        "confidence": 0.5, "caveats": [],
    })
    rep = LLMIntelSummariser(_FakeLLM(payload)).summarise(
        pivots=res.pivots, clusters=res.clusters,
        source_coverage=res.source_coverage)
    assert rep.next_pivots[0]["source_to_query"] == ""


def test_summariser_clamps_confidence():
    res = _example_pivots_clusters()
    payload = json.dumps({
        "headline": "x", "primary_actor_hypothesis": "y",
        "key_findings": [], "next_pivots": [],
        "confidence": 4.5, "caveats": [],
    })
    rep = LLMIntelSummariser(_FakeLLM(payload)).summarise(
        pivots=res.pivots, clusters=res.clusters,
        source_coverage=res.source_coverage)
    assert rep.confidence == 1.0


def test_summariser_handles_garbled_response():
    res = _example_pivots_clusters()
    rep = LLMIntelSummariser(_FakeLLM("not json at all")).summarise(
        pivots=res.pivots, clusters=res.clusters,
        source_coverage=res.source_coverage)
    assert rep.headline == ""
    assert rep.confidence == 0.0


def test_summariser_parses_fenced_json():
    res = _example_pivots_clusters()
    target = res.pivots[0].key
    payload = "Sure:\n```json\n" + json.dumps({
        "headline": "h", "primary_actor_hypothesis": "p",
        "key_findings": ["a"], "next_pivots": [
            {"target": target, "rationale": "r", "source_to_query": "dns"}
        ],
        "confidence": 0.5, "caveats": [],
    }) + "\n```\n"
    rep = LLMIntelSummariser(_FakeLLM(payload)).summarise(
        pivots=res.pivots, clusters=res.clusters,
        source_coverage=res.source_coverage)
    assert rep.next_pivots[0]["source_to_query"] == "dns"


# ============================================================ live LLM

@pytest.mark.skipif(not os.environ.get("LLM_LIVE"),
                          reason="set LLM_LIVE=1 to run")
def test_llm_live_summariser_smoke():
    from llm_client import LLMClient
    eng = CorrelationEngine(
        load_all_fixtures(FIXTURES),
        resolver=EntityResolver(min_edge_weight=0.7),
        pivot_engine=PivotEngine(top_k=8),
    )
    res = eng.correlate(["secure-corp-login.example"])
    summariser = LLMIntelSummariser(LLMClient(timeout=180), model="glm-5.1")
    report = summariser.summarise(
        pivots=res.pivots, clusters=res.clusters,
        source_coverage=res.source_coverage,
        seed_query="secure-corp-login.example",
    )
    assert report.headline
    assert 0.0 <= report.confidence <= 1.0
    # The LLM should propose at least one pivot, all of which must be in
    # the engine's pivot/cluster set (validator enforces this)
    valid_keys = {p.key for p in res.pivots}
    for c in res.clusters:
        valid_keys.update(c.members)
    for np_ in report.next_pivots:
        assert np_["target"] in valid_keys
    print("\nLLM headline:", report.headline)
    print("LLM confidence:", report.confidence,
            "next_pivots:", len(report.next_pivots))
