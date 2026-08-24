import datetime as dt

from osint.engine import Engine

TODAY = dt.date(2026, 8, 1)


def test_entity_resolution_merges_and_attributes(sources):
    results = Engine(sources).sweep("example.com", now=TODAY)
    dom = next(r for r in results if r.finding.value == "www.example.com")
    assert dom.corroborated                          # seen by 2 sources
    assert set(dom.sources) == {"src-a", "src-b"}    # both recorded
    assert dom.finding.confidence > 0.8              # corroboration bonus


def test_pii_minimised_by_default(sources):
    results = Engine(sources).sweep("example.com", now=TODAY)
    email = next(r for r in results if r.finding.type.value == "email")
    assert email.finding.value != "admin@example.com"   # redacted


def test_pii_included_on_request(sources):
    results = Engine(sources).sweep("example.com", now=TODAY, include_pii=True)
    email = next(r for r in results if r.finding.type.value == "email")
    assert email.finding.value == "admin@example.com"


def test_merge_confidence_gate_drops_weak_pii(sources):
    # a single-source email at 0.6; gate at 0.8 -> dropped
    results = Engine(sources).sweep("example.com", now=TODAY, include_pii=True,
                                    merge_confidence=0.8)
    assert not any(r.finding.type.value == "email" for r in results)


def test_results_sorted_by_confidence(sources):
    results = Engine(sources).sweep("example.com", now=TODAY)
    confs = [r.finding.confidence for r in results]
    assert confs == sorted(confs, reverse=True)
