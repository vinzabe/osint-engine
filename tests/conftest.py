import datetime as dt

import pytest

from osint.model import DatumType, Finding
from osint.sources import StaticSource

TODAY = dt.date(2026, 8, 1)


@pytest.fixture
def today():
    return TODAY


@pytest.fixture
def sources(today):
    a = StaticSource("src-a", [
        Finding(DatumType.DOMAIN, "www.example.com", "src-a", today, 0.7),
        Finding(DatumType.EMAIL, "admin@example.com", "src-a", today, 0.6),
    ])
    b = StaticSource("src-b", [
        Finding(DatumType.DOMAIN, "www.example.com", "src-b", today, 0.8),
        Finding(DatumType.IP, "1.2.3.4", "src-b", today, 0.9),
    ])
    return (a, b)
