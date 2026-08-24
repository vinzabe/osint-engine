import datetime as dt

from osint.model import DatumType, Finding
from osint.privacy import apply_privacy, redact

TODAY = dt.date(2026, 8, 1)


def test_redact_email():
    assert redact("admin@example.com", DatumType.EMAIL).endswith("@example.com")
    assert "admin" not in redact("admin@example.com", DatumType.EMAIL)


def test_redact_phone_keeps_last_four():
    r = redact("+1-555-123-4567", DatumType.PHONE)
    assert r.endswith("4567") and "123" not in r


def test_pii_redacted_by_default():
    f = [Finding(DatumType.EMAIL, "user@x.com", "s", TODAY)]
    out = apply_privacy(f, include_pii=False, now=TODAY, retention_days=365)
    assert "@x.com" in out[0].value and out[0].value != "user@x.com"


def test_pii_included_when_requested():
    f = [Finding(DatumType.EMAIL, "user@x.com", "s", TODAY)]
    out = apply_privacy(f, include_pii=True, now=TODAY, retention_days=365)
    assert out[0].value == "user@x.com"


def test_retention_drops_expired():
    old = Finding(DatumType.DOMAIN, "old.com", "s", dt.date(2020, 1, 1))
    new = Finding(DatumType.DOMAIN, "new.com", "s", TODAY)
    out = apply_privacy([old, new], include_pii=False, now=TODAY,
                        retention_days=365)
    assert [f.value for f in out] == ["new.com"]


def test_non_pii_never_redacted():
    f = [Finding(DatumType.DOMAIN, "www.example.com", "s", TODAY)]
    out = apply_privacy(f, include_pii=False, now=TODAY, retention_days=365)
    assert out[0].value == "www.example.com"
