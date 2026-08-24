import json

import pytest

from osint.cli import main


def test_sweep_default_minimises_pii(capsys):
    main(["sweep", "example.com", "--now", "2026-08-01"])
    out = capsys.readouterr().out
    assert "PII minimised" in out
    assert "admin@example.com" not in out


def test_sweep_json_has_provenance(capsys):
    main(["sweep", "example.com", "--now", "2026-08-01", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert all("sources" in d for d in data)


def test_include_pii_flag(capsys):
    main(["sweep", "example.com", "--now", "2026-08-01", "--include-pii", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert any(d["value"] == "admin@example.com" for d in data)


def test_version():
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
