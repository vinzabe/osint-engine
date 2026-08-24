# osint-engine

**Multi-source OSINT collection with provenance on every datum and PII minimisation by default — the opposite of hoover-it-all.**

OSINT tooling makes over-collection the path of least resistance: grab everything about a target, merge it, keep it forever. That is a privacy and legal liability, and it buries the actual signal. `osint-engine` inverts the defaults.

- **Provenance on every datum** — what it is, which source produced it, when. A finding you can't attribute is a finding you can't defend, so merged findings record *every* corroborating source.
- **PII minimisation by default** — emails and phones are redacted unless you explicitly pass `--include-pii`, and weak single-source PII can be gated out entirely.
- **Retention as code** — findings past the retention window are dropped on access, not "documented as should-be-deleted".

```
$ osint sweep example.com
OSINT sweep for example.com (PII minimised):

  ✓✓ [0.90] domain: www.example.com
        sources: cert-transparency, dns
  ·  [0.85] ip: 93.184.216.34
        sources: dns
  ·  [0.60] email: a****@example.com          ← redacted by default
        sources: web-scrape
```

The domain seen by two sources is marked corroborated (`✓✓`) with both sources recorded; the email is redacted unless you ask for it.

## Authorized use only

OSINT on people and organizations carries legal and ethical weight (GDPR/CCPA and similar). This tool's defaults — minimise, attribute, expire — exist to keep collection lawful and proportionate. Use it only for authorized purposes (your own attack surface, an authorized engagement, threat research on infrastructure). See [`THREAT_MODEL.md`](THREAT_MODEL.md).

## Entity resolution that stays attributable

The same datum seen by multiple sources merges into one finding, taking the max confidence **plus a corroboration bonus** — but the merge *records every contributing source*, so a high-confidence finding is never a black box. PII is only merged across sources above a confidence gate, so the engine won't fabricate a confident identity from scattered weak hits.

## Quickstart (60 seconds)

```bash
git clone https://github.com/vinzabe/osint-engine && cd osint-engine
python -m pip install -e ".[dev]"

osint sweep example.com                       # PII minimised (default)
osint sweep example.com --json                # provenance per datum
osint sweep example.com --include-pii         # raw PII (authorized use only)
osint sweep example.com --retention 90        # drop anything older than 90d
osint sweep example.com --merge-confidence 0.8  # drop weak single-source PII
```

Sources are pluggable behind a `Source` interface; the bundled ones are deterministic fixtures (cert-transparency, DNS, web-scrape) so the engine runs offline. Wire real collectors behind the same interface.

## Development

```bash
python -m pip install -e ".[dev]"
pytest --cov=osint       # 19 tests, ~94% coverage
mypy --strict src/osint  # clean
ruff check src tests     # clean
```

## License

MIT © vinzabe
