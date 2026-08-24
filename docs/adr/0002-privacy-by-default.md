# 2. Provenance always, PII minimisation and retention by default

Date: 2026-08-24
Status: Accepted

## Context
OSINT tools default to maximal collection and indefinite retention, which is a
legal/privacy liability and drowns signal in noise. The safe defaults are the
opposite, but "safe" must not mean "useless".

## Decision
- Every `Finding` carries type, source, and collection date; merged findings record
  ALL contributing sources, so nothing is unattributable.
- PII (email/phone) is redacted unless `include_pii` is explicitly set; redaction
  preserves correlation value (domain, last-4) without storing raw PII.
- Retention is enforced at access time (`apply_privacy` drops expired findings),
  not left as a policy note.
- PII is merged across sources only above a confidence gate, to avoid fabricating a
  confident identity from weak scattered hits.

## Consequences
- Defaults are lawful-by-tendency (minimise, attribute, expire); raw PII requires a
  deliberate flag, creating an audit-worthy moment.
- Redaction keeps correlation possible (matching a masked email's domain) without
  retaining the sensitive part.
- Tested: redaction, retention drop, default-minimisation, and the merge gate.
