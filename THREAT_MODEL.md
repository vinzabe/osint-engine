# Threat model, scope & authorized-use

## Intended use
Authorized OSINT: mapping your own external attack surface, an engagement with a
written scope, or threat research on infrastructure. The privacy-by-default posture
exists to keep such use lawful and proportionate.

## Not for
Stalking, doxxing, or compiling dossiers on private individuals. The tool minimises
PII by default and expires data specifically to discourage this; the `--include-pii`
flag is a deliberate, auditable choice that the operator is accountable for.

## Trust boundaries & limits
- **Sources are pluggable and their output is trusted as collected.** A source can
  return wrong/poisoned data; provenance lets you attribute and discount it, but the
  engine does not verify source truthfulness.
- **Entity resolution is heuristic** (exact type+value match). It will not merge
  `Corp Inc` and `Corp, Inc.`; over/under-merging is possible and confidence, not
  certainty, is what it reports.
- **Retention/lawful-basis are the operator's legal duty.** The engine enforces a
  retention window and minimises PII, but jurisdiction-specific compliance (GDPR
  lawful basis, notice) is on the deployer.

## Non-goals
- Active exploitation or intrusive probing — this is passive collection modelling.
- De-anonymisation or cross-source identity fabrication (explicitly gated against).
- Being a data source — it collects via the sources you provide.

## Reporting
A path that returns raw PII without `--include-pii`, or fails to expire data past
retention, is a privacy bug — report to **gabejar@usa.com**.
