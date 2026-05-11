# Security Policy

## Reporting

Report vulnerabilities responsibly to the repository owner by email -- do not open public issues.

## Defensive use only

`osint-engine` is built for **defensive** OSINT correlation: SOC
analysts, fraud teams, takedown operators, and threat-intel researchers.
The bundled fixtures are entirely fictional and use the `*.example`
TLD plus RFC-5737 IP space. The engine itself is data-source-agnostic
and could be pointed at live sources by adding new `Source` subclasses;
that step is deliberately left to the user so this repo cannot be
mistaken for a turnkey doxing tool.

## Hard guarantees

- **No active scanning.** None of the bundled sources opens a network
  socket. Adding a real source is the user's responsibility and brings
  the user's own legal and ethical considerations.
- **Entity inputs are normalised before the graph touches them.** This
  prevents trivial bypasses (case, IDN, www-prefix, leading-zero IP).
- **The LLM cannot inject entities.** `LLMIntelSummariser._coerce`
  rejects any `next_pivot.target` that is not in the engine's pivot or
  cluster set, and any `source_to_query` not in the fixed enum
  `{whois, dns, ct, github, paste, breach, social}`.
- **A single bad source cannot crash the run.** Each source's
  `fetch()` is wrapped in try/except in `CorrelationEngine.correlate`.
- **Bad fixture rows are dropped silently.** `_FixtureSource.fetch`
  swallows per-row parse errors so a single malformed entity (e.g. an
  invalid email) cannot poison the rest of the dataset.

## Limits

- The clustering used by `EntityResolver` is a strong-edge transitive
  closure -- it is *not* probabilistic record-linkage. False merges
  remain possible if a low-confidence source asserts a wrong link with
  high cumulative weight. Tune `min_edge_weight` per use-case.
- The LLM summary is advisory. Treat its `confidence` field as a
  rough heuristic. The engine's quantitative pivot scores remain the
  authoritative output.

## Privacy

When wiring this engine to live sources you become responsible for the
PII it touches. Suggested guard-rails:

- Apply a per-source allow-list of TLDs / IP ranges before calling
  `correlate`.
- Mask or hash sensitive fields before they reach the LLM (the
  summariser receives only the entity-key + neighbour-type summary by
  default; do not pass raw email bodies / passwords / etc. through
  the `evidence` dict if you intend to keep `summarise` enabled).
- Apply retention policies to any `to_dict()` dumps you persist.
