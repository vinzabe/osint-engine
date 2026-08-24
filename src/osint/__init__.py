"""osint — multi-source OSINT with provenance and privacy built in.

OSINT tooling makes it easy to over-collect: hoover up everything about a target,
merge it, and keep it forever. That is a privacy and legal liability, and it buries
the signal. This engine takes the opposite defaults:

  * **Provenance on every datum** — what it is, which source produced it, and when.
    A finding you cannot attribute is a finding you cannot defend.
  * **PII minimisation by default** — emails, phones, and similar are redacted
    unless explicitly requested, and never merged across sources without a
    confidence gate.
  * **Retention as code** — data past its retention window is dropped on access, not
    "documented as should-be-deleted".
"""
__version__ = "1.0.0"
