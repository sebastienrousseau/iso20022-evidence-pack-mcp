# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.1] - 2026-07-18

Initial release: the fully local, closed-world Model Context Protocol (MCP)
server of the **ISO 20022 MCP Suite** — the audit and certification sibling of
`iso20022-readiness-suite-mcp` and `iso20022-bank-profile-mcp`. It compiles a
readiness result, remediation diffs, and simulated bank responses into one
sealed, exportable audit evidence pack, and lets auditors re-seal, verify, and
render packs.

### Added

- **4 MCP tools over stdio**, each a pure, local, deterministic, closed-world
  transform that returns typed, JSON-serialisable data and an `{"error": ...}`
  payload on any failure (never a traceback):
  - `build_evidence_pack` — fold a readiness result (+ optional remediation, +
    optional simulated responses, + metadata) into a graded, sealed pack;
    returns the pack, its digest, and a rendered markdown report.
  - `seal_pack` — compute the deterministic SHA-256 seal for a pack (raw JSON).
  - `verify_seal` — recompute a pack's seal and compare it to an expected
    digest.
  - `render_markdown` — render a pack as a markdown compliance report.
- **Deterministic SHA-256 seal**: a digest over the pack's canonical JSON
  (sorted keys, tight separators, the `digest` field excluded), making the pack
  **tamper-evident** — re-sealing identical content yields the identical
  digest, and changing any field breaks verification. The seal is an integrity
  digest for tamper-evidence, **not** a cryptographic signature; signing
  (keys/PKI) is a roadmap item and the operator's responsibility.
- **Grading**: a 0-100 readiness score maps to a letter grade (A/B/C/F) folded
  into the pack.
- **`iso20022-evidence-pack-mcp` console entry point** launching the FastMCP
  server over stdio (`--version` supported).
- **Read-only / closed-world tool annotations**: every tool is marked
  read-only, non-destructive, idempotent, and closed-world (no network, no
  sub-servers).
- **Supply chain**: 100% line + branch coverage gate, ruff + black +
  mypy `--strict` + bandit + interrogate in CI across Python 3.10/3.11/3.12/
  3.13; OpenSSF Scorecard; SLSA Build L3 provenance + PEP 740 sigstore
  attestations on release; CycloneDX 1.6 + SPDX 2.3 + pip-licenses SBOMs on
  every GitHub release; NIST SP 800-218 SSDF practice mapping in
  `SECURITY.md`; MCP registry + Glama directory manifests.

[0.0.1]: https://github.com/sebastienrousseau/iso20022-evidence-pack-mcp/releases/tag/v0.0.1
