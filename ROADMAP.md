<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# `iso20022-evidence-pack-mcp` roadmap

## Mission

The fully local, closed-world Model Context Protocol (MCP) server for the
**ISO 20022 MCP Suite** — the audit and certification sibling of
`iso20022-readiness-suite-mcp` and `iso20022-bank-profile-mcp`. It compiles a
readiness result, an optional remediation result, and any simulated bank
responses into one sealed, exportable audit evidence pack, and lets auditors
re-seal, verify, and render packs — all without a network surface.

## Where we are (v0.0.1, shipped 2026-07-18)

- **4 MCP tools** over stdio, each a pure, local, deterministic, closed-world
  transform that returns typed, JSON-serialisable data and an
  `{"error": ...}` payload on any failure (never a traceback):
  - `build_evidence_pack` — fold a readiness result (+ optional remediation, +
    optional simulated responses, + metadata) into a graded, sealed pack;
    returns the pack, its digest, and a rendered markdown report.
  - `seal_pack` — compute the deterministic SHA-256 seal for a pack (raw JSON).
  - `verify_seal` — recompute a pack's seal and compare it to an expected
    digest.
  - `render_markdown` — render a pack as a markdown compliance report.
- **The deterministic seal**: a SHA-256 digest over the pack's canonical JSON
  (sorted keys, tight separators, the `digest` field excluded), making the
  pack **tamper-evident** — re-sealing identical content yields the identical
  digest, and changing any field breaks verification. The seal is an integrity
  digest, **not** a cryptographic signature (see below).
- **Grading**: a readiness score maps to a letter grade (A/B/C/F) folded into
  the pack.
- **Stdio transport** (FastMCP default): one process per operator, launched
  by the MCP client, no network surface, no authentication needed.
- **Supply chain**: 100% line + branch coverage, OpenSSF Scorecard, SLSA
  Build L3 + PEP 740 sigstore attestations on every release, CycloneDX 1.6 +
  SPDX 2.3 + pip-licenses SBOMs on every GitHub release, NIST SP 800-218 SSDF
  practice mapping in `SECURITY.md`.

## Fast-follow — signing, storage, HTTP transport, entitlement gating

Goal: turn the tamper-evident pack into an authenticatable, durably archived,
shareable audit artifact.

- **Cryptographic signing / PKI**: sign the pack (or its seal) with an operator
  key so a pack proves **authenticity**, not just integrity — sigstore keyless
  and/or an operator-supplied key, with verification against a trust root. This
  closes the "seal is not a signature" gap called out below and is the headline
  premium seam.
- **Long-term evidence storage + export formats**: durable, addressable pack
  storage and export to audit-friendly formats (PDF/A, signed archives,
  WORM-style stores) for certification and retention workflows.
- **HTTP/SSE transport variant**:
  `iso20022-evidence-pack-mcp --transport=http --bind=…` alongside the default
  stdio, with an optional tenant header forwarded into the tool-visible
  `Context` for multi-tenant scoping, and OAuth 2.1 resource-server auth
  (RFC 9728) on the HTTP transport.
- **Premium entitlement gating**: gate the higher-tier capabilities (signing,
  long-term storage, white-label reports) behind an entitlement claim, so
  operators can license the features they need.

## Later

Goal: post-Nov-2026, field-tested behaviour.

- **Observability**: Prometheus metrics on the MCP layer (request/tool
  counters, tool latency histograms) and a tamper-evident audit chain over
  sealed packs.
- **Richer reports**: scheme-specific report templates, batch pack assembly,
  and cross-message evidence roll-ups.
- **MCP API surface freeze** at the first stable minor: any future tool name
  change becomes a minor-bump event per SemVer.
- **OpenSSF Best Practices** badge progression (Passing → Silver → Gold).

## Out of scope (until a contributor steps up)

- **Embedded LLM**: this server delegates all inference to the client's model
  via MCP; no bundled LLM weights, no hosted inference endpoint.
- **Reimplementing sibling logic**: readiness scoring, remediation, and message
  generation/parsing stay in the sibling servers; this server folds their
  results into a pack, it does not reproduce them.
- **A CA / key-management service**: the planned signing feature verifies and
  produces signatures; running a certificate authority or key-management
  infrastructure is the operator's job.

## How to influence the roadmap

- Open an issue with the proposed capability + the use case it unblocks.
- For larger items, sketch a design in the issue body.
- See [`GOVERNANCE.md`](GOVERNANCE.md) for the decision-making process.
