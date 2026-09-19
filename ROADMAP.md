<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# `iso20022-evidence-pack-mcp` roadmap

## Mission

The fully local, closed-world Model Context Protocol (MCP) server for the
**ISO 20022 MCP Suite** — the audit and certification sibling of
`iso20022-readiness-suite-mcp` and `iso20022-bank-profile-mcp`. It compiles a
readiness result, an optional remediation result, and any simulated bank
responses into one sealed, exportable audit evidence pack, and lets auditors
re-seal, verify, and render packs — all without a network surface.

## Where we are (v0.0.5, shipped 2026-08-29)

- **11 MCP tools**. Six are pure, local, deterministic, closed-world transforms
  that return typed, JSON-serialisable data and an `{"error": ...}` payload on
  any failure (never a traceback):
  - `build_evidence_pack` — fold a readiness result (+ optional remediation, +
    optional simulated responses, + metadata) into a graded, sealed pack;
    returns the pack, its digest, and a rendered markdown report.
  - `seal_pack` — compute the deterministic SHA-256 seal for a pack (raw JSON).
  - `verify_seal` — recompute a pack's seal and compare it to an expected
    digest.
  - `render_markdown` — render a pack as a markdown compliance report.
  - `sign_pack` — sign a pack's canonical bytes with the operator's Ed25519
    key; returns the detached signature, public key, and `key_id`.
  - `verify_pack_signature` — verify a detached Ed25519 signature over a pack's
    canonical bytes against a supplied public key.
  - Five reach outside the process and are annotated as such (v0.0.3):
    `sign_pack_aws_kms`, `sign_pack_vault` and `export_pack_to_s3` behind the
    `[aws]` / `[vault]` extras; `verify_slsa_provenance` and
    `verify_cosign_signature`.
- **One prompt and two resources** (v0.0.3): `audit_readiness_compliance`,
  `evidence://schema` and `evidence://error-codes`.
- **The deterministic seal**: a SHA-256 digest over the pack's canonical JSON
  (sorted keys, tight separators, the `digest` field excluded), making the
  pack **tamper-evident** — re-sealing identical content yields the identical
  digest, and changing any field breaks verification. The seal is an integrity
  digest; the signature is authenticity (see below).
- **Ed25519 pack signing (delivered, v0.0.2)**: `sign_pack` /
  `verify_pack_signature` sign and verify the pack's canonical bytes with an
  **operator-custodied** key configured via `ISO20022_EVIDENCE_PACK_SIGNING_KEY`
  / `_SIGNING_KEY_FILE`. The private key never crosses the tool boundary and the
  server never generates or persists private keys. This delivers *authenticity*
  on top of the seal's *integrity*; keyless/PKI trust roots remain below.
- **Optional HTTP transport with OAuth 2.1 (delivered, v0.0.2)**:
  `--transport=http --bind=HOST:PORT` serves the MCP server over authenticated
  streamable HTTP (loopback default), with OAuth 2.1 resource-server auth
  (RFC 9728) via `ISO20022_EVIDENCE_PACK_OAUTH_*` or a static dev-mode token,
  and an optional `X-MCP-Tenant` header forwarded into the tool-visible context.
- **Grading**: a readiness score maps to a letter grade (A/B/C/F) folded into
  the pack.
- **Transports**: stdio (default; one process per operator, launched by the
  MCP client, no network surface); the authenticated HTTP transport above;
  and, unreleased on `main`, streamable HTTP and SSE from the suite's shared
  command line (`--transport streamable-http|sse`, `--host`, `--port`).
- **Opt-in OpenTelemetry tracing** (v0.0.3) behind the `[otel]` extra
  (`--otel-endpoint`).
- **Supply chain**: 100% line + branch coverage, OpenSSF Scorecard, SLSA
  Build L3 + PEP 740 sigstore attestations on every release, CycloneDX 1.6 +
  SPDX 2.3 + pip-licenses SBOMs on every GitHub release, NIST SP 800-218 SSDF
  practice mapping in `SECURITY.md`, the suite conformance gate (v0.0.4), a
  scheduled release-consistency check against PyPI (v0.0.5), CI on Python 3.10
  to 3.14.

## Fast-follow — keyless/PKI signing, storage, entitlement gating

Goal: build on the delivered signing and HTTP transport to make the pack a
durably archived, publicly verifiable audit artifact.

- **Operator-key Ed25519 signing** — *delivered in v0.0.2* (`sign_pack` /
  `verify_pack_signature`, see above).
- **Authenticated HTTP transport with OAuth 2.1 (RFC 9728)** — *delivered in
  v0.0.2* (`--transport=http`, see above).
- **Keyless / PKI signing + trust root**: sigstore-style keyless signing and/or
  PKI, with verification against a public **trust root**, so a pack's
  authenticity can be checked without pre-sharing the operator's public key.
  This is the remaining half of the "seal is not a signature" story and the
  headline premium seam.
- **Long-term evidence storage + export formats**: durable, addressable pack
  storage and export to audit-friendly formats (PDF/A, signed archives,
  WORM-style stores) for certification and retention workflows.
- **Premium entitlement gating**: gate the higher-tier capabilities (keyless/PKI
  signing, long-term storage, white-label reports) behind an entitlement claim,
  so operators can license the features they need. The HTTP transport already
  forwards the authenticated token's scopes into the tool context as the seam
  for this.

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
- **A CA / key-management service**: the signing feature verifies and produces
  signatures with an operator-supplied key; running a certificate authority or
  key-management infrastructure (HSM/KMS) is the operator's job.

## How to influence the roadmap

- Open an issue with the proposed capability + the use case it unblocks.
- For larger items, sketch a design in the issue body.
- See [`GOVERNANCE.md`](GOVERNANCE.md) for the decision-making process.
