# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.5] - 2026-08-29

Adds the scheduled release-consistency check this repository was
missing, and refreshes the shared conformance gate.

### Added

- `scripts/check_suite_consistency.py` and a scheduled **Release
  Consistency** workflow compare this tree against what is actually
  published on PyPI. A version bumped in the tree and never released
  breaks nothing — the tree is consistent, the tests pass, the changelog
  is written — and only the index disagrees. That has happened three
  times in this suite, each time stranding a security floor that reached
  nobody.
- The check distinguishes the two directions: a tree ahead of the index
  is the expected transient between merging a bump and pushing its tag,
  while a tree *behind* it means a release was cut from somewhere other
  than this branch.

### Changed

- Refreshed `tests/test_suite_conformance.py` to the current canonical
  copy. This repository was carrying a 24-invariant version; the
  twenty-fifth is the one that requires the check added above, so it had
  been conformant only against an older bar.

## [0.0.4] - 2026-08-28

Brings this repository onto the **suite conformance gate**.

### Added

- **`benches/bench_pack_lifecycle.py`** — build, seal, verify and render
  across finding counts. A pack is the artefact an institution keeps, and
  a real migration produces thousands of findings, not the handful in the
  fixtures.

  **Building is linear.** `us/finding` at 5,000 is **0.81x** the cost at
  10 — flat, so nothing re-serialises what it has already placed.

  **Verification does not leak timing.** `verify_seal` against a tampered
  pack costs the same as against a good one (ratio ~1.00 across sizes and
  runs). That property was never measured: a short-circuit that bails out
  on a mismatched prefix would turn the digest check into an oracle
  telling an attacker how much of a forged pack was accepted before the
  difference was found.

  The output says explicitly that the ratio must be read across runs.
  These are sub-millisecond measurements and a single row lands anywhere
  between roughly 0.6 and 1.2 on an idle machine — one low reading is
  noise, not a finding.

  Nothing asserts a timing threshold. CI runs `--quick`, so a benchmark
  that stops compiling fails the build rather than rotting.

- **`tests/test_suite_conformance.py`** — invariants shared by every
  repository in the suite, vendored from one canonical copy and
  checksummed by its own test.

### Changed

- CI lints, formats and runs `benches/` alongside everything else.
- `tomli` (on 3.10) and `packaging` are named in the dev dependency group.
  The conformance gate parses `pyproject.toml` and needs both. CI installs
  from the hash-pinned `requirements/test.txt`, where both are already
  present, so this changes nothing for the build — it records the
  requirement for anyone working locally.
- `tests/test_suite_conformance.py` is excluded from black: it is
  generated, and the suite uses three different line lengths.

## [0.0.3] - 2026-08-21

### Added

- **KMS/Vault signing, S3 export, and SLSA/cosign verification** — the
  substantive feature work in this release.
- **MCP prompts and resources** for parity across the MCP trinity.
- **Optional OpenTelemetry tracing** behind the `[otel]` extra.
- **README and docs snippets are executed in CI**, so documented
  examples cannot silently stop working.

### Fixed

- **`cryptography` 50.0.0**, the release that patches the outstanding
  advisory. The previous ceiling made it unresolvable.
- **`mcp` capped below 2.0**, restoring the FastMCP API the server is
  written against.

### Changed

- **A `lockfile` CI job.** `release.yml` installs with poetry and CI did
  not, so a stale `poetry.lock` was undetectable until a release — with
  the tag already public.
- Security policy's supported-versions table reconciled.
- Dependency and GitHub Actions updates consolidated across several
  Dependabot batches.

## [0.0.2] - 2026-07-18

Adds **cryptographic signing** of evidence packs and an **optional
authenticated HTTP transport** — turning a tamper-evident pack into an
*authenticatable* one, and letting the server run as a shared, multi-tenant
service alongside the default stdio transport.

### Added

- **Ed25519 pack signing — 2 new MCP tools** (6 tools total), separating
  *authenticity* from the seal's *integrity*:
  - `sign_pack` — sign a pack's **canonical bytes** (the exact serialization
    the seal digests) with the operator's Ed25519 private key. Returns the
    base64 detached signature, `algorithm` `"ed25519"`, the PEM public key, and
    a `key_id` (`ed25519:<16 hex>`). Because the signature covers the sealed
    content (the `digest` field excluded), a signature stays valid when only
    the `digest` changes but breaks if any sealed field changes.
  - `verify_pack_signature` — verify a detached signature over a pack's
    canonical bytes against a **public** key passed as a tool argument
    (public keys are safe to pass); returns `verified` and `key_id`. A
    malformed key or signature returns `EP_INVALID_INPUT`.
- **Operator-custodied signing key**: the Ed25519 private key is configured by
  the operator at launch via `ISO20022_EVIDENCE_PACK_SIGNING_KEY` (inline PEM)
  or `ISO20022_EVIDENCE_PACK_SIGNING_KEY_FILE` (a PEM path). The private key
  **never crosses the MCP tool boundary**; the server never generates or
  persists private keys (ideally custody them in an HSM/KMS). With no key
  configured, `sign_pack` returns `EP_NO_SIGNING_KEY`.
- **Seal vs signature, now both shipped**: the seal digest proves **integrity**
  (the content has not changed); the signature proves **authenticity** (a
  specific key attests to that content). Keyless/PKI signing and a verification
  trust root remain roadmap items.
- **Optional streamable-HTTP transport**:
  `iso20022-evidence-pack-mcp --transport=http --bind=HOST:PORT` serves the MCP
  server over authenticated streamable HTTP alongside the default stdio
  transport (`--bind` defaults to loopback `127.0.0.1:8080`). An optional
  `X-MCP-Tenant` request header is forwarded into a tool-visible context
  variable for multi-tenant scoping.
- **OAuth 2.1 resource-server auth (RFC 9728)** on the HTTP transport, enabled
  by the `ISO20022_EVIDENCE_PACK_OAUTH_*` variables — `_ISSUER` (required),
  `_AUDIENCE` (required), `_JWKS_URL` (optional; defaults to
  `<issuer>/.well-known/jwks.json`), and `_SCOPES` (optional). Bearer JWTs are
  validated against the JWKS (`iss`/`aud`/`exp`/`nbf` and any required scopes);
  the verification algorithm is taken from the JWKS key, not the token header.
  Protected-resource metadata is served at
  `/.well-known/oauth-protected-resource`; failures are rejected `401` / `403`
  with a `WWW-Authenticate` challenge. A static dev-mode bearer token
  (`ISO20022_EVIDENCE_PACK_TOKEN`) remains available as an explicit fallback.
  Starting the HTTP transport with **no** auth configured is refused rather
  than serving an unauthenticated endpoint.
- **New optional dependencies** for the HTTP transport and signing:
  `pyjwt[crypto]`, `httpx`, `starlette`, `uvicorn`, and `cryptography`. The
  default stdio transport is unaffected.

[0.0.2]: https://github.com/sebastienrousseau/iso20022-evidence-pack-mcp/releases/tag/v0.0.2

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
