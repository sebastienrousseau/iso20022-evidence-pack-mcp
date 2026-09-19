<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# iso20022-evidence-pack-mcp Architecture

A map of the codebase for new contributors and maintainers. The goal is
that anyone can navigate, extend, and reason about
iso20022-evidence-pack-mcp without prior context.

## The pipeline

```
MCP client (Claude Desktop, IDE, agent, gateway)
        |  stdio (JSON-RPC), streamable HTTP, SSE,
        |  or authenticated streamable HTTP (http/transport.py)
        v
iso20022_evidence_pack_mcp/server.py   (MCPServer: tools, resources, prompt)
        |  thin typed wrappers
        v
builder / signing / cloud / report     (fold, seal, grade, sign, export, render)
        |
        v
sealed EvidencePack JSON (+ detached signature, markdown report)
```

Tools are deliberately thin: every one is a small adapter that parses
its JSON arguments into the `models.py` types, delegates to one module,
and returns a JSON-serialisable result. The inputs are the results of
the sibling servers (`iso20022-readiness-suite-mcp` produces the
readiness, remediation and simulation results); this server folds them
into one pack and never re-implements their logic.

## Module map

| Area | Module | Responsibility |
| :--- | :--- | :--- |
| **Server** | `iso20022_evidence_pack_mcp/server.py` | The MCPServer, all tool / resource / prompt registrations, the argparse `main()` |
| **Entry point** | `iso20022_evidence_pack_mcp.server:main` (console script: `iso20022-evidence-pack-mcp`) | Launches the server over stdio, over streamable HTTP / SSE with `--transport` (`_cli.py`, `_transports.py`, ADR 0001), or over authenticated streamable HTTP with `--transport http --bind` (`http/transport.py`) |
| **Suite command line** | `iso20022_evidence_pack_mcp/_cli.py`, `iso20022_evidence_pack_mcp/_transports.py` | `--host`/`--port` and the transport dispatch, copied verbatim into every server of the suite; work on mcp 1.x and 2.x |
| **Authenticated HTTP** | `iso20022_evidence_pack_mcp/http/transport.py` | Streamable HTTP that refuses to start without auth; bearer token or OAuth 2.1, `X-MCP-Tenant` forwarded into the request context |
| **OAuth** | `iso20022_evidence_pack_mcp/http/oauth.py` | OAuth 2.1 resource-server JWT validation (RFC 9728) against a JWKS; protected-resource metadata |
| **Request context** | `iso20022_evidence_pack_mcp/http/context.py` | The tool-visible tenant context set by the HTTP transport |
| **Builder** | `iso20022_evidence_pack_mcp/builder.py` | Folds readiness, remediation and simulation results into a graded pack; the deterministic SHA-256 seal and its verification |
| **Models** | `iso20022_evidence_pack_mcp/models.py` | The `EvidencePack` contract and every tool payload as pydantic models |
| **Signing** | `iso20022_evidence_pack_mcp/signing.py` | Ed25519 signing and verification of a pack's canonical bytes; the operator-custodied key from the environment |
| **Cloud** | `iso20022_evidence_pack_mcp/cloud.py` | AWS KMS and Vault Transit signing, S3 export, SLSA provenance and cosign verification; `boto3`/`hvac` imported lazily behind the `[aws]`/`[vault]` extras |
| **Report** | `iso20022_evidence_pack_mcp/report.py` | The markdown compliance report |
| **Errors** | `iso20022_evidence_pack_mcp/errors.py` | The stable error taxonomy (`EP_*` codes) returned inside tool payloads and served at `evidence://error-codes` |
| **Tracing** | `iso20022_evidence_pack_mcp/tracing.py` | Opt-in OpenTelemetry tracing behind the `[otel]` extra (`--otel-endpoint`) |
| **SDK shim** | `iso20022_evidence_pack_mcp/_mcp_compat.py` | One import surface over mcp 1.x (`FastMCP`) and 2.x (`MCPServer`) |
| **Version** | `iso20022_evidence_pack_mcp/__init__.py` | Single source of truth (`__version__`) |
| **Tests** | `tests/` | In-process regressions per module, the executed README/docs snippets, the suite conformance invariants |
| **Benchmarks** | `benches/bench_pack_lifecycle.py` | Build, seal, verify and render across finding counts; CI runs `--quick` |
| **Examples** | `examples/` | One runnable script per usage shape, executed by a test |
| **Release helpers** | `scripts/verify_versions.py`, `scripts/check_suite_consistency.py` | Version sources agree; the tree agrees with PyPI |

## Tools, resources, prompts

The current MCP surface:

- **Tools** (11) - local `build_evidence_pack`, `seal_pack`,
  `verify_seal`, `render_markdown`, `sign_pack`,
  `verify_pack_signature`; external `sign_pack_aws_kms`,
  `sign_pack_vault`, `export_pack_to_s3`, `verify_slsa_provenance`,
  `verify_cosign_signature`.
- **Resources** (2) - `evidence://schema` (the `EvidencePack` JSON
  schema) and `evidence://error-codes` (the error taxonomy).
- **Prompts** (1) - `audit_readiness_compliance`.

## Key design decisions

- **Errors as data.** Tools do not raise on bad input. An
  `EvidencePackError` or malformed JSON becomes an `{"error": ...}`
  payload with a stable code so the agent can reason about failure
  without parsing tracebacks.
- **The seal is deterministic.** SHA-256 over the pack's canonical JSON
  (sorted keys, tight separators, `digest` excluded): identical content
  seals to the identical digest and any change breaks verification.
- **Seal is integrity, signature is authenticity.** Ed25519 signs the
  same canonical bytes the seal digests; the private key is configured
  by the operator and never crosses the tool boundary.
- **Four transports, one command line.** stdio for a client that spawns
  the process; streamable HTTP and SSE from the suite's shared
  `_cli`/`_transports` pair, unauthenticated and bound to loopback by
  default; authenticated streamable HTTP in `http/transport.py` for
  shared multi-tenant deployments, which refuses to start without auth
  (ADR 0001).
- **Optional extras stay optional.** `boto3`, `hvac` and OpenTelemetry
  are imported lazily; the base install pulls in none of them and the
  external tools are annotated as such.
- **Coverage enforced at 100%** line+branch and docstring
  (`interrogate`); the suite-conformance test pins the invariants every
  repository in the suite shares.

## Extension points

- **Add a tool:** a `@server.tool(...)` function in
  `iso20022_evidence_pack_mcp/server.py` that parses its input with
  `_loads`, delegates to one module and returns a model's `model_dump()`;
  pair it with tests in `tests/test_server.py`, document it in the
  README and update the tool count in the README, `glama.json` and
  `server.json`.
- **Add a resource:** `@server.resource("evidence://...")`.
- **Add a prompt:** `@server.prompt()`.
- **Change the pack schema:** edit `models.py`; the seal must stay
  reproducible, so any change to the canonical form comes with a test
  that proves identical content still seals to an identical digest.

## Where to look first

- Runnable examples: [`examples/`](examples/)
- Decisions: [`docs/adr/`](docs/adr/index.md)
- Roadmap: [`ROADMAP.md`](ROADMAP.md)
- Release process: [`RELEASING.md`](RELEASING.md)
- The pack model and the seal: [`docs/evidence-packs.md`](docs/evidence-packs.md)
