# iso20022-evidence-pack-mcp documentation

`iso20022-evidence-pack-mcp` is the **audit and certification** server of the
ISO 20022 MCP Suite. It is a fully local, closed-world MCP server: no network
surface, no sub-servers, and no XML. It takes the results of
`iso20022-readiness-suite-mcp` — a readiness score with findings, an optional
remediation result, and any simulated bank responses — and folds them into one
strongly-typed, graded, **sealed** evidence pack that can be exported, verified,
and rendered as a compliance report. Every tool returns typed,
JSON-serialisable data on every path — never a traceback.

## Start here

- [Quick start](quickstart.md) — install, configure the server in an MCP
  client, and build your first sealed evidence pack.
- [Evidence packs](evidence-packs.md) — the pack schema, the deterministic
  SHA-256 sealing model, tamper-evidence, the seal-vs-signature caveat, and the
  readiness → evidence pipeline.

## The tools

| Tool | What it does |
| --- | --- |
| `build_evidence_pack` | Fold readiness (+ optional remediation, simulation, metadata) into a graded, sealed pack. |
| `seal_pack` | Compute the deterministic SHA-256 seal for a pack. |
| `verify_seal` | Recompute a pack's seal and compare it to an expected digest. |
| `render_markdown` | Render a pack as a markdown compliance report. |

## Part of the ISO 20022 MCP Suite

This server is the audit/certification sibling of
`iso20022-readiness-suite-mcp` (which produces the readiness, remediation, and
simulation results it folds in) and `iso20022-bank-profile-mcp`. See the
[project README](https://github.com/sebastienrousseau/iso20022-evidence-pack-mcp)
for the full suite map.
