<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# `iso20022-evidence-pack-mcp` governance

This document describes how `iso20022-evidence-pack-mcp` is run, how
decisions are made, and how to take on responsibility for it.
`iso20022-evidence-pack-mcp` is the audit and certification server of the
**ISO 20022 MCP Suite**; the suite-wide conventions (CI floor, release
pipeline, PR style) are shared across the sibling repositories. This document
covers the evidence-pack-server-specific bits.

## Mission and scope

`iso20022-evidence-pack-mcp` is the fully local, closed-world Model Context
Protocol (MCP) server that compiles a readiness result, an optional
remediation result, and any simulated bank responses into one sealed,
exportable audit evidence pack. It is the audit/certification sibling of
`iso20022-readiness-suite-mcp` (which produces those findings) and
`iso20022-bank-profile-mcp`. Changes are weighed against the same criterion as
the rest of the suite: **correctness, security, and clarity over feature
breadth**.

A change is in-scope if it adds or hardens a pack section, the deterministic
sealing model, the markdown report, or the grading, or improves the
audit-workflow shape. A change is out-of-scope if it duplicates logic that
belongs in a sibling server (readiness scoring, remediation, message
generation/parsing), reaches the network, or ships features that depend on a
particular client (e.g. Claude-specific extensions).

## Roles + decision making

| Role | Who | Can |
| :--- | :--- | :--- |
| **Maintainer** | Listed in [`MAINTAINERS.md`](MAINTAINERS.md) | Merge PRs, cut releases, triage, set direction |
| **Contributor** | Anyone with a merged PR | Propose changes, review, discuss |
| **User** | Everyone | File issues, ask questions, request features |

- Day-to-day changes land via PR with maintainer approval (conventional
  commits + signed commits + branch policy from the suite STYLEGUIDE).
- Larger changes (new tool surface, new transport, a change to the sealing
  model or the pack schema, dependency additions) require a tracking GitHub
  Issue + 72-hour comment window + maintainer agreement.
- Releases are cut against a v0.X milestone; signed tag + OIDC publish
  to PyPI with PEP 740 attestations.
- Security disclosures: 3-day ack / 7-day assessment / 30-day fix per
  [`SECURITY.md`](SECURITY.md).

## A note on the seal

The pack seal is a deterministic **content digest** (SHA-256 over the pack's
canonical JSON, the `digest` field excluded) for **tamper-evidence**. It is not
a cryptographic signature and proves integrity, not authenticity. Any change to
the sealing model, the canonical form, or the digest algorithm is a
compatibility-affecting change and follows the "larger changes" path above.

## Cross-suite consistency

All packages in the ISO 20022 MCP Suite share the same CI floor, release
pipeline, and governance documents. Cross-suite policy changes are agreed
across the sibling repositories and mirrored so the servers stay aligned.

## Becoming a maintainer

See the path in [`MAINTAINERS.md`](MAINTAINERS.md).

## Updating this document

PR with the 72-hour comment window for anything material. The lead
maintainer has final say but engages with substantive feedback before
merging.
