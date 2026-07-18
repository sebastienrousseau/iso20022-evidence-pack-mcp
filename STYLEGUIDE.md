<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# `iso20022-evidence-pack-mcp` style guide

`iso20022-evidence-pack-mcp` follows the shared conventions of the
**ISO 20022 MCP Suite**. Those conventions are the single source of truth for:

- Voice + spelling conventions (British prose, American code, no em-dashes,
  no emojis outside the standard checkmark/cross in supported-versions
  tables).
- README structure (section template + badge order).
- CHANGELOG structure (Keep-a-Changelog + suite Quality gates).
- SECURITY.md structure (including the NIST SSDF practice mapping).
- SUPPORT.md / CONTRIBUTING.md structure.
- CI floor (test + lint + security + docstring-coverage gates + release-only
  gates).
- PR style (conventional commits + signed commits + branch policy).
- Branch naming, issue filing, naming conventions.

## Local additions

`iso20022-evidence-pack-mcp` follows the suite convention that **MCP tool
names use the `verbNoun` snake_case pattern**:

```
build_evidence_pack      # not make_pack or pack()
seal_pack                # not compute_seal or pack_seal
verify_seal              # not check_seal or seal_verify
render_markdown          # not to_markdown or markdown()
```

This makes tool names read naturally as English imperatives in agent
prompts.

Three evidence-pack-specific conventions:

- **Errors are data, not tracebacks.** Every tool returns an
  `{"error": ...}` payload on failure; internal errors are captured as a
  typed `ErrorDetail` and never raised across the tool boundary.
- **Inputs are content, not paths.** Tools accept raw JSON text
  (`readiness_content`, `pack_content`, ...), never a server filesystem path.
- **The seal is deterministic.** The digest is a SHA-256 over the pack's
  canonical JSON (sorted keys, tight separators, `digest` excluded). Sealing
  identical content must always yield the identical digest; any code touching
  the canonical form must preserve that property.

## Updating

If you find divergence between this repo's practice and the shared suite
conventions, the suite wins; open a PR to align this repo (and/or fix the
deviation).
