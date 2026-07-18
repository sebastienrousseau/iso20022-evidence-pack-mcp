# Evidence packs

An **evidence pack** is the exportable audit artifact this server produces. It
folds a readiness result, an optional remediation result, and any simulated
bank responses into one strongly-typed, graded, **sealed** document. This page
covers the pack schema, the deterministic SHA-256 sealing model, why that makes
a pack tamper-evident, the seal-vs-signature caveat, and how the pack fits the
readiness → evidence pipeline.

## The pack schema

A pack is a JSON object with the following fields (schema version `1.0`):

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | string | The evidence-pack schema version (currently `"1.0"`). |
| `metadata` | object (string → string) | Free-form audit metadata (institution, reference, ...). |
| `readiness` | object | The readiness outcome folded into the pack (see below). |
| `remediation` | object or `null` | The remediation outcome, if one was supplied. |
| `simulated_responses` | array | Simulated bank status responses, if any were supplied. |
| `grade` | string | The letter grade (`A` / `B` / `C` / `F`) derived from the readiness score. |
| `digest` | string | The `sha256:<hex>` seal over the pack's canonical content. |

### `readiness`

| Field | Type | Meaning |
| --- | --- | --- |
| `message_type` | string | The ISO 20022 message type (e.g. `pacs.008.001.08`). |
| `is_valid` | boolean | Whether the payload was structurally valid. |
| `readiness_score` | integer (0–100) | The readiness score. |
| `structural_errors` | array of findings | Structural validation findings. |
| `profile_findings` | array of findings | Clearing-profile lint findings. |

### `remediation` (optional)

| Field | Type | Meaning |
| --- | --- | --- |
| `remediation_applied` | boolean | Whether remediation was applied. |
| `fixes_log` | array of strings | Human-readable log of the fixes applied. |
| `residual_findings` | array of findings | Findings that remain after remediation. |

### `simulated_responses` (optional)

Each entry has a `status` (e.g. `ACCP`, `RJCT`, `PDNG`) and a
`generated_response_type` (e.g. `pacs.002.001.10`).

### A finding

Findings (in `structural_errors`, `profile_findings`, `residual_findings`) are
normalised to `{ "code", "locator", "explanation", "severity" }`, where
`severity` is one of `info`, `warning`, or `error`.

### Grading

The `readiness_score` maps to a letter grade:

| Score | Grade |
| --- | --- |
| 90–100 | `A` |
| 75–89 | `B` |
| 50–74 | `C` |
| 0–49 | `F` |

## The sealing model

The `digest` is a **deterministic SHA-256 seal** over the pack's *canonical*
JSON form. It is computed as follows:

1. Serialise the pack to a JSON-compatible dict.
2. **Remove the `digest` field** (a pack cannot seal its own seal).
3. Serialise that dict to text with **sorted keys**, **tight separators**
   (`,` and `:`, no spaces), and non-ASCII preserved.
4. UTF-8 encode, take the SHA-256, and prefix the hex with `sha256:`.

Because every step is deterministic and key order is fixed, **sealing the same
content always yields the same digest**. Two packs with identical content —
regardless of how their JSON happened to be formatted or key-ordered on the
wire — seal to the identical value.

```python
import asyncio
import json

from iso20022_evidence_pack_mcp import server


async def main() -> None:
    async def call(name, args):
        result = await server.server.call_tool(name, args)
        content = result[0] if isinstance(result, tuple) else result
        return content[0].text if content else ""

    readiness = json.dumps({"message_type": "pacs.008.001.08",
                            "is_valid": True, "readiness_score": 92})
    built = json.loads(await call("build_evidence_pack",
                                  {"readiness_content": readiness}))
    pack, digest = built["pack"], built["digest"]

    # seal_pack recomputes the same digest the pack already carries.
    resealed = json.loads(await call("seal_pack",
                                     {"pack_content": json.dumps(pack)}))
    assert resealed["digest"] == digest == pack["digest"]


asyncio.run(main())
```

## Why this makes a pack tamper-evident

To check a pack, `verify_seal` recomputes the seal over the pack it is handed
(excluding the `digest` field) and compares it to an `expected_digest`:

- If nothing changed, the recomputed seal equals the expected digest →
  `verified: true`.
- If **any** sealed field changed — a score, a finding, a piece of metadata,
  the grade — the recomputed seal differs → `verified: false`.

So a verifier can detect whether a pack was altered after it was sealed, even a
single-byte change. The pack is *tamper-evident*: tampering does not go
unnoticed.

```python
    # ... continuing from above ...
    tampered = {**pack, "grade": "F"}       # change one field
    checked = json.loads(await call("verify_seal", {
        "pack_content": json.dumps(tampered),
        "expected_digest": digest,          # the original seal
    }))
    assert checked["verified"] is False     # the seal no longer matches
```

## Seal vs signature — an important caveat

!!! warning "The seal is an integrity digest, not a cryptographic signature"
    The seal proves a pack has **not changed** since it was sealed
    (tamper-evidence / integrity). It does **not** prove **who** produced the
    pack (authenticity). Anyone who can build a pack can also compute a valid
    seal for it, so the seal is a checksum, not a proof of origin.

Establishing authenticity — binding a pack to an operator identity via keys /
PKI — is explicitly a **roadmap** item and, until it ships, the operator's
responsibility. Treat a sealed pack as integrity-checked, transmit and store it
over channels you already trust, and do not represent it as a signed one. See
the threat-model note in
[`SECURITY.md`](https://github.com/sebastienrousseau/iso20022-evidence-pack-mcp/blob/main/SECURITY.md).

## The readiness → evidence pipeline

The evidence pack is the second stage of a two-stage suite pipeline:

1. **Readiness → results.** `iso20022-readiness-suite-mcp` runs
   `run_readiness_check` (score + findings), `remediate_payload` (automated
   fixes), and `simulate_bank_response` (a mocked pacs.002 outcome). Each
   returns typed JSON.
2. **Results → sealed pack.** You hand those JSON results to
   `build_evidence_pack` here (as `readiness_content`, `remediation_content`,
   and `simulation_content`). It normalises them into a strongly-typed pack,
   grades the readiness score, and seals the whole thing. `verify_seal` later
   proves the pack is unchanged; `render_markdown` turns it into a
   human-readable compliance report.

The two servers stay decoupled: the readiness suite knows nothing about
sealing, and this server knows nothing about how the findings were produced —
it only folds and certifies them. Because the seal is deterministic, a pack
built today and re-sealed next quarter is provably the same pack, or provably
not.
