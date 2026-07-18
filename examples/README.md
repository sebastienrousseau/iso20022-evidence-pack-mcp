# iso20022-evidence-pack-mcp examples

Runnable, self-contained examples for the ISO 20022 evidence-pack MCP
server. Each script drives the public tools directly and needs no network,
sub-server, or external state. Run any of them from the repository root:

```sh
python examples/<name>.py
```

| Example | Focus |
|---------|-------|
| [`01_build_full_pack.py`](01_build_full_pack.py) | Fold readiness + remediation + simulation + metadata into one sealed pack |
| [`02_build_readiness_only.py`](02_build_readiness_only.py) | Build a pack from a readiness result alone (optional sections off) |
| [`03_seal_pack.py`](03_seal_pack.py) | Re-seal a pack and confirm the digest is deterministic |
| [`04_verify_good_seal.py`](04_verify_good_seal.py) | Verify a pack against its own (correct) seal |
| [`05_detect_tampered_pack.py`](05_detect_tampered_pack.py) | Flip a sealed field and watch verification fail |
| [`06_render_markdown.py`](06_render_markdown.py) | Render a pack as a markdown compliance report |
| [`07_grade_bands.py`](07_grade_bands.py) | Walk readiness scores through the A/B/C/F grade bands |
| [`08_roundtrip_readiness.py`](08_roundtrip_readiness.py) | Full readiness → evidence → seal → verify round trip |
| [`09_sign_and_verify.py`](09_sign_and_verify.py) | Ed25519-sign a pack, verify it, and detect a tampered field |

## Tamper-evidence

The pack seal is a SHA-256 digest over the pack's canonical content (the
`digest` field itself excluded). It is deterministic, so re-sealing the same
content reproduces the same value — and editing any sealed field changes the
recomputed digest, which is exactly what makes tampering detectable
(`05_detect_tampered_pack.py`).

## Installation

The examples import from `iso20022_evidence_pack_mcp`, so install the
package first (Python 3.10+):

```sh
pip install iso20022-evidence-pack-mcp
```

When running from a checkout without installing, put the repository root on
`PYTHONPATH`:

```sh
PYTHONPATH=. python examples/01_build_full_pack.py
```
