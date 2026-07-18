# Security Policy

The iso20022-evidence-pack-mcp maintainers take the security of this project
seriously. This document explains which versions receive security updates and
how to report a vulnerability responsibly.

iso20022-evidence-pack-mcp is the fully local, closed-world Model Context
Protocol (MCP) server of the **ISO 20022 MCP Suite** — the audit and
certification sibling of iso20022-readiness-suite-mcp and
iso20022-bank-profile-mcp. It compiles a readiness result, an optional
remediation result, and any simulated bank responses into one sealed,
exportable audit evidence pack, and lets auditors re-seal, verify, and render
packs. It has no network surface, spawns no sub-servers, and parses no XML:
every tool works standalone on the JSON structures it is handed.

## Supported Versions

Security fixes are applied to the latest released minor version. While the
project is in its `0.x` series, only the most recent release line receives
security updates.

| Version | Supported          |
| ------- | ------------------ |
| 0.0.2   | :white_check_mark: |
| < 0.0.2 | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests.**

We support coordinated disclosure. To report a vulnerability, use either of the
following private channels:

- **GitHub Security Advisories** (preferred): open a private report via the
  repository's
  [Security tab → "Report a vulnerability"](https://github.com/sebastienrousseau/iso20022-evidence-pack-mcp/security/advisories/new).
- **Email**: contact the maintainer at
  [sebastian.rousseau@gmail.com](mailto:sebastian.rousseau@gmail.com).

When reporting, please include as much of the following as possible:

- A description of the vulnerability and its potential impact.
- Steps to reproduce, or a proof-of-concept.
- The affected version(s) and environment (Python version, OS).
- Any known mitigations or workarounds.

## Response Timeline

We aim to meet the following targets, on a best-effort basis:

| Stage                     | Target                          |
| ------------------------- | ------------------------------- |
| Acknowledge receipt       | Within 3 business days          |
| Initial assessment        | Within 7 business days          |
| Fix or mitigation plan    | Within 30 days of confirmation  |
| Public disclosure         | Coordinated, after a fix ships  |

We will keep you informed of progress throughout the process and will credit
reporters in the advisory unless anonymity is requested.

## Threat model note: the seal is a digest, not a signature

The pack seal is a **deterministic SHA-256 content digest** over the pack's
canonical JSON (the `digest` field excluded). It is a **tamper-evidence**
mechanism: re-sealing identical content yields the identical digest, and
changing any field breaks verification, so a verifier can detect accidental or
undetected modification of a pack.

It is **not** a cryptographic signature and does **not** prove authenticity.
Anyone who can produce a pack can also produce a valid seal for it, so the seal
does not attest *who* built the pack, only that the pack has not changed since
it was sealed. Establishing authenticity — binding a pack to an operator
identity via keys / PKI — is explicitly a **roadmap** item (see
[`ROADMAP.md`](ROADMAP.md)) and, until it ships, the operator's responsibility:
transmit and store packs over channels you already trust, and treat the seal as
an integrity checksum rather than a proof of origin. Do not represent a sealed
pack as a signed one.

## Scope

The following are in scope:

- The `iso20022-evidence-pack-mcp` MCP server as published in this repository,
  including the FastMCP tools it exposes over stdio (`build_evidence_pack`,
  `seal_pack`, `verify_seal`, `render_markdown`) and the error envelopes it
  returns.
- The deterministic sealing model: the canonical JSON form, the SHA-256 digest
  computation, and the round-trip guarantee that re-sealing identical content
  reproduces the digest while any field change breaks verification.
- Handling of agent-supplied tool arguments and the payloads returned to
  agents, including error envelopes. Inputs are accepted as raw string content
  (readiness / remediation / simulation / pack JSON), never as server
  filesystem paths.
- Input validation for the pack schema and the readiness / remediation /
  simulation shapes folded into a pack.

The following are generally out of scope:

- **Authenticity claims for a sealed pack.** The seal is an integrity digest,
  not a signature (see the threat-model note above); "the seal does not prove
  who produced the pack" is a documented property, not a vulnerability.
- Vulnerabilities in the sibling suite servers themselves
  (iso20022-readiness-suite-mcp, iso20022-bank-profile-mcp, and the
  foundational message servers); please report those against their respective
  repositories.
- Vulnerabilities in third-party dependencies (please report those upstream;
  we will track and update affected dependencies via Dependabot).
- Issues requiring a compromised host, malicious local configuration, or
  physical access.
- Denial of service caused by intentionally malformed, multi-gigabyte inputs
  beyond documented usage.

Thank you for helping keep iso20022-evidence-pack-mcp and its users safe.

## NIST SSDF practice mapping

This repository follows the practices of the **NIST Secure Software
Development Framework (SP 800-218 Rev 1.1)**. The table below maps
each SSDF practice that applies to an open-source Python project to
the concrete control(s) that implement it in this repo.

| SSDF practice | How this repo addresses it |
| :--- | :--- |
| **PO.1** Define security requirements | This `SECURITY.md`, plus the in-scope/out-of-scope sections above and the seal-is-not-a-signature threat-model note. |
| **PO.3** Implement supporting toolchains | `pyproject.toml`; `.github/workflows/ci.yml` (test + lint + security scan); `.github/workflows/scorecard.yml`. |
| **PO.4** Define and use criteria for software security checks | CI enforces tests on Python 3.10/3.11/3.12/3.13, ruff lint, black formatting, mypy `--strict`, bandit security scan, interrogate docstring coverage; Scorecard runs weekly. |
| **PO.5** Implement and maintain secure environments | PyPI Trusted Publishing (OIDC, no long-lived tokens); branch protection + signed commits on `main`; per-workflow `permissions:` minimisation. |
| **PS.1** Protect all forms of code from unauthorized access and tampering | Signed commits (SSH ed25519); branch protection; required PR reviews; `persist-credentials: false` on Scorecard checkout. |
| **PS.2** Provide a mechanism for verifying software release integrity | Signed git tags; `actions/attest-build-provenance` SLSA L3 provenance attestations; PEP 740 sigstore attestations on PyPI uploads (`pypa/gh-action-pypi-publish` with `attestations: true`). |
| **PS.3** Archive and protect each software release | GitHub Releases pin the exact `dist/*` artifacts; CycloneDX 1.6 + SPDX 2.3 SBOMs and a pip-licenses manifest attached to every release; PyPI is the immutable archive. |
| **PW.1** Design software to mitigate security risks | No network surface, no sub-processes, no XML parsing; every tool returns serialised `{"error": ...}` payloads rather than raising into client transports; the pack seal gives downstream auditors a tamper-evident integrity check. |
| **PW.4** Reuse well-secured software when feasible | Dependencies pinned via pyproject; Dependabot grouped weekly + separate security-update group; updates reviewed before merge. |
| **PW.5** Adhere to secure coding practices | `ruff`, `bandit -ll`, strict `mypy`, code review on every PR. |
| **PW.6** Configure build processes to improve security | Reproducible builds via `poetry build` with locked dependencies; CI uses SHA-pinned actions; minimum-required GH Actions permissions. |
| **PW.7** Review and analyze human-readable code | All changes go through PRs with required review; CodeQL static analysis runs on push/PR; ruff + mypy + bandit on every change. |
| **PW.8** Test executable code | pytest on Python 3.10–3.13 at 100% line + branch coverage, including the seal determinism and tamper-evidence round-trips. |
| **PW.9** Configure software with secure defaults | Stdio transport binds to the local process owner only (no network listener); tools return errors as data instead of raising into the client. |
| **RV.1** Identify and confirm vulnerabilities on an ongoing basis | Dependabot daily; `bandit` in CI; OpenSSF Scorecard weekly; GitHub Security Advisories accept reports. |
| **RV.2** Assess, prioritise, and remediate vulnerabilities | Coordinated-disclosure timeline above (3-day ack / 7-day assessment / 30-day fix); CHANGELOG + advisory at fix publication. |
| **RV.3** Analyze root causes | Each security advisory captures root cause + remediation in the GitHub Security Advisory body; lessons feed back into added regression tests. |

Cross-suite practices (organisation roles, multi-package release governance)
are shared across the ISO 20022 MCP Suite repositories.

## Accepted OpenSSF Scorecard findings

The suite runs [OpenSSF Scorecard](https://securityscorecards.dev/) weekly and
treats its results as advisory. The checks below are **accepted risks**: they
cannot be resolved by code or configuration for a single-maintainer
open-source project at v0.0.1, and are recorded here so their status is
explicit.

- **Branch-Protection** — `main` is protected: pull requests are required,
  with a required status check (`Lint & Type Check`), dismissal of stale
  reviews, linear history, and no force-pushes or deletions. Scorecard's
  highest tier also wants `enforce_admins` enabled; we deliberately leave it
  **off** so the sole maintainer can still merge approved release/security
  PRs without a second account (see [`MAINTAINERS.md`](MAINTAINERS.md)). This
  is an accepted trade-off.
- **Code-Review** — Scorecard expects each change to be approved by a
  *second* reviewer. With a single maintainer this is structurally
  impossible; changes still go through pull requests with CI gating.
  Accepted until a second maintainer joins.
- **Maintained** — a heuristic over recent commit/issue cadence that can lag
  immediately after a release lull. The project is actively maintained (see
  the commit history and the lockstep release process).
- **Fuzzing** — no continuous fuzzing harness ships in v0.0.1. The
  attacker-reachable surface is small and pure: the tools parse JSON with the
  standard library and validate it against pydantic models, returning errors
  as data. A fuzzing target may be added later. Accepted for now.
- **CII-Best-Practices** — the project is not yet registered for an OpenSSF
  Best Practices badge (a manual enrolment). Accepted until enrolled.

All **code-fixable** Scorecard checks are satisfied: Pinned-Dependencies
(SHA-pinned GitHub Actions + hash-pinned `pip` installs, resolved and
hash-pinned from PyPI in `requirements/*.txt`), Token-Permissions
(least-privilege workflow tokens), and SAST (CodeQL on push/PR). One residual
Pinned-Dependencies signal is accepted: `pip install .` (installing this
repository's own checked-out source in `mcp-inspect.yml` and the `Dockerfile`),
which has no external version or hash to pin.
