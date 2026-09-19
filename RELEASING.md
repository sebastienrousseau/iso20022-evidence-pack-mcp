<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Releasing iso20022-evidence-pack-mcp

This document defines **what merits a release** and **how to cut one**,
so versions are deliberate rather than ad-hoc.

## Versioning scheme

Versions advance one patch at a time (`0.0.X`). There is no fixed
cadence and no coupling to another package's version: this server owns
the pack schema, the seal and the signing tools, and its siblings in the
ISO 20022 MCP Suite are consumed as data, not as dependencies.

## What merits a release

Cut a new version when there is user-visible change to ship - bug fixes,
security or dependency patches, new tools / resources / prompts, or
documentation that ships in the package.

Do **not** cut a release that contains only a version-number bump with
no functional, security, or documentation change.

## Pre-flight checklist

A release is ready only when **all** of the following hold on `main`:

1. `make check` is green (lint + type check + 100% line and branch
   coverage) and `interrogate` reports 100% docstring coverage.
2. `mypy --strict`, `ruff`, `black` and `bandit` are clean.
3. Every Dependabot / CodeQL / bandit alert is resolved or has a
   documented, expiring suppression.
4. `CHANGELOG.md` has a dated section for the new version describing the
   change set (this is the single source of truth for the release).
5. The version is identical in `pyproject.toml`,
   `iso20022_evidence_pack_mcp/__init__.py`, `glama.json` and
   `server.json` (enforced by `scripts/verify_versions.py`, which the
   `versions.yml` workflow and the suite conformance test run). The
   Glama directory and the MCP registry read those two manifests; a
   release that forgets them shows an old version to every agent that
   browses for the server.
6. `poetry.lock` is current (`poetry check --lock`; the `lockfile` CI job
   fails otherwise, and so would the release).

## Cutting the release

1. Bump the version in `pyproject.toml`,
   `iso20022_evidence_pack_mcp/__init__.py`, `glama.json` and
   `server.json`, and add the `CHANGELOG.md` section, in a single PR.
2. Merge the PR to `main` once CI is green.
3. Push a signed tag:

   ```bash
   git tag -s vX.Y.Z -m "iso20022-evidence-pack-mcp vX.Y.Z" <merge-commit>
   git push origin vX.Y.Z
   ```

4. The tag triggers the `publish` job in `release.yml`: it installs the
   hash-pinned build tooling, runs `poetry build` and `twine check`,
   attaches a SLSA build-provenance attestation to the distributions,
   publishes to PyPI via OIDC trusted publishing (with PEP 740
   attestations), signs each distribution with cosign (keyless, `.sig`
   and `.pem`), and creates or updates the GitHub release with the
   distributions. The `sbom` job then attaches CycloneDX, SPDX and
   pip-licenses manifests to that release.
5. The same tag triggers `publish-mcp.yml`, which waits for PyPI to
   surface the version and publishes `server.json` to the MCP registry
   with GitHub OIDC.

## After releasing

- Confirm the version is live on
  [PyPI](https://pypi.org/project/iso20022-evidence-pack-mcp/) and the
  GitHub release is published (not draft).
- Verify a clean install: `pip install iso20022-evidence-pack-mcp==X.Y.Z`.
- The scheduled **Release Consistency** workflow
  (`scripts/check_suite_consistency.py`) compares the tree with what
  PyPI serves; a bump merged and never tagged shows up there.

## Optional CI integrations

- **PyPI trusted publisher** (`release.yml`): configured at
  <https://pypi.org/manage/account/publishing/>. The publisher claim
  set is `repo:sebastienrousseau/iso20022-evidence-pack-mcp:environment:pypi`
  with `workflow_ref` pointing at `.github/workflows/release.yml`. A
  Pending Publisher is auto-converted to a permanent Trusted Publisher
  on the first successful publish.
- **MCP registry** (`publish-mcp.yml`): authenticates with the
  workflow's GitHub OIDC identity; no secret is needed. Ownership is
  proven by the `mcp-name:` marker in the README on PyPI.
