# Copyright (C) 2023-2026 Sebastien Rousseau.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Opt-in cloud / external-verifier tools.

Every external boundary is mocked -- AWS via ``moto`` (``mock_aws``), Vault by
monkeypatching ``hvac.Client``, and the ``slsa-verifier`` / ``cosign`` binaries
by monkeypatching ``subprocess.run`` and ``shutil.which``. Nothing here touches
a live AWS account, a live Vault, or a real verifier binary; the tests assert
request *shape*, response *parsing*, and error *handling* only.
"""

from __future__ import annotations

import base64
import importlib
import json
from typing import Any

import boto3
import hvac
import pytest
from moto import mock_aws

from iso20022_evidence_pack_mcp import cloud
from iso20022_evidence_pack_mcp import server as server_mod

# --------------------------------------------------------------------------
# Test doubles
# --------------------------------------------------------------------------


class _FakeCompletedProcess:
    """A stand-in for :class:`subprocess.CompletedProcess`."""

    def __init__(self, returncode: int, stdout: str, stderr: str) -> None:
        """Store the canned return code and output streams."""
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _fake_run(returncode: int, stdout: str = "", stderr: str = ""):
    """Build a ``subprocess.run`` replacement recording its command."""
    recorded: dict[str, Any] = {}

    def run(command: list[str], **kwargs: Any) -> _FakeCompletedProcess:
        recorded["command"] = command
        recorded["kwargs"] = kwargs
        return _FakeCompletedProcess(returncode, stdout, stderr)

    run.recorded = recorded  # type: ignore[attr-defined]
    return run


def _force_missing_extra(monkeypatch: pytest.MonkeyPatch, target: str) -> None:
    """Make the lazy import of ``target`` raise ImportError, else delegate."""
    real = importlib.import_module

    def fake(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == target:
            raise ImportError(f"No module named '{name}'")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(cloud.importlib, "import_module", fake)


class _FakeTransit:
    """A fake Vault Transit engine recording the sign_data call."""

    def __init__(self, recorder: dict[str, Any]) -> None:
        """Store a shared recorder dict."""
        self._recorder = recorder

    def sign_data(
        self, name: str, hash_input: str
    ) -> dict[str, dict[str, Any]]:
        """Record the request and return a canned Vault signature."""
        self._recorder["name"] = name
        self._recorder["hash_input"] = hash_input
        return {
            "data": {"signature": "vault:v1:ZmFrZXNpZw==", "key_version": 1}
        }


class _FakeSecrets:
    """The ``client.secrets`` namespace exposing ``transit``."""

    def __init__(self, recorder: dict[str, Any]) -> None:
        """Wire up the fake transit engine."""
        self.transit = _FakeTransit(recorder)


class _FakeVaultClient:
    """A fake ``hvac.Client`` recording its url and token."""

    def __init__(self, recorder: dict[str, Any]):
        """Return a constructor that records connection parameters."""
        self._recorder = recorder

    def __call__(self, url: str, token: str) -> _FakeVaultClient:
        """Record the url/token and expose ``.secrets``."""
        self._recorder["url"] = url
        self._recorder["token"] = token
        self.secrets = _FakeSecrets(self._recorder)
        return self


# --------------------------------------------------------------------------
# _lazy_import
# --------------------------------------------------------------------------


def test_lazy_import_returns_module() -> None:
    """A present module imports normally."""
    assert cloud._lazy_import("json", "aws") is json


def test_lazy_import_missing_raises_missing_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing module maps to ``EP_MISSING_EXTRA`` with an install hint."""
    _force_missing_extra(monkeypatch, "boto3")
    from iso20022_evidence_pack_mcp.errors import MissingExtraError

    with pytest.raises(MissingExtraError) as info:
        cloud._lazy_import("boto3", "aws")
    assert info.value.code == "EP_MISSING_EXTRA"
    assert "iso20022-evidence-pack-mcp[aws]" in info.value.explanation


# --------------------------------------------------------------------------
# Cap 41 -- sign_pack_aws_kms
# --------------------------------------------------------------------------


def test_sign_pack_aws_kms_success(full_pack_json: str) -> None:
    """A KMS-backed sign attaches a well-shaped ``aws_kms_signature``."""
    with mock_aws():
        kms = boto3.client("kms", region_name="us-east-1")
        arn = kms.create_key(KeyUsage="SIGN_VERIFY", KeySpec="ECC_NIST_P256")[
            "KeyMetadata"
        ]["Arn"]
        result = server_mod.sign_pack_aws_kms(
            evidence_pack_json=full_pack_json,
            key_arn=arn,
            aws_region="us-east-1",
        )
    assert result["error"] is None
    block = result["aws_kms_signature"]
    assert block["provider"] == "aws-kms"
    assert block["key_arn"] == arn
    assert block["region"] == "us-east-1"
    assert block["signing_algorithm"] == "ECDSA_SHA_256"
    assert block["digest"].startswith("sha256:")
    assert len(block["digest"].split(":", 1)[1]) == 64
    # The signature round-trips as base64 and is non-empty.
    assert base64.b64decode(block["signature"])
    # The signature block is attached to the returned pack, which keeps its
    # original sealed content.
    assert result["signed_pack"]["aws_kms_signature"] == block
    assert result["signed_pack"]["grade"] == "A"


def test_sign_pack_aws_kms_missing_extra(
    monkeypatch: pytest.MonkeyPatch, full_pack_json: str
) -> None:
    """Without the ``[aws]`` extra the tool returns ``EP_MISSING_EXTRA``."""
    _force_missing_extra(monkeypatch, "boto3")
    result = server_mod.sign_pack_aws_kms(
        evidence_pack_json=full_pack_json,
        key_arn="arn:aws:kms:us-east-1:0:key/abc",
        aws_region="us-east-1",
    )
    assert result["signed_pack"] is None
    assert result["error"]["code"] == "EP_MISSING_EXTRA"
    assert "iso20022-evidence-pack-mcp[aws]" in result["error"]["explanation"]


def test_sign_pack_aws_kms_bad_pack_json() -> None:
    """Unparseable pack JSON returns ``EP_INVALID_INPUT`` (no AWS call)."""
    result = server_mod.sign_pack_aws_kms(
        evidence_pack_json="{bad",
        key_arn="arn:aws:kms:us-east-1:0:key/abc",
        aws_region="us-east-1",
    )
    assert result["error"]["code"] == "EP_INVALID_INPUT"


# --------------------------------------------------------------------------
# Cap 42 -- sign_pack_vault
# --------------------------------------------------------------------------


def test_sign_pack_vault_success(
    monkeypatch: pytest.MonkeyPatch, full_pack_json: str
) -> None:
    """A Vault-backed sign POSTs the canonical bytes and attaches the sig."""
    recorder: dict[str, Any] = {}
    monkeypatch.setattr(hvac, "Client", _FakeVaultClient(recorder))
    result = server_mod.sign_pack_vault(
        evidence_pack_json=full_pack_json,
        vault_url="https://vault.example:8200",
        key_name="evidence-key",
        token="s.sometoken",
    )
    assert result["error"] is None
    # Request shape: connection params + the exact Transit key and input.
    assert recorder["url"] == "https://vault.example:8200"
    assert recorder["token"] == "s.sometoken"
    assert recorder["name"] == "evidence-key"
    from iso20022_evidence_pack_mcp import builder

    pack = builder.parse_pack(full_pack_json)
    expected_input = base64.b64encode(builder.canonical_bytes(pack)).decode(
        "ascii"
    )
    assert recorder["hash_input"] == expected_input
    # Response parsing.
    block = result["vault_signature"]
    assert block["provider"] == "vault-transit"
    assert block["key_name"] == "evidence-key"
    assert block["signature"] == "vault:v1:ZmFrZXNpZw=="
    assert block["key_version"] == 1
    assert result["signed_pack"]["vault_signature"] == block


def test_sign_pack_vault_missing_extra(
    monkeypatch: pytest.MonkeyPatch, full_pack_json: str
) -> None:
    """Without the ``[vault]`` extra the tool returns ``EP_MISSING_EXTRA``."""
    _force_missing_extra(monkeypatch, "hvac")
    result = server_mod.sign_pack_vault(
        evidence_pack_json=full_pack_json,
        vault_url="https://vault.example:8200",
        key_name="evidence-key",
        token="s.sometoken",
    )
    assert result["signed_pack"] is None
    assert result["error"]["code"] == "EP_MISSING_EXTRA"
    assert (
        "iso20022-evidence-pack-mcp[vault]" in result["error"]["explanation"]
    )


def test_sign_pack_vault_bad_pack_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unparseable pack JSON returns ``EP_INVALID_INPUT``."""
    recorder: dict[str, Any] = {}
    monkeypatch.setattr(hvac, "Client", _FakeVaultClient(recorder))
    result = server_mod.sign_pack_vault(
        evidence_pack_json="{bad",
        vault_url="https://vault.example:8200",
        key_name="evidence-key",
        token="s.sometoken",
    )
    assert result["error"]["code"] == "EP_INVALID_INPUT"


# --------------------------------------------------------------------------
# Cap 43 -- export_pack_to_s3
# --------------------------------------------------------------------------


def test_export_pack_to_s3_success(full_pack_json: str) -> None:
    """A pack uploads to S3 and the tool returns bucket/key/etag."""
    with mock_aws():
        boto3.client("s3", region_name="us-east-1").create_bucket(
            Bucket="evidence-bucket"
        )
        result = server_mod.export_pack_to_s3(
            signed_pack_json=full_pack_json,
            s3_uri="s3://evidence-bucket/packs/audit-2026.json",
        )
        # The object really landed with the JSON body we sent.
        body = (
            boto3.client("s3", region_name="us-east-1")
            .get_object(Bucket="evidence-bucket", Key="packs/audit-2026.json")[
                "Body"
            ]
            .read()
            .decode("utf-8")
        )
    assert result["error"] is None
    assert result["bucket"] == "evidence-bucket"
    assert result["key"] == "packs/audit-2026.json"
    assert result["etag"]
    assert '"' not in result["etag"]
    assert json.loads(body) == json.loads(full_pack_json)


def test_export_pack_to_s3_unsupported_scheme(full_pack_json: str) -> None:
    """A ``gs://`` scheme returns a clear unsupported-scheme error."""
    result = server_mod.export_pack_to_s3(
        signed_pack_json=full_pack_json,
        s3_uri="gs://bucket/key.json",
    )
    assert result["error"]["code"] == "EP_INVALID_INPUT"
    assert "only s3:// is implemented" in result["error"]["explanation"]
    assert result["error"]["context"]["scheme"] == "gs"


def test_export_pack_to_s3_missing_key(full_pack_json: str) -> None:
    """An ``s3://bucket`` URI with no key returns an error."""
    result = server_mod.export_pack_to_s3(
        signed_pack_json=full_pack_json,
        s3_uri="s3://bucket-only",
    )
    assert result["error"]["code"] == "EP_INVALID_INPUT"
    assert "s3://bucket/key" in result["error"]["explanation"]


def test_export_pack_to_s3_bad_json() -> None:
    """A non-JSON body returns ``EP_INVALID_INPUT`` before any AWS call."""
    result = server_mod.export_pack_to_s3(
        signed_pack_json="{bad",
        s3_uri="s3://bucket/key.json",
    )
    assert result["error"]["code"] == "EP_INVALID_INPUT"
    assert result["error"]["locator"] == "/signed_pack_json"


def test_export_pack_to_s3_missing_extra(
    monkeypatch: pytest.MonkeyPatch, full_pack_json: str
) -> None:
    """Without the ``[aws]`` extra the tool returns ``EP_MISSING_EXTRA``."""
    _force_missing_extra(monkeypatch, "boto3")
    result = server_mod.export_pack_to_s3(
        signed_pack_json=full_pack_json,
        s3_uri="s3://bucket/key.json",
    )
    assert result["bucket"] == ""
    assert result["error"]["code"] == "EP_MISSING_EXTRA"
    assert "iso20022-evidence-pack-mcp[aws]" in result["error"]["explanation"]


# --------------------------------------------------------------------------
# Cap 46 -- verify_slsa_provenance
# --------------------------------------------------------------------------


def test_verify_slsa_missing_binary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing ``slsa-verifier`` binary returns ``EP_EXTERNAL_TOOL``."""
    monkeypatch.setattr(cloud.shutil, "which", lambda _name: None)
    result = server_mod.verify_slsa_provenance(
        artifact_path="/tmp/app", provenance_path="/tmp/app.intoto.jsonl"
    )
    assert result["error"]["code"] == "EP_EXTERNAL_TOOL"
    assert "slsa-verifier is not installed" in result["error"]["explanation"]


def test_verify_slsa_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """A zero exit reports ``verified`` true and passes the right command."""
    monkeypatch.setattr(
        cloud.shutil, "which", lambda _name: "/usr/local/bin/slsa-verifier"
    )
    run = _fake_run(0, stdout="PASSED: Verified SLSA provenance\n")
    monkeypatch.setattr(cloud.subprocess, "run", run)
    result = server_mod.verify_slsa_provenance(
        artifact_path="/tmp/app", provenance_path="/tmp/app.intoto.jsonl"
    )
    assert result["error"] is None
    assert result["verified"] is True
    assert "PASSED" in result["output"]
    command = run.recorded["command"]  # type: ignore[attr-defined]
    assert command[0] == "/usr/local/bin/slsa-verifier"
    assert command[1] == "verify-artifact"
    assert "/tmp/app" in command
    assert "--provenance-path" in command
    assert "/tmp/app.intoto.jsonl" in command


def test_verify_slsa_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-zero exit reports ``verified`` false with the tool output."""
    monkeypatch.setattr(
        cloud.shutil, "which", lambda _name: "/usr/local/bin/slsa-verifier"
    )
    monkeypatch.setattr(
        cloud.subprocess,
        "run",
        _fake_run(1, stderr="FAILED: could not verify provenance\n"),
    )
    result = server_mod.verify_slsa_provenance(
        artifact_path="/tmp/app", provenance_path="/tmp/app.intoto.jsonl"
    )
    assert result["error"] is None
    assert result["verified"] is False
    assert "FAILED" in result["output"]


# --------------------------------------------------------------------------
# Cap 47 -- verify_cosign_signature
# --------------------------------------------------------------------------


def test_verify_cosign_missing_binary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing ``cosign`` binary returns ``EP_EXTERNAL_TOOL``."""
    monkeypatch.setattr(cloud.shutil, "which", lambda _name: None)
    result = server_mod.verify_cosign_signature(image_ref="ghcr.io/x/y:1")
    assert result["error"]["code"] == "EP_EXTERNAL_TOOL"
    assert "cosign is not installed" in result["error"]["explanation"]


def test_verify_cosign_keyless_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keyless verify parses cosign's JSON and passes the identity flags."""
    monkeypatch.setattr(
        cloud.shutil, "which", lambda _name: "/usr/local/bin/cosign"
    )
    payload = [{"critical": {"image": {"docker-manifest-digest": "sha256:x"}}}]
    run = _fake_run(0, stdout=json.dumps(payload))
    monkeypatch.setattr(cloud.subprocess, "run", run)
    result = server_mod.verify_cosign_signature(
        image_ref="ghcr.io/x/y:1",
        certificate_identity="https://github.com/x/y/.github/workflows/r.yml@refs/tags/v1",
        certificate_oidc_issuer="https://token.actions.githubusercontent.com",
    )
    assert result["error"] is None
    assert result["verified"] is True
    assert result["output"] == payload
    command = run.recorded["command"]  # type: ignore[attr-defined]
    assert command[:4] == [
        "/usr/local/bin/cosign",
        "verify",
        "--output",
        "json",
    ]
    assert "--certificate-identity" in command
    assert "--certificate-oidc-issuer" in command
    assert command[-1] == "ghcr.io/x/y:1"


def test_verify_cosign_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-zero exit reports ``verified`` false with cosign's stderr."""
    monkeypatch.setattr(
        cloud.shutil, "which", lambda _name: "/usr/local/bin/cosign"
    )
    run = _fake_run(1, stderr="no matching signatures\n")
    monkeypatch.setattr(cloud.subprocess, "run", run)
    result = server_mod.verify_cosign_signature(image_ref="ghcr.io/x/y:1")
    assert result["error"] is None
    assert result["verified"] is False
    assert "no matching signatures" in result["output"]
    # Without keyless flags, the command carries only the base verb + image.
    command = run.recorded["command"]  # type: ignore[attr-defined]
    assert "--certificate-identity" not in command
    assert "--certificate-oidc-issuer" not in command


def test_verify_cosign_success_non_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A zero exit with non-JSON stdout falls back to the raw string."""
    monkeypatch.setattr(
        cloud.shutil, "which", lambda _name: "/usr/local/bin/cosign"
    )
    monkeypatch.setattr(
        cloud.subprocess, "run", _fake_run(0, stdout="Verified OK")
    )
    result = server_mod.verify_cosign_signature(image_ref="ghcr.io/x/y:1")
    assert result["error"] is None
    assert result["verified"] is True
    assert result["output"] == "Verified OK"
