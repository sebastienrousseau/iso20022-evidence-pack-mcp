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

"""Opt-in cloud, KMS, and external-verifier integrations.

The base evidence-pack server has **no network surface by design**: every
tool in :mod:`iso20022_evidence_pack_mcp.server` marked ``_LOCAL`` is a pure,
closed-world transform. The helpers here are the exception -- each reaches an
*external* system (AWS KMS/S3, HashiCorp Vault, or a locally installed
verifier binary) and is therefore gated behind an optional extra.

To keep the base install network-free, every third-party client is imported
**lazily** via :func:`_lazy_import`; importing this module never pulls in
``boto3`` or ``hvac``. When the relevant extra is not installed the lazy
import raises :class:`~iso20022_evidence_pack_mcp.errors.MissingExtraError`,
which carries the exact ``pip install`` command that unlocks the tool.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import json
import shutil
import subprocess  # nosec B404 - used only to invoke trusted verifier CLIs
import urllib.parse
from typing import Any

from iso20022_evidence_pack_mcp import builder
from iso20022_evidence_pack_mcp.errors import (
    ExternalToolError,
    InvalidInputError,
    MissingExtraError,
)

#: KMS signing algorithm used over the pack's SHA-256 digest. ``ECDSA_SHA_256``
#: matches an ``ECC_NIST_P256`` (``SIGN_VERIFY``) KMS key; the pre-computed
#: digest is submitted with ``MessageType='DIGEST'``.
KMS_SIGNING_ALGORITHM = "ECDSA_SHA_256"

#: Distribution name used to spell out install hints in missing-extra errors.
_DIST = "iso20022-evidence-pack-mcp"


def _lazy_import(module_name: str, extra: str) -> Any:
    """Import an optional dependency, mapping ImportError to a clear error.

    Args:
        module_name: The importable module (e.g. ``"boto3"``).
        extra: The optional extra that provides it (e.g. ``"aws"``).

    Returns:
        The imported module.

    Raises:
        MissingExtraError: When the module is not installed; the message names
            the ``pip install`` command that unlocks the tool.
    """
    try:
        return importlib.import_module(module_name)
    except ImportError as exc:
        raise MissingExtraError(
            f"this tool requires the optional '{extra}' extra, which is not "
            f"installed; install it with: pip install {_DIST}[{extra}]",
            context={"extra": extra, "module": module_name},
        ) from exc


def _pack_digest(evidence_pack_json: str) -> tuple[dict[str, Any], bytes]:
    """Parse a pack and return its JSON form plus the SHA-256 of its canon.

    The digest is taken over the pack's canonical byte form (the exact bytes
    the local seal digests), so a KMS/Vault signature attests to the same
    content the ``digest`` field seals.
    """
    pack = builder.parse_pack(evidence_pack_json)
    digest = hashlib.sha256(builder.canonical_bytes(pack)).digest()
    return pack.model_dump(mode="json"), digest


def sign_pack_aws_kms(
    evidence_pack_json: str, key_arn: str, aws_region: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Sign a pack's canonical digest with AWS KMS.

    Requires the ``[aws]`` extra (``boto3``) and reaches AWS KMS over the
    network. Returns the pack with an ``aws_kms_signature`` block attached and
    the block itself.

    Raises:
        MissingExtraError: When ``boto3`` is not installed.
        InvalidInputError: When ``evidence_pack_json`` is not a valid pack.
    """
    boto3 = _lazy_import("boto3", "aws")
    signed_pack, digest = _pack_digest(evidence_pack_json)
    client = boto3.client("kms", region_name=aws_region)
    response = client.sign(
        KeyId=key_arn,
        Message=digest,
        MessageType="DIGEST",
        SigningAlgorithm=KMS_SIGNING_ALGORITHM,
    )
    block: dict[str, Any] = {
        "provider": "aws-kms",
        "key_arn": key_arn,
        "region": aws_region,
        "signing_algorithm": response.get(
            "SigningAlgorithm", KMS_SIGNING_ALGORITHM
        ),
        "digest": "sha256:" + digest.hex(),
        "signature": base64.b64encode(response["Signature"]).decode("ascii"),
        "key_id": response.get("KeyId", key_arn),
    }
    signed_pack["aws_kms_signature"] = block
    return signed_pack, block


def sign_pack_vault(
    evidence_pack_json: str, vault_url: str, key_name: str, token: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Sign a pack's canonical bytes with HashiCorp Vault Transit.

    Requires the ``[vault]`` extra (``hvac``) and reaches a Vault server over
    the network. POSTs the base64 canonical bytes to
    ``/v1/transit/sign/{key_name}`` and attaches a ``vault_signature`` block.

    Raises:
        MissingExtraError: When ``hvac`` is not installed.
        InvalidInputError: When ``evidence_pack_json`` is not a valid pack.
    """
    hvac = _lazy_import("hvac", "vault")
    pack = builder.parse_pack(evidence_pack_json)
    canonical = builder.canonical_bytes(pack)
    input_b64 = base64.b64encode(canonical).decode("ascii")
    client = hvac.Client(url=vault_url, token=token)
    response = client.secrets.transit.sign_data(
        name=key_name, hash_input=input_b64
    )
    data = response["data"]
    block: dict[str, Any] = {
        "provider": "vault-transit",
        "vault_url": vault_url,
        "key_name": key_name,
        "signature": data["signature"],
        "key_version": data.get("key_version"),
    }
    signed_pack = pack.model_dump(mode="json")
    signed_pack["vault_signature"] = block
    return signed_pack, block


def export_pack_to_s3(signed_pack_json: str, s3_uri: str) -> dict[str, str]:
    """Upload a signed pack to Amazon S3.

    Requires the ``[aws]`` extra (``boto3``) and reaches AWS S3 over the
    network. Only the ``s3://`` scheme is supported; other object-store
    schemes (``gs://``, ``az://``) raise a clear error rather than silently
    doing nothing.

    Args:
        signed_pack_json: The (signed) pack as raw JSON text; stored verbatim.
        s3_uri: A destination of the form ``s3://bucket/key``.

    Returns:
        A mapping with the ``bucket``, ``key``, and ``etag`` of the object.

    Raises:
        InvalidInputError: For a non-``s3://`` scheme, a malformed URI, or
            body that is not valid JSON.
        MissingExtraError: When ``boto3`` is not installed.
    """
    parsed = urllib.parse.urlparse(s3_uri)
    if parsed.scheme != "s3":
        raise InvalidInputError(
            f"unsupported scheme '{parsed.scheme}://'; only s3:// is "
            f"implemented.",
            locator="/s3_uri",
            context={"scheme": parsed.scheme},
        )
    bucket = parsed.netloc
    key = parsed.path.lstrip("/")
    if not bucket or not key:
        raise InvalidInputError(
            "s3_uri must be of the form s3://bucket/key.",
            locator="/s3_uri",
        )
    try:
        json.loads(signed_pack_json)
    except json.JSONDecodeError as exc:
        raise InvalidInputError(
            f"signed_pack_json is not valid JSON: {exc}",
            locator="/signed_pack_json",
        ) from exc
    boto3 = _lazy_import("boto3", "aws")
    client = boto3.client("s3")
    response = client.put_object(
        Bucket=bucket,
        Key=key,
        Body=signed_pack_json.encode("utf-8"),
        ContentType="application/json",
    )
    return {
        "bucket": bucket,
        "key": key,
        "etag": str(response.get("ETag", "")).strip('"'),
    }


def verify_slsa_provenance(
    artifact_path: str, provenance_path: str
) -> tuple[bool, str]:
    """Verify an artifact's SLSA provenance with the ``slsa-verifier`` binary.

    Reaches an external system only insofar as it shells out to a locally
    installed ``slsa-verifier`` binary (which may itself fetch metadata). No
    optional Python extra is required.

    Returns:
        ``(verified, output)`` where ``verified`` reflects a zero exit code
        and ``output`` is the combined stdout/stderr of the run.

    Raises:
        ExternalToolError: When the ``slsa-verifier`` binary is not on ``PATH``.
    """
    binary = shutil.which("slsa-verifier")
    if binary is None:
        raise ExternalToolError(
            "slsa-verifier is not installed; install it from "
            "https://github.com/slsa-framework/slsa-verifier.",
            context={"binary": "slsa-verifier"},
        )
    proc = subprocess.run(  # nosec B603 - resolved absolute path, no shell
        [
            binary,
            "verify-artifact",
            artifact_path,
            "--provenance-path",
            provenance_path,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0, output


def verify_cosign_signature(
    image_ref: str,
    certificate_identity: str | None = None,
    certificate_oidc_issuer: str | None = None,
) -> tuple[bool, Any]:
    """Verify a container image signature with the ``cosign`` binary.

    Reaches an external system only insofar as it shells out to a locally
    installed ``cosign`` binary (which contacts the registry/transparency
    log). No optional Python extra is required. Keyless verification supplies
    ``certificate_identity`` and ``certificate_oidc_issuer``.

    Returns:
        ``(verified, output)`` where ``verified`` reflects a zero exit code and
        ``output`` is cosign's parsed JSON payload (or the raw stdout string
        when it is not JSON).

    Raises:
        ExternalToolError: When the ``cosign`` binary is not on ``PATH``.
    """
    binary = shutil.which("cosign")
    if binary is None:
        raise ExternalToolError(
            "cosign is not installed; install it from "
            "https://github.com/sigstore/cosign.",
            context={"binary": "cosign"},
        )
    command = [binary, "verify", "--output", "json"]
    if certificate_identity is not None:
        command += ["--certificate-identity", certificate_identity]
    if certificate_oidc_issuer is not None:
        command += ["--certificate-oidc-issuer", certificate_oidc_issuer]
    command.append(image_ref)
    proc = subprocess.run(  # nosec B603 - resolved absolute path, no shell
        command, capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout or "")
    try:
        return True, json.loads(proc.stdout)
    except json.JSONDecodeError:
        return True, proc.stdout
