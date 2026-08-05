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

"""Model Context Protocol (MCP) server for ISO 20022 evidence packs.

This server compiles a readiness result, an optional remediation result, and
any simulated bank responses into one sealed, exportable audit artifact, and
lets auditors re-seal, verify, and render packs. The core tool surface is
fully local and closed-world (no network surface, no sub-servers). A small set
of **opt-in** cloud/KMS tools (annotated ``openWorldHint``) reach external
systems -- AWS KMS/S3, HashiCorp Vault, or a local verifier binary -- and are
gated behind optional extras (``[aws]``, ``[vault]``) with lazy imports, so the
base install stays network-free. Every tool returns typed, JSON-serializable
data and an ``{"error": ...}``-shaped payload on any failure, never a
traceback.

Launch as a console script (``iso20022-evidence-pack-mcp``) or configure it in
an MCP client. The transport is stdio (the SDK's default).
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Annotated, Any, cast

from mcp.types import ToolAnnotations
from pydantic import Field

from iso20022_evidence_pack_mcp import (
    __version__,
    builder,
    cloud,
    report,
    signing,
    tracing,
)
from iso20022_evidence_pack_mcp._mcp_compat import build_server
from iso20022_evidence_pack_mcp.errors import (
    ErrorDetail,
    EvidencePackError,
    InvalidInputError,
    NoSigningKeyError,
    SealMismatchError,
)
from iso20022_evidence_pack_mcp.models import (
    AwsKmsSignResponse,
    BuildRequest,
    BuildResponse,
    CosignVerifyResponse,
    EvidencePack,
    RenderRequest,
    RenderResponse,
    S3ExportResponse,
    SealRequest,
    SealResponse,
    SignRequest,
    SignResponse,
    SlsaVerifyResponse,
    VaultSignResponse,
    VerifyRequest,
    VerifyResponse,
    VerifySignatureRequest,
    VerifySignatureResponse,
)

server = build_server("iso20022-evidence-pack", __version__)

# Every tool is a pure, local, deterministic, closed-world transform.
_LOCAL = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)

# Opt-in tools that reach an *external* system (cloud KMS/S3, Vault). They are
# not read-only (they emit a signature or write an object) but are
# non-destructive, and open-world -- distinct from the ``_LOCAL`` annotation
# the closed-world tools carry. These require an optional extra to be
# installed; see :mod:`iso20022_evidence_pack_mcp.cloud`.
_EXTERNAL = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    openWorldHint=True,
)

# Opt-in tools that reach an external system but only *read* from it (the
# provenance/signature verifiers). Read-only, non-destructive, open-world.
_EXTERNAL_RO = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    openWorldHint=True,
)


def _as_detail(exc: Exception) -> ErrorDetail:
    """Render any exception as a serializable :class:`ErrorDetail`."""
    if isinstance(exc, EvidencePackError):
        return exc.to_detail()
    return ErrorDetail(code="EP_ERROR", explanation=f"Unexpected error: {exc}")


def _loads(content: str, locator: str) -> Any:
    """Parse raw JSON text, raising :class:`InvalidInputError` on failure."""
    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        raise InvalidInputError(
            f"{locator} is not valid JSON: {exc}", locator=locator
        ) from exc


@server.tool(title="Build an evidence pack", annotations=_LOCAL)
@tracing.traced_tool("build_evidence_pack")
def build_evidence_pack(
    readiness_content: Annotated[
        str, Field(description="A readiness result as raw JSON text.")
    ],
    remediation_content: Annotated[
        str | None,
        Field(default=None, description="Optional remediation JSON text."),
    ] = None,
    simulation_content: Annotated[
        str | None,
        Field(default=None, description="Optional simulated-responses JSON."),
    ] = None,
    metadata: Annotated[
        dict[str, str] | None,
        Field(default=None, description="Free-form audit metadata."),
    ] = None,
) -> dict[str, Any]:
    """Fold readiness, remediation, and simulations into a sealed pack.

    Args:
        readiness_content: A readiness result, as JSON text.
        remediation_content: An optional remediation result, as JSON text.
        simulation_content: An optional JSON array of simulated responses.
        metadata: Free-form audit metadata (institution, reference, ...).
    """
    request = BuildRequest(
        readiness_content=readiness_content,
        remediation_content=remediation_content,
        simulation_content=simulation_content,
        metadata=metadata or {},
    )
    try:
        readiness = _loads(request.readiness_content, "/readiness_content")
        remediation = (
            _loads(request.remediation_content, "/remediation_content")
            if request.remediation_content is not None
            else None
        )
        simulation = (
            _loads(request.simulation_content, "/simulation_content")
            if request.simulation_content is not None
            else None
        )
        pack = builder.build_pack(
            readiness, remediation, simulation, request.metadata
        )
        response = BuildResponse(
            pack=pack,
            digest=pack.digest,
            markdown=report.render_markdown(pack),
        )
    except Exception as exc:  # noqa: BLE001 - boundary: return data, not trace
        response = BuildResponse(error=_as_detail(exc))
    return response.model_dump(mode="json")


@server.tool(title="Seal an evidence pack", annotations=_LOCAL)
@tracing.traced_tool("seal_pack")
def seal_pack(
    pack_content: Annotated[
        str, Field(description="An evidence pack as raw JSON text.")
    ],
) -> dict[str, Any]:
    """Compute the deterministic SHA-256 seal for an evidence pack.

    Args:
        pack_content: The evidence pack to seal, as JSON text.
    """
    request = SealRequest(pack_content=pack_content)
    try:
        pack = builder.parse_pack(request.pack_content)
        response = SealResponse(digest=builder.compute_digest(pack))
    except Exception as exc:  # noqa: BLE001 - boundary: return data, not trace
        response = SealResponse(error=_as_detail(exc))
    return response.model_dump(mode="json")


@server.tool(title="Verify an evidence-pack seal", annotations=_LOCAL)
@tracing.traced_tool("verify_seal")
def verify_seal(
    pack_content: Annotated[
        str, Field(description="An evidence pack as raw JSON text.")
    ],
    expected_digest: Annotated[
        str, Field(description="The seal to check the pack against.")
    ],
) -> dict[str, Any]:
    """Recompute a pack's seal and compare it to an expected digest.

    Args:
        pack_content: The evidence pack to check, as JSON text.
        expected_digest: The seal the pack is expected to carry.
    """
    request = VerifyRequest(
        pack_content=pack_content, expected_digest=expected_digest
    )
    try:
        pack = builder.parse_pack(request.pack_content)
        computed = builder.compute_digest(pack)
        response = VerifyResponse(
            verified=computed == request.expected_digest,
            computed_digest=computed,
        )
    except Exception as exc:  # noqa: BLE001 - boundary: return data, not trace
        response = VerifyResponse(error=_as_detail(exc))
    return response.model_dump(mode="json")


@server.tool(title="Render an evidence pack", annotations=_LOCAL)
@tracing.traced_tool("render_markdown")
def render_markdown(
    pack_content: Annotated[
        str, Field(description="An evidence pack as raw JSON text.")
    ],
) -> dict[str, Any]:
    """Render an evidence pack as a markdown compliance report.

    Args:
        pack_content: The evidence pack to render, as JSON text.
    """
    request = RenderRequest(pack_content=pack_content)
    try:
        pack = builder.parse_pack(request.pack_content)
        response = RenderResponse(markdown=report.render_markdown(pack))
    except Exception as exc:  # noqa: BLE001 - boundary: return data, not trace
        response = RenderResponse(error=_as_detail(exc))
    return response.model_dump(mode="json")


@server.tool(title="Sign an evidence pack", annotations=_LOCAL)
@tracing.traced_tool("sign_pack")
def sign_pack(
    pack_content: Annotated[
        str, Field(description="An evidence pack as raw JSON text.")
    ],
) -> dict[str, Any]:
    """Sign a pack's canonical content with the server's Ed25519 key.

    The private key is configured by the operator via the environment (see
    :mod:`iso20022_evidence_pack_mcp.signing`); it never crosses the tool
    boundary. Returns the detached signature, the public key, and a key id;
    fails with ``EP_NO_SIGNING_KEY`` when no key is configured.

    Args:
        pack_content: The evidence pack to sign, as JSON text.
    """
    request = SignRequest(pack_content=pack_content)
    try:
        pack = builder.parse_pack(request.pack_content)
        private_key = signing.load_signing_key()
        if private_key is None:
            raise NoSigningKeyError(
                "No Ed25519 signing key is configured; set "
                f"{signing.SIGNING_KEY_ENV} or {signing.SIGNING_KEY_FILE_ENV}."
            )
        message = builder.canonical_bytes(pack)
        response = SignResponse(
            signature=signing.sign(private_key, message),
            algorithm=signing.ALGORITHM,
            public_key=signing.public_key_pem(private_key),
            key_id=signing.key_id(private_key.public_key()),
        )
    except Exception as exc:  # noqa: BLE001 - boundary: return data, not trace
        response = SignResponse(error=_as_detail(exc))
    return response.model_dump(mode="json")


@server.tool(title="Verify an evidence-pack signature", annotations=_LOCAL)
@tracing.traced_tool("verify_pack_signature")
def verify_pack_signature(
    pack_content: Annotated[
        str, Field(description="An evidence pack as raw JSON text.")
    ],
    signature: Annotated[
        str, Field(description="The base64 Ed25519 signature to check.")
    ],
    public_key: Annotated[
        str, Field(description="The signer's PEM public key.")
    ],
) -> dict[str, Any]:
    """Verify a detached Ed25519 signature over a pack's canonical content.

    Args:
        pack_content: The evidence pack to check, as JSON text.
        signature: The base64-encoded detached signature.
        public_key: The signer's PEM public key.
    """
    request = VerifySignatureRequest(
        pack_content=pack_content,
        signature=signature,
        public_key=public_key,
    )
    try:
        pack = builder.parse_pack(request.pack_content)
        message = builder.canonical_bytes(pack)
        ok = signing.verify(request.public_key, message, request.signature)
        response = VerifySignatureResponse(
            verified=ok,
            key_id=signing.key_id_from_pem(request.public_key),
        )
    except Exception as exc:  # noqa: BLE001 - boundary: return data, not trace
        response = VerifySignatureResponse(error=_as_detail(exc))
    return response.model_dump(mode="json")


# --------------------------------------------------------------------------
# Opt-in cloud / external-verifier tools (require an optional extra; each
# reaches an external system, unlike every tool above). See
# :mod:`iso20022_evidence_pack_mcp.cloud`.
# --------------------------------------------------------------------------


@server.tool(title="Sign a pack with AWS KMS", annotations=_EXTERNAL)
@tracing.traced_tool("sign_pack_aws_kms")
def sign_pack_aws_kms(
    evidence_pack_json: Annotated[
        str, Field(description="An evidence pack as raw JSON text.")
    ],
    key_arn: Annotated[
        str, Field(description="The ARN of the KMS SIGN_VERIFY key.")
    ],
    aws_region: Annotated[
        str, Field(default="us-east-1", description="The AWS region.")
    ] = "us-east-1",
) -> dict[str, Any]:
    """Sign a pack's SHA-256 canonical digest with AWS KMS.

    **Requires the ``[aws]`` extra** (``pip install
    iso20022-evidence-pack-mcp[aws]``) and **reaches AWS KMS over the
    network** -- unlike the closed-world tools, this one has a network
    surface. The private key never leaves KMS; the tool submits only the
    pack's digest. Returns the pack with an ``aws_kms_signature`` block
    attached.

    Args:
        evidence_pack_json: The evidence pack to sign, as JSON text.
        key_arn: The ARN of the KMS ``SIGN_VERIFY`` key.
        aws_region: The AWS region hosting the key.
    """
    try:
        signed_pack, block = cloud.sign_pack_aws_kms(
            evidence_pack_json, key_arn, aws_region
        )
        response = AwsKmsSignResponse(
            signed_pack=signed_pack, aws_kms_signature=block
        )
    except Exception as exc:  # noqa: BLE001 - boundary: return data, not trace
        response = AwsKmsSignResponse(error=_as_detail(exc))
    return response.model_dump(mode="json")


@server.tool(title="Sign a pack with Vault Transit", annotations=_EXTERNAL)
@tracing.traced_tool("sign_pack_vault")
def sign_pack_vault(
    evidence_pack_json: Annotated[
        str, Field(description="An evidence pack as raw JSON text.")
    ],
    vault_url: Annotated[
        str, Field(description="The base URL of the Vault server.")
    ],
    key_name: Annotated[
        str, Field(description="The Transit key name to sign with.")
    ],
    token: Annotated[str, Field(description="The Vault access token.")],
) -> dict[str, Any]:
    """Sign a pack's canonical bytes with HashiCorp Vault Transit.

    **Requires the ``[vault]`` extra** (``pip install
    iso20022-evidence-pack-mcp[vault]``) and **reaches a Vault server over the
    network** -- unlike the closed-world tools, this one has a network
    surface. POSTs to ``/v1/transit/sign/{key_name}`` and returns the pack
    with a ``vault_signature`` block attached.

    Args:
        evidence_pack_json: The evidence pack to sign, as JSON text.
        vault_url: The base URL of the Vault server.
        key_name: The Transit key to sign with.
        token: The Vault access token.
    """
    try:
        signed_pack, block = cloud.sign_pack_vault(
            evidence_pack_json, vault_url, key_name, token
        )
        response = VaultSignResponse(
            signed_pack=signed_pack, vault_signature=block
        )
    except Exception as exc:  # noqa: BLE001 - boundary: return data, not trace
        response = VaultSignResponse(error=_as_detail(exc))
    return response.model_dump(mode="json")


@server.tool(title="Export a pack to Amazon S3", annotations=_EXTERNAL)
@tracing.traced_tool("export_pack_to_s3")
def export_pack_to_s3(
    signed_pack_json: Annotated[
        str, Field(description="A signed evidence pack as raw JSON text.")
    ],
    s3_uri: Annotated[
        str, Field(description="Destination of the form s3://bucket/key.")
    ],
) -> dict[str, Any]:
    """Upload a signed evidence pack to Amazon S3.

    **Requires the ``[aws]`` extra** (``pip install
    iso20022-evidence-pack-mcp[aws]``) and **reaches AWS S3 over the
    network** -- unlike the closed-world tools, this one has a network
    surface. Only the ``s3://`` scheme is supported; ``gs://`` / ``az://``
    return a clear error. Returns the object's ``bucket``, ``key``, and
    ``etag``.

    Args:
        signed_pack_json: The signed pack to upload, as JSON text.
        s3_uri: The destination, of the form ``s3://bucket/key``.
    """
    try:
        location = cloud.export_pack_to_s3(signed_pack_json, s3_uri)
        response = S3ExportResponse(
            bucket=location["bucket"],
            key=location["key"],
            etag=location["etag"],
        )
    except Exception as exc:  # noqa: BLE001 - boundary: return data, not trace
        response = S3ExportResponse(error=_as_detail(exc))
    return response.model_dump(mode="json")


@server.tool(title="Verify SLSA provenance", annotations=_EXTERNAL_RO)
@tracing.traced_tool("verify_slsa_provenance")
def verify_slsa_provenance(
    artifact_path: Annotated[
        str, Field(description="Path to the artifact to verify.")
    ],
    provenance_path: Annotated[
        str, Field(description="Path to the SLSA provenance attestation.")
    ],
) -> dict[str, Any]:
    """Verify an artifact's SLSA provenance with ``slsa-verifier``.

    **Reaches an external system**: shells out to a locally installed
    ``slsa-verifier`` binary (which may fetch metadata). No optional Python
    extra is required, but the binary must be on ``PATH`` -- otherwise the
    tool returns an ``EP_EXTERNAL_TOOL`` error.

    Args:
        artifact_path: Path to the artifact whose provenance is checked.
        provenance_path: Path to the SLSA provenance attestation.
    """
    try:
        verified, output = cloud.verify_slsa_provenance(
            artifact_path, provenance_path
        )
        response = SlsaVerifyResponse(verified=verified, output=output)
    except Exception as exc:  # noqa: BLE001 - boundary: return data, not trace
        response = SlsaVerifyResponse(error=_as_detail(exc))
    return response.model_dump(mode="json")


@server.tool(title="Verify a cosign signature", annotations=_EXTERNAL_RO)
@tracing.traced_tool("verify_cosign_signature")
def verify_cosign_signature(
    image_ref: Annotated[
        str, Field(description="The container image reference to verify.")
    ],
    certificate_identity: Annotated[
        str | None,
        Field(default=None, description="Keyless certificate identity."),
    ] = None,
    certificate_oidc_issuer: Annotated[
        str | None,
        Field(default=None, description="Keyless OIDC issuer URL."),
    ] = None,
) -> dict[str, Any]:
    """Verify a container image signature with ``cosign``.

    **Reaches an external system**: shells out to a locally installed
    ``cosign`` binary (which contacts the registry and transparency log). No
    optional Python extra is required, but the binary must be on ``PATH`` --
    otherwise the tool returns an ``EP_EXTERNAL_TOOL`` error. For keyless
    verification, supply ``certificate_identity`` and
    ``certificate_oidc_issuer``.

    Args:
        image_ref: The container image reference to verify.
        certificate_identity: The keyless certificate identity (optional).
        certificate_oidc_issuer: The keyless OIDC issuer URL (optional).
    """
    try:
        verified, output = cloud.verify_cosign_signature(
            image_ref,
            certificate_identity=certificate_identity,
            certificate_oidc_issuer=certificate_oidc_issuer,
        )
        response = CosignVerifyResponse(verified=verified, output=output)
    except Exception as exc:  # noqa: BLE001 - boundary: return data, not trace
        response = CosignVerifyResponse(error=_as_detail(exc))
    return response.model_dump(mode="json")


# Prompts
# --------------------------------------------------------------------------


@server.prompt(
    title="Audit an evidence pack for readiness and compliance",
)
def audit_readiness_compliance(
    evidence_pack_id: Annotated[
        str,
        Field(
            default="",
            description=(
                "Optional identifier or reference of the pack under audit; "
                "leave empty to assemble a pack from raw inputs first."
            ),
        ),
    ] = "",
) -> str:
    """Guide an analyst through a readiness/compliance audit of a pack.

    The guidance teaches the full evidence-pack workflow (build, seal or sign,
    verify, then render) and asks for a prioritized remediation checklist.

    Args:
        evidence_pack_id: An optional pack identifier to anchor the audit;
            when omitted, the guidance covers assembling a pack from scratch.
    """
    if evidence_pack_id:
        subject = f"the evidence pack referenced as `{evidence_pack_id}`"
        obtain = (
            f"Locate {subject}. If you hold its readiness (and any "
            "remediation or simulation) JSON, rebuild it with "
            "`build_evidence_pack` so the analysis works from a freshly "
            "sealed artifact."
        )
    else:
        subject = "an ISO 20022 readiness evidence pack"
        obtain = (
            "No pack identifier was supplied, so assemble one first: call "
            "`build_evidence_pack` with the readiness result (and any "
            "remediation result and simulated bank responses) as JSON text."
        )
    return (
        f"You are auditing {subject} for ISO 20022 readiness and "
        "compliance. Produce a prioritized remediation checklist backed by "
        "the pack's own tamper-evident evidence.\n\n"
        "Follow this workflow end to end:\n"
        f"1. Obtain the pack. {obtain}\n"
        "2. Establish integrity before trusting any content. Recompute the "
        "seal with `seal_pack` and confirm it against the pack's `digest` "
        "using `verify_seal`. When the pack carries a detached signature, "
        "also sign or re-check it with `sign_pack` and "
        "`verify_pack_signature`; treat any mismatch (an `EP_SEAL_MISMATCH` "
        "or a failed signature) as a blocking finding and stop.\n"
        "3. Read the human-readable report. Call `render_markdown` and use it "
        "to review the readiness grade (A >= 90, B >= 75, C >= 50, else F), "
        "the structural errors, and the profile findings.\n"
        "4. Assess the gaps. Weigh each structural error and profile finding "
        "by severity (error > warning > info), then check whether the "
        "remediation section already resolved it or left it as a residual "
        "finding.\n\n"
        "Deliver a remediation checklist ordered by severity. For each item "
        "give the finding code, its locator, why it blocks compliance, and "
        "the concrete fix. Close with the readiness grade and an overall "
        "verdict on whether the pack is audit-ready."
    )


# --------------------------------------------------------------------------
# Resources
# --------------------------------------------------------------------------

#: The internal error taxonomy exposed by ``evidence://error-codes``. Each
#: class contributes its own stable ``code`` and docstring; nothing here is
#: hand-written, so the resource always mirrors :mod:`errors`.
_ERROR_CLASSES: tuple[type[EvidencePackError], ...] = (
    EvidencePackError,
    InvalidInputError,
    SealMismatchError,
    NoSigningKeyError,
)


@server.resource(
    "evidence://schema",
    title="Evidence-pack JSON schema",
    description="The EvidencePack Pydantic model as a JSON schema.",
    mime_type="application/json",
)
def evidence_pack_schema() -> str:
    """Return the :class:`EvidencePack` contract as a JSON schema.

    Agents can read this to learn the exact shape of a sealed pack (its
    sections, the grade, and the ``digest`` seal) before building or auditing
    one.
    """
    return json.dumps(EvidencePack.model_json_schema(), indent=2)


@server.resource(
    "evidence://error-codes",
    title="Evidence-pack error taxonomy",
    description="The stable error codes returned inside tool payloads.",
    mime_type="application/json",
)
def error_codes() -> str:
    """Return the stable error taxonomy tools may surface as ``ErrorDetail``.

    Every entry is derived from an :class:`EvidencePackError` subclass, so the
    codes and explanations match exactly what the tools can return.
    """
    taxonomy = [
        {
            "code": cls.code,
            "name": cls.__name__,
            "explanation": cast(str, cls.__doc__).strip(),
        }
        for cls in _ERROR_CLASSES
    ]
    return json.dumps(taxonomy, indent=2)


def main(argv: list[str] | None = None) -> None:
    """Run the MCP server over stdio (default) or streamable HTTP.

    ``--transport=http`` serves the authenticated streamable-HTTP transport
    (OAuth 2.1 resource server, or a static dev-mode bearer token); see
    :mod:`iso20022_evidence_pack_mcp.http.transport`.

    ``--otel-endpoint`` (or ``OTEL_EXPORTER_OTLP_ENDPOINT``) opts into
    OpenTelemetry tracing of tool calls; it requires the ``[otel]`` extra and
    is a graceful no-op when that extra is absent (see
    :mod:`iso20022_evidence_pack_mcp.tracing`).
    """
    parser = argparse.ArgumentParser(
        prog="iso20022-evidence-pack-mcp",
        description="ISO 20022 evidence-pack MCP server.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"iso20022-evidence-pack-mcp {__version__}",
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "http"),
        default="stdio",
        help="Transport to serve (default: stdio).",
    )
    parser.add_argument(
        "--bind",
        default=None,
        metavar="HOST:PORT",
        help="Address for --transport=http (default: 127.0.0.1:8080).",
    )
    parser.add_argument(
        "--otel-endpoint",
        default=None,
        metavar="URL",
        help=(
            "Enable OpenTelemetry tracing and export spans to this OTLP/HTTP "
            "endpoint (requires the [otel] extra; a no-op if absent). Also "
            "honours the OTEL_EXPORTER_OTLP_ENDPOINT environment variable."
        ),
    )
    args = parser.parse_args(argv)
    if args.otel_endpoint or os.environ.get(tracing.OTEL_ENDPOINT_ENV):
        tracing.init_tracing(endpoint=args.otel_endpoint)
    if args.transport == "http":
        from iso20022_evidence_pack_mcp.http import transport

        transport.run_http(server, args.bind or transport.DEFAULT_BIND)
    else:
        server.run()


if __name__ == "__main__":  # pragma: no cover
    main()
