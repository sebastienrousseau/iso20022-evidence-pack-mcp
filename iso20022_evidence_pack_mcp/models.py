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

"""Pydantic schemas for evidence packs and the tool request/response surface.

An :class:`EvidencePack` is the exportable audit artifact: it folds a readiness
result, an optional remediation result, and any simulated bank responses into
one sealed, self-describing document. The ``digest`` field is a SHA-256 seal
over the pack's canonical content, giving downstream auditors a tamper-evident
checksum.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from iso20022_evidence_pack_mcp.errors import ErrorDetail

#: The evidence-pack schema version embedded in every sealed pack.
SCHEMA_VERSION = "1.0"


class Finding(BaseModel):
    """A single structural or profile finding, normalized for the pack."""

    model_config = ConfigDict(frozen=True)

    code: str
    locator: str = "/"
    explanation: str = ""
    severity: Literal["info", "warning", "error"] = "error"


class ReadinessSection(BaseModel):
    """The readiness outcome folded into an evidence pack."""

    model_config = ConfigDict(frozen=True)

    message_type: str = ""
    is_valid: bool = False
    readiness_score: int = Field(default=0, ge=0, le=100)
    structural_errors: tuple[Finding, ...] = ()
    profile_findings: tuple[Finding, ...] = ()


class RemediationSection(BaseModel):
    """The remediation outcome folded into an evidence pack."""

    model_config = ConfigDict(frozen=True)

    remediation_applied: bool = False
    fixes_log: tuple[str, ...] = ()
    residual_findings: tuple[Finding, ...] = ()


class SimulatedResponse(BaseModel):
    """A simulated bank status response folded into an evidence pack."""

    model_config = ConfigDict(frozen=True)

    status: str = ""
    generated_response_type: str = ""


class EvidencePack(BaseModel):
    """The exportable, sealed audit artifact."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = SCHEMA_VERSION
    metadata: dict[str, str] = Field(default_factory=dict)
    readiness: ReadinessSection = Field(default_factory=ReadinessSection)
    remediation: RemediationSection | None = None
    simulated_responses: tuple[SimulatedResponse, ...] = ()
    grade: str = "F"
    #: SHA-256 hex seal over the pack's canonical content (digest excluded).
    digest: str = ""


class BuildRequest(BaseModel):
    """Input for :func:`build_evidence_pack`."""

    model_config = ConfigDict(extra="forbid")

    readiness_content: str = Field(
        description="A readiness result as raw JSON text."
    )
    remediation_content: str | None = Field(
        default=None,
        description="An optional remediation result as JSON text.",
    )
    simulation_content: str | None = Field(
        default=None,
        description="An optional JSON array of simulated bank responses.",
    )
    metadata: dict[str, str] = Field(
        default_factory=dict,
        description="Free-form audit metadata (institution, reference, ...).",
    )


class BuildResponse(BaseModel):
    """The assembled evidence pack, its seal, and a rendered summary."""

    model_config = ConfigDict(frozen=True)

    pack: EvidencePack | None = None
    digest: str = ""
    markdown: str = ""
    error: ErrorDetail | None = None


class SealRequest(BaseModel):
    """Input for :func:`seal_pack`."""

    model_config = ConfigDict(extra="forbid")

    pack_content: str = Field(description="An evidence pack as raw JSON text.")


class SealResponse(BaseModel):
    """A freshly computed pack seal."""

    model_config = ConfigDict(frozen=True)

    digest: str = ""
    error: ErrorDetail | None = None


class VerifyRequest(BaseModel):
    """Input for :func:`verify_seal`."""

    model_config = ConfigDict(extra="forbid")

    pack_content: str = Field(description="An evidence pack as raw JSON text.")
    expected_digest: str = Field(
        description="The seal to check the pack against."
    )


class VerifyResponse(BaseModel):
    """The result of checking a pack against an expected seal."""

    model_config = ConfigDict(frozen=True)

    verified: bool = False
    computed_digest: str = ""
    error: ErrorDetail | None = None


class RenderRequest(BaseModel):
    """Input for :func:`render_markdown`."""

    model_config = ConfigDict(extra="forbid")

    pack_content: str = Field(description="An evidence pack as raw JSON text.")


class RenderResponse(BaseModel):
    """A rendered markdown compliance summary."""

    model_config = ConfigDict(frozen=True)

    markdown: str = ""
    error: ErrorDetail | None = None


class SignRequest(BaseModel):
    """Input for :func:`sign_pack`."""

    model_config = ConfigDict(extra="forbid")

    pack_content: str = Field(description="An evidence pack as raw JSON text.")


class SignResponse(BaseModel):
    """A detached Ed25519 signature over a pack's canonical content."""

    model_config = ConfigDict(frozen=True)

    signature: str = ""
    algorithm: str = ""
    public_key: str = ""
    key_id: str = ""
    error: ErrorDetail | None = None


class VerifySignatureRequest(BaseModel):
    """Input for :func:`verify_pack_signature`."""

    model_config = ConfigDict(extra="forbid")

    pack_content: str = Field(description="An evidence pack as raw JSON text.")
    signature: str = Field(description="The base64 Ed25519 signature.")
    public_key: str = Field(description="The signer's PEM public key.")


class VerifySignatureResponse(BaseModel):
    """The result of checking a detached pack signature."""

    model_config = ConfigDict(frozen=True)

    verified: bool = False
    key_id: str = ""
    error: ErrorDetail | None = None


# --------------------------------------------------------------------------
# Opt-in cloud / external tool responses (require optional extras; each
# reaches an external system, unlike the closed-world tools above).
# --------------------------------------------------------------------------


class AwsKmsSignResponse(BaseModel):
    """A pack signed by AWS KMS, with the attached ``aws_kms_signature``."""

    model_config = ConfigDict(frozen=True)

    signed_pack: dict[str, Any] | None = None
    aws_kms_signature: dict[str, Any] | None = None
    error: ErrorDetail | None = None


class VaultSignResponse(BaseModel):
    """A pack signed by HashiCorp Vault Transit, with its signature block."""

    model_config = ConfigDict(frozen=True)

    signed_pack: dict[str, Any] | None = None
    vault_signature: dict[str, Any] | None = None
    error: ErrorDetail | None = None


class S3ExportResponse(BaseModel):
    """The location and entity tag of a pack exported to Amazon S3."""

    model_config = ConfigDict(frozen=True)

    bucket: str = ""
    key: str = ""
    etag: str = ""
    error: ErrorDetail | None = None


class SlsaVerifyResponse(BaseModel):
    """The result of verifying SLSA provenance with ``slsa-verifier``."""

    model_config = ConfigDict(frozen=True)

    verified: bool = False
    output: str = ""
    error: ErrorDetail | None = None


class CosignVerifyResponse(BaseModel):
    """The result of verifying an image signature with ``cosign``."""

    model_config = ConfigDict(frozen=True)

    verified: bool = False
    output: Any = None
    error: ErrorDetail | None = None
