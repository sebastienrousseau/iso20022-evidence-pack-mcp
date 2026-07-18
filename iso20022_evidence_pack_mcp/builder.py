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

"""Assembly and sealing of evidence packs.

The builder folds loosely-typed inputs (a readiness result, an optional
remediation result, and any simulated responses — each accepted as parsed
JSON) into a strongly-typed :class:`EvidencePack`, then seals it with a
deterministic SHA-256 digest over its canonical JSON form. The digest is
reproducible: sealing the same content always yields the same value, which is
what makes the pack tamper-evident.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import ValidationError

from iso20022_evidence_pack_mcp.errors import InvalidInputError
from iso20022_evidence_pack_mcp.models import (
    EvidencePack,
    Finding,
    ReadinessSection,
    RemediationSection,
    SimulatedResponse,
)

_VALID_SEVERITIES = frozenset({"info", "warning", "error"})


def grade(score: int) -> str:
    """Map a 0-100 readiness score to a letter grade (A/B/C/F)."""
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 50:
        return "C"
    return "F"


def _severity(raw: dict[str, Any]) -> str:
    """Resolve a finding's severity from the top level or nested context."""
    context = raw.get("context")
    nested = context.get("severity") if isinstance(context, dict) else None
    severity = raw.get("severity") or nested or "error"
    return severity if severity in _VALID_SEVERITIES else "error"


def _finding(raw: Any) -> Finding:
    """Normalize one loosely-typed finding into a :class:`Finding`."""
    if not isinstance(raw, dict):
        return Finding(code="EP_MALFORMED_FINDING", explanation=str(raw))
    return Finding(
        code=str(raw.get("code", "UNKNOWN")),
        locator=str(raw.get("locator", "/")),
        explanation=str(raw.get("explanation", "")),
        severity=_severity(raw),
    )


def _findings(raw: Any) -> tuple[Finding, ...]:
    """Normalize a list of loosely-typed findings."""
    if not isinstance(raw, list):
        return ()
    return tuple(_finding(item) for item in raw)


def _readiness_section(data: Any) -> ReadinessSection:
    """Build the readiness section from a parsed readiness result."""
    if not isinstance(data, dict):
        raise InvalidInputError(
            "readiness_content must be a JSON object.",
            locator="/readiness_content",
        )
    raw_score = data.get("readiness_score", 0)
    score = raw_score if isinstance(raw_score, int) else 0
    return ReadinessSection(
        message_type=str(data.get("message_type", "")),
        is_valid=bool(data.get("is_valid", False)),
        readiness_score=max(0, min(100, score)),
        structural_errors=_findings(data.get("structural_errors")),
        profile_findings=_findings(data.get("profile_findings")),
    )


def _remediation_section(data: Any) -> RemediationSection:
    """Build the remediation section from a parsed remediation result."""
    if not isinstance(data, dict):
        raise InvalidInputError(
            "remediation_content must be a JSON object.",
            locator="/remediation_content",
        )
    fixes = data.get("fixes_log")
    fixes_log = (
        tuple(str(item) for item in fixes) if isinstance(fixes, list) else ()
    )
    return RemediationSection(
        remediation_applied=bool(data.get("remediation_applied", False)),
        fixes_log=fixes_log,
        residual_findings=_findings(data.get("residual_findings")),
    )


def _simulated(data: Any) -> tuple[SimulatedResponse, ...]:
    """Build the simulated-responses section from a parsed JSON array."""
    if not isinstance(data, list):
        raise InvalidInputError(
            "simulation_content must be a JSON array.",
            locator="/simulation_content",
        )
    responses: list[SimulatedResponse] = []
    for item in data:
        if not isinstance(item, dict):
            raise InvalidInputError(
                "Each simulated response must be a JSON object.",
                locator="/simulation_content",
            )
        responses.append(
            SimulatedResponse(
                status=str(item.get("status", "")),
                generated_response_type=str(
                    item.get("generated_response_type", "")
                ),
            )
        )
    return tuple(responses)


def canonical_bytes(pack: EvidencePack) -> bytes:
    """Return the pack's canonical byte form (digest field excluded)."""
    payload = pack.model_dump(mode="json")
    payload.pop("digest", None)
    text = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return text.encode("utf-8")


def compute_digest(pack: EvidencePack) -> str:
    """Return the ``sha256:<hex>`` seal over the pack's canonical content."""
    return "sha256:" + hashlib.sha256(canonical_bytes(pack)).hexdigest()


def build_pack(
    readiness: Any,
    remediation: Any,
    simulation: Any,
    metadata: dict[str, str],
) -> EvidencePack:
    """Fold parsed inputs into a graded, sealed :class:`EvidencePack`."""
    readiness_section = _readiness_section(readiness)
    remediation_section = (
        _remediation_section(remediation) if remediation is not None else None
    )
    simulated = _simulated(simulation) if simulation is not None else ()
    unsealed = EvidencePack(
        metadata=dict(metadata),
        readiness=readiness_section,
        remediation=remediation_section,
        simulated_responses=simulated,
        grade=grade(readiness_section.readiness_score),
    )
    return unsealed.model_copy(update={"digest": compute_digest(unsealed)})


def parse_pack(pack_content: str) -> EvidencePack:
    """Parse raw JSON text into an :class:`EvidencePack`.

    Raises :class:`InvalidInputError` for malformed JSON or a shape that does
    not match the evidence-pack schema.
    """
    try:
        data = json.loads(pack_content)
    except json.JSONDecodeError as exc:
        raise InvalidInputError(
            f"pack_content is not valid JSON: {exc}"
        ) from exc
    try:
        return EvidencePack.model_validate(data)
    except ValidationError as exc:
        raise InvalidInputError(
            f"pack_content does not match the evidence-pack schema: "
            f"{exc.error_count()} error(s).",
            context={"errors": exc.errors(include_url=False)},
        ) from exc
