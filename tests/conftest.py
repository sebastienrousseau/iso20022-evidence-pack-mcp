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

"""Shared fixtures for the iso20022-evidence-pack-mcp test suite.

Provides ready-made readiness, remediation, and simulation JSON payloads,
plus small helpers to build a sealed pack and re-serialize it to JSON so the
seal/verify/render tools can be exercised without any network or sub-server.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

#: A readiness result with structural errors and profile findings, scoring in
#: the "A" band (>= 90). ``severity`` is drawn from every supported location.
READINESS_FULL: dict[str, Any] = {
    "message_type": "pain.001.001.09",
    "is_valid": True,
    "readiness_score": 95,
    "structural_errors": [
        {
            "code": "EP_STRUCT_1",
            "locator": "/Document",
            "explanation": "Missing element.",
            "severity": "error",
        },
        "not-a-dict-finding",
    ],
    "profile_findings": [
        {
            "code": "CBPR_ADDR",
            "locator": "/Cdtr/PstlAdr",
            "explanation": "Address not fully structured.",
            "context": {"severity": "warning"},
        }
    ],
}

#: A minimal readiness result: no findings, low score (the "F" band).
READINESS_MINIMAL: dict[str, Any] = {
    "message_type": "camt.053.001.08",
    "is_valid": False,
    "readiness_score": 10,
}

#: A remediation result with a fixes log and one residual finding.
REMEDIATION_FULL: dict[str, Any] = {
    "remediation_applied": True,
    "fixes_log": ["Added Ctry", "Added TwnNm"],
    "residual_findings": [
        {
            "code": "CBPR_RESIDUAL",
            "locator": "/Cdtr",
            "explanation": "Still non-compliant.",
            "severity": "info",
        }
    ],
}

#: A JSON array of two simulated bank responses.
SIMULATION_FULL: list[dict[str, Any]] = [
    {"status": "ACCP", "generated_response_type": "pacs.002.001.10"},
    {"status": "RJCT", "generated_response_type": "pacs.002.001.10"},
]

#: Free-form audit metadata.
METADATA: dict[str, str] = {
    "institution": "Acme Bank",
    "reference": "AUDIT-2026-01",
}


def build_full_pack_json() -> str:
    """Build a fully-populated sealed pack and return it as JSON text."""
    from iso20022_evidence_pack_mcp.server import build_evidence_pack

    result = build_evidence_pack(
        readiness_content=json.dumps(READINESS_FULL),
        remediation_content=json.dumps(REMEDIATION_FULL),
        simulation_content=json.dumps(SIMULATION_FULL),
        metadata=METADATA,
    )
    return json.dumps(result["pack"])


@pytest.fixture
def full_pack_json() -> str:
    """A sealed, fully-populated evidence pack as JSON text."""
    return build_full_pack_json()
