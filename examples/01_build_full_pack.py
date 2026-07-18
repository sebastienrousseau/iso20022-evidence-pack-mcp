#!/usr/bin/env python3
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

"""Example: build a fully-populated, sealed evidence pack.

Folds a readiness result, a remediation result, simulated bank responses,
and audit metadata into one sealed :class:`EvidencePack`. This is the
headline workflow of the server.

Usage::

    python examples/01_build_full_pack.py
"""

import json

from iso20022_evidence_pack_mcp.server import build_evidence_pack

_READINESS = {
    "message_type": "pain.001.001.09",
    "is_valid": True,
    "readiness_score": 95,
    "profile_findings": [
        {
            "code": "CBPR_ADDR",
            "locator": "/Cdtr/PstlAdr",
            "explanation": "Address not fully structured.",
            "context": {"severity": "warning"},
        }
    ],
}
_REMEDIATION = {
    "remediation_applied": True,
    "fixes_log": ["Added Ctry", "Added TwnNm"],
}
_SIMULATION = [
    {"status": "ACCP", "generated_response_type": "pacs.002.001.10"},
]
_METADATA = {"institution": "Acme Bank", "reference": "AUDIT-2026-01"}


def main() -> None:
    """Build a full evidence pack and print its seal and grade."""
    result = build_evidence_pack(
        readiness_content=json.dumps(_READINESS),
        remediation_content=json.dumps(_REMEDIATION),
        simulation_content=json.dumps(_SIMULATION),
        metadata=_METADATA,
    )
    pack = result["pack"]
    print(f"Grade          : {pack['grade']}")
    print(f"Readiness score: {pack['readiness']['readiness_score']}/100")
    print(f"Seal           : {result['digest']}")
    print(f"Simulated      : {len(pack['simulated_responses'])} response(s)")


if __name__ == "__main__":
    main()
