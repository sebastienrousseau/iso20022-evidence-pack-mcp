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

"""Example: full readiness -> evidence -> seal -> verify round trip.

Chains the whole audit workflow: a readiness result is folded into a
sealed pack, the pack is exported as JSON, then re-verified against its
seal — proving the artifact survives serialization intact.

Usage::

    python examples/08_roundtrip_readiness.py
"""

import json

from iso20022_evidence_pack_mcp.server import (
    build_evidence_pack,
    verify_seal,
)

_READINESS = {
    "message_type": "pain.001.001.09",
    "is_valid": True,
    "readiness_score": 91,
}


def main() -> None:
    """Build, export, and re-verify a pack end to end."""
    built = build_evidence_pack(readiness_content=json.dumps(_READINESS))
    exported = json.dumps(built["pack"])  # what an auditor would archive

    reloaded = json.loads(exported)
    result = verify_seal(
        pack_content=exported, expected_digest=reloaded["digest"]
    )
    print(f"Grade    : {reloaded['grade']}")
    print(f"Seal     : {reloaded['digest']}")
    print(f"Round-trip verified: {result['verified']}")


if __name__ == "__main__":
    main()
