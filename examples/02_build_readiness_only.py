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

"""Example: build a readiness-only evidence pack.

Remediation and simulation are optional; a pack can be sealed from a
readiness result alone. The remediation section stays absent and the
simulated-responses list stays empty.

Usage::

    python examples/02_build_readiness_only.py
"""

import json

from iso20022_evidence_pack_mcp.server import build_evidence_pack

_READINESS = {
    "message_type": "camt.053.001.08",
    "is_valid": False,
    "readiness_score": 40,
    "structural_errors": [
        {
            "code": "EP_STRUCT_1",
            "locator": "/Document",
            "explanation": "Missing statement group header.",
            "severity": "error",
        }
    ],
}


def main() -> None:
    """Build a readiness-only pack and confirm the optional blocks are off."""
    result = build_evidence_pack(readiness_content=json.dumps(_READINESS))
    pack = result["pack"]
    print(f"Grade          : {pack['grade']}")
    print(f"Message type   : {pack['readiness']['message_type']}")
    print(f"Remediation set: {pack['remediation'] is not None}")
    print(f"Simulated      : {len(pack['simulated_responses'])} response(s)")
    print(f"Seal           : {result['digest']}")


if __name__ == "__main__":
    main()
