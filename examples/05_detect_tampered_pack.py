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

"""Example: detect a tampered pack.

The seal is tamper-evident. If anyone edits a sealed field — here the
grade is flipped — the recomputed digest no longer matches the original
seal, and :func:`verify_seal` reports the pack as unverified.

Usage::

    python examples/05_detect_tampered_pack.py
"""

import json

from iso20022_evidence_pack_mcp.server import (
    build_evidence_pack,
    verify_seal,
)

_READINESS = {"message_type": "pain.001.001.09", "readiness_score": 95}


def main() -> None:
    """Tamper with a sealed field and show verification fails."""
    built = build_evidence_pack(readiness_content=json.dumps(_READINESS))
    original_seal = built["digest"]

    pack = built["pack"]
    print(f"Original grade : {pack['grade']} (seal {original_seal})")
    pack["grade"] = "F"  # forge a passing grade into a failing one
    tampered_json = json.dumps(pack)

    result = verify_seal(
        pack_content=tampered_json, expected_digest=original_seal
    )
    print(f"Tampered grade : {pack['grade']}")
    print(f"Recomputed seal: {result['computed_digest']}")
    print(f"Verified       : {result['verified']}")


if __name__ == "__main__":
    main()
