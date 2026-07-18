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

"""Example: verify a pack against its own (correct) seal.

An auditor who holds a pack and its expected seal can confirm the pack is
intact: :func:`verify_seal` recomputes the digest and reports whether it
matches. A correct seal verifies true.

Usage::

    python examples/04_verify_good_seal.py
"""

import json

from iso20022_evidence_pack_mcp.server import (
    build_evidence_pack,
    verify_seal,
)

_READINESS = {"message_type": "pain.001.001.09", "readiness_score": 88}


def main() -> None:
    """Build a pack, then verify it against the seal it was built with."""
    built = build_evidence_pack(readiness_content=json.dumps(_READINESS))
    pack_json = json.dumps(built["pack"])
    result = verify_seal(
        pack_content=pack_json, expected_digest=built["digest"]
    )
    print(f"Expected seal : {built['digest']}")
    print(f"Computed seal : {result['computed_digest']}")
    print(f"Verified      : {result['verified']}")


if __name__ == "__main__":
    main()
