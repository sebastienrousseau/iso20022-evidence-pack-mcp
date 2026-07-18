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

"""Example: re-seal a pack and confirm the digest is deterministic.

The seal is a SHA-256 over the pack's canonical content (the digest field
excluded). Sealing the same content always yields the same value, so a
freshly-sealed pack reproduces the digest computed at build time.

Usage::

    python examples/03_seal_pack.py
"""

import json

from iso20022_evidence_pack_mcp.server import build_evidence_pack, seal_pack

_READINESS = {"message_type": "pain.001.001.09", "readiness_score": 80}


def main() -> None:
    """Build a pack, re-seal its JSON, and show the digests agree."""
    built = build_evidence_pack(readiness_content=json.dumps(_READINESS))
    pack_json = json.dumps(built["pack"])
    resealed = seal_pack(pack_content=pack_json)
    print(f"Build-time seal: {built['digest']}")
    print(f"Re-sealed      : {resealed['digest']}")
    print(f"Deterministic  : {built['digest'] == resealed['digest']}")


if __name__ == "__main__":
    main()
