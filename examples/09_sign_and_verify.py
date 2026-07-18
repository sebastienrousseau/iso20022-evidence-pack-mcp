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

"""Example: Ed25519 signing and verification of an evidence pack.

The seal (SHA-256 digest) proves integrity; a signature proves authenticity.
``sign_pack`` signs the pack's canonical bytes with an operator-configured
key (via the ``ISO20022_EVIDENCE_PACK_SIGNING_KEY`` env var — the private key
never crosses the tool boundary) and ``verify_pack_signature`` checks it
against a public key. This example generates an ephemeral key, signs a pack,
verifies it, and shows tamper detection. Fully local.

Usage::

    python examples/09_sign_and_verify.py
"""

import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from iso20022_evidence_pack_mcp import server

_READINESS = json.dumps(
    {
        "message_type": "pacs.008.001.08",
        "is_valid": True,
        "readiness_score": 95,
    }
)


def main() -> None:
    """Build a pack, sign it, verify it, then detect tampering."""
    pack = server.build_evidence_pack(_READINESS)["pack"]
    pack_json = json.dumps(pack)

    # No key configured -> signing is refused.
    print(
        f"sign_pack (no key) -> {server.sign_pack(pack_json)['error']['code']}"
    )

    # Configure an ephemeral operator key (an HSM/KMS in production).
    key = Ed25519PrivateKey.generate()
    os.environ["ISO20022_EVIDENCE_PACK_SIGNING_KEY"] = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    try:
        signed = server.sign_pack(pack_json)
    finally:
        del os.environ["ISO20022_EVIDENCE_PACK_SIGNING_KEY"]
    print(f"sign_pack -> {signed['algorithm']} key_id={signed['key_id']}")

    good = server.verify_pack_signature(
        pack_json, signed["signature"], signed["public_key"]
    )
    print(f"verify (untampered) -> verified={good['verified']}")

    tampered = dict(pack)
    tampered["grade"] = "F"  # the untampered pack graded A (score 95)
    bad = server.verify_pack_signature(
        json.dumps(tampered), signed["signature"], signed["public_key"]
    )
    print(f"verify (grade tampered A->F) -> verified={bad['verified']}")


if __name__ == "__main__":
    main()
