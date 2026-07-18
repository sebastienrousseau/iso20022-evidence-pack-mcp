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

"""Ed25519 cryptographic signing of evidence packs.

The pack ``digest`` proves *integrity* (the content has not changed). A
signature proves *authenticity* (a specific key attests to that content). This
module signs the pack's canonical bytes -- the exact same serialization the
seal digests -- with an Ed25519 private key the **operator** configures at
launch, so the private key never crosses the MCP tool boundary:

* ``ISO20022_EVIDENCE_PACK_SIGNING_KEY`` -- the PEM private key inline, or
* ``ISO20022_EVIDENCE_PACK_SIGNING_KEY_FILE`` -- a path to a PEM key file.

Verification, by contrast, needs only the *public* key, which is safe to pass
as a tool argument. Key material is generated and custodied by the operator
(ideally in an HSM/KMS); this module never generates or persists private keys.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
from collections.abc import Mapping
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from iso20022_evidence_pack_mcp.errors import InvalidInputError

#: Signature algorithm identifier reported in signing responses.
ALGORITHM = "ed25519"

#: Environment variable holding the PEM Ed25519 private key inline.
SIGNING_KEY_ENV = "ISO20022_EVIDENCE_PACK_SIGNING_KEY"  # nosec B105

#: Environment variable holding a path to a PEM Ed25519 private key file.
SIGNING_KEY_FILE_ENV = "ISO20022_EVIDENCE_PACK_SIGNING_KEY_FILE"  # nosec B105


def load_signing_key(
    environ: Mapping[str, str] | None = None,
) -> Ed25519PrivateKey | None:
    """Load the operator's Ed25519 signing key from the environment.

    Reads the inline PEM key first, then the key-file path. Returns ``None``
    when neither is configured (the caller then reports ``EP_NO_SIGNING_KEY``).

    Raises:
        InvalidInputError: When the configured key cannot be read or is not a
            PEM Ed25519 private key.
    """
    env = os.environ if environ is None else environ
    pem = env.get(SIGNING_KEY_ENV, "").strip()
    if not pem:
        path = env.get(SIGNING_KEY_FILE_ENV, "").strip()
        if not path:
            return None
        try:
            pem = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise InvalidInputError(
                f"could not read signing key file: {exc.__class__.__name__}",
                locator=SIGNING_KEY_FILE_ENV,
            ) from exc
    try:
        key = serialization.load_pem_private_key(
            pem.encode("utf-8"), password=None
        )
    except (ValueError, TypeError) as exc:
        raise InvalidInputError(
            f"configured signing key is not a valid PEM private key: "
            f"{exc.__class__.__name__}",
            locator=SIGNING_KEY_ENV,
        ) from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise InvalidInputError(
            "configured signing key is not an Ed25519 key.",
            locator=SIGNING_KEY_ENV,
        )
    return key


def public_key_pem(private_key: Ed25519PrivateKey) -> str:
    """Return the PEM (SubjectPublicKeyInfo) encoding of the public key."""
    return (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )


def key_id(public_key: Ed25519PublicKey) -> str:
    """Return a short stable ``ed25519:<hex>`` fingerprint of a public key."""
    raw = public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return "ed25519:" + hashlib.sha256(raw).hexdigest()[:16]


def sign(private_key: Ed25519PrivateKey, message: bytes) -> str:
    """Sign ``message`` and return the base64-encoded Ed25519 signature."""
    return base64.b64encode(private_key.sign(message)).decode("ascii")


def key_id_from_pem(public_key_pem_text: str) -> str:
    """Return the ``ed25519:<hex>`` fingerprint of a PEM public key.

    Raises:
        InvalidInputError: When the text is not a PEM Ed25519 public key.
    """
    return key_id(_load_public_key(public_key_pem_text))


def _load_public_key(public_key_pem_text: str) -> Ed25519PublicKey:
    """Parse a PEM public key, raising :class:`InvalidInputError` on failure."""
    try:
        key = serialization.load_pem_public_key(
            public_key_pem_text.encode("utf-8")
        )
    except (ValueError, TypeError) as exc:
        raise InvalidInputError(
            f"public_key is not a valid PEM public key: "
            f"{exc.__class__.__name__}",
            locator="/public_key",
        ) from exc
    if not isinstance(key, Ed25519PublicKey):
        raise InvalidInputError(
            "public_key is not an Ed25519 public key.", locator="/public_key"
        )
    return key


def verify(
    public_key_pem_text: str, message: bytes, signature_b64: str
) -> bool:
    """Verify a base64 Ed25519 ``signature_b64`` over ``message``.

    Args:
        public_key_pem_text: The signer's PEM public key.
        message: The exact signed bytes (the pack's canonical form).
        signature_b64: The base64-encoded detached signature.

    Returns:
        ``True`` when the signature is valid, ``False`` when it does not
        verify against the key.

    Raises:
        InvalidInputError: When the public key or the signature encoding is
            malformed (as opposed to merely not matching).
    """
    public_key = _load_public_key(public_key_pem_text)
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidInputError(
            f"signature is not valid base64: {exc.__class__.__name__}",
            locator="/signature",
        ) from exc
    try:
        public_key.verify(signature, message)
    except InvalidSignature:
        return False
    return True
