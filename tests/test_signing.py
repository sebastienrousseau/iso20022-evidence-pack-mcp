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

"""Ed25519 signing-key loading, signing, and verification."""

from __future__ import annotations

import re

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from iso20022_evidence_pack_mcp import signing
from iso20022_evidence_pack_mcp.errors import InvalidInputError

_KEY_ID_RE = re.compile(r"^ed25519:[0-9a-f]{16}$")


def _private_pem(key: Ed25519PrivateKey) -> str:
    """Return the PKCS8 PEM encoding of an Ed25519 private key."""
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")


def _rsa_private_pem() -> str:
    """Return a PKCS8 PEM RSA private key (a non-Ed25519 key)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")


def _rsa_public_pem() -> str:
    """Return a PEM SubjectPublicKeyInfo RSA public key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )


# --------------------------------------------------------------------------
# load_signing_key
# --------------------------------------------------------------------------


def test_load_signing_key_unset_returns_none() -> None:
    """No configured key yields ``None`` (the caller reports no key)."""
    assert signing.load_signing_key(environ={}) is None


def test_load_signing_key_inline_pem() -> None:
    """An inline PEM in ``SIGNING_KEY_ENV`` loads the private key."""
    key = Ed25519PrivateKey.generate()
    loaded = signing.load_signing_key(
        environ={signing.SIGNING_KEY_ENV: _private_pem(key)}
    )
    assert isinstance(loaded, Ed25519PrivateKey)


def test_load_signing_key_from_file(tmp_path) -> None:
    """A PEM path in ``SIGNING_KEY_FILE_ENV`` is read and loaded."""
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "key.pem"
    path.write_text(_private_pem(key), encoding="utf-8")
    loaded = signing.load_signing_key(
        environ={signing.SIGNING_KEY_FILE_ENV: str(path)}
    )
    assert isinstance(loaded, Ed25519PrivateKey)


def test_load_signing_key_missing_file(tmp_path) -> None:
    """A missing key-file path raises :class:`InvalidInputError`."""
    missing = tmp_path / "nope.pem"
    with pytest.raises(InvalidInputError) as info:
        signing.load_signing_key(
            environ={signing.SIGNING_KEY_FILE_ENV: str(missing)}
        )
    assert info.value.code == "EP_INVALID_INPUT"
    assert info.value.locator == signing.SIGNING_KEY_FILE_ENV


def test_load_signing_key_garbage_value() -> None:
    """A non-PEM inline value raises :class:`InvalidInputError`."""
    with pytest.raises(InvalidInputError) as info:
        signing.load_signing_key(
            environ={signing.SIGNING_KEY_ENV: "not-a-pem-key"}
        )
    assert info.value.code == "EP_INVALID_INPUT"
    assert info.value.locator == signing.SIGNING_KEY_ENV


def test_load_signing_key_rejects_rsa() -> None:
    """A valid RSA (non-Ed25519) PEM key raises :class:`InvalidInputError`."""
    with pytest.raises(InvalidInputError) as info:
        signing.load_signing_key(
            environ={signing.SIGNING_KEY_ENV: _rsa_private_pem()}
        )
    assert "not an Ed25519 key" in info.value.explanation


def test_load_signing_key_uses_os_environ(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With ``environ=None`` the key is read from ``os.environ``."""
    key = Ed25519PrivateKey.generate()
    monkeypatch.setenv(signing.SIGNING_KEY_ENV, _private_pem(key))
    loaded = signing.load_signing_key()
    assert isinstance(loaded, Ed25519PrivateKey)


# --------------------------------------------------------------------------
# sign / verify round trip
# --------------------------------------------------------------------------


def test_sign_verify_round_trip() -> None:
    """A signature verifies against its key over the same message."""
    key = Ed25519PrivateKey.generate()
    sig = signing.sign(key, b"msg")
    assert signing.verify(signing.public_key_pem(key), b"msg", sig) is True


def test_verify_tampered_message_is_false() -> None:
    """A signature does not verify over a different message."""
    key = Ed25519PrivateKey.generate()
    sig = signing.sign(key, b"msg")
    assert (
        signing.verify(signing.public_key_pem(key), b"tampered", sig) is False
    )


def test_verify_wrong_key_is_false() -> None:
    """A signature does not verify against a different key's public PEM."""
    key = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    sig = signing.sign(key, b"msg")
    assert signing.verify(signing.public_key_pem(other), b"msg", sig) is False


def test_verify_malformed_public_key_raises() -> None:
    """A malformed public PEM raises :class:`InvalidInputError`."""
    key = Ed25519PrivateKey.generate()
    sig = signing.sign(key, b"msg")
    with pytest.raises(InvalidInputError) as info:
        signing.verify("not-a-pem", b"msg", sig)
    assert info.value.locator == "/public_key"


def test_verify_non_base64_signature_raises() -> None:
    """A non-base64 signature raises :class:`InvalidInputError`."""
    key = Ed25519PrivateKey.generate()
    with pytest.raises(InvalidInputError) as info:
        signing.verify(signing.public_key_pem(key), b"msg", "!!!not-b64!!!")
    assert info.value.locator == "/signature"


def test_verify_wrong_length_signature_is_false() -> None:
    """A valid-base64 but wrong-length signature reports ``False``."""
    key = Ed25519PrivateKey.generate()
    # "AAAA" decodes to three bytes -- not a 64-byte Ed25519 signature.
    assert signing.verify(signing.public_key_pem(key), b"msg", "AAAA") is False


# --------------------------------------------------------------------------
# key_id / key_id_from_pem / _load_public_key
# --------------------------------------------------------------------------


def test_key_id_and_from_pem_agree() -> None:
    """``key_id`` and ``key_id_from_pem`` produce the same fingerprint."""
    key = Ed25519PrivateKey.generate()
    direct = signing.key_id(key.public_key())
    from_pem = signing.key_id_from_pem(signing.public_key_pem(key))
    assert direct == from_pem
    assert _KEY_ID_RE.match(direct)


def test_load_public_key_rejects_rsa() -> None:
    """An RSA public PEM raises :class:`InvalidInputError`."""
    with pytest.raises(InvalidInputError) as info:
        signing._load_public_key(_rsa_public_pem())
    assert "not an Ed25519 public key" in info.value.explanation


# --------------------------------------------------------------------------
# Determinism
# --------------------------------------------------------------------------


def test_signing_is_deterministic() -> None:
    """Ed25519 signing the same message twice yields the same signature."""
    key = Ed25519PrivateKey.generate()
    assert signing.sign(key, b"msg") == signing.sign(key, b"msg")
