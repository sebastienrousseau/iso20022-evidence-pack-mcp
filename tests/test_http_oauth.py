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

"""OAuth 2.1 resource-server auth: JWKS, JWT validation, ASGI middleware."""

from __future__ import annotations

import time
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from iso20022_evidence_pack_mcp.http import context, oauth

ISSUER = "https://auth.example.com"
AUDIENCE = "https://mcp.example.com/mcp"


# --------------------------------------------------------------------------
# Key + token helpers
# --------------------------------------------------------------------------


def _rsa_key() -> rsa.RSAPrivateKey:
    """Generate an RSA private key for signing test JWTs."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _private_pem(key: rsa.RSAPrivateKey) -> bytes:
    """Return the PKCS8 PEM encoding of an RSA private key."""
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _jwk_entry(key: rsa.RSAPrivateKey, kid: str = "k1") -> dict[str, Any]:
    """Build a JWKS entry (public key) for ``key``."""
    entry = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    entry["kid"] = kid
    entry["use"] = "sig"
    return entry


def _cache_with(key: rsa.RSAPrivateKey, kid: str = "k1") -> oauth.JWKSCache:
    """Build a JWKSCache pre-seeded with ``key`` (no network)."""
    cache = oauth.JWKSCache(f"{ISSUER}/.well-known/jwks.json")
    cache._keys = {kid: jwt.PyJWK(_jwk_entry(key, kid))}
    cache._fetched_at = float("inf")
    return cache


def _encode(key: rsa.RSAPrivateKey, claims: dict[str, Any]) -> str:
    """Sign a JWT with ``key`` and the ``k1`` key id."""
    return jwt.encode(
        claims, _private_pem(key), algorithm="RS256", headers={"kid": "k1"}
    )


def _claims(**overrides: Any) -> dict[str, Any]:
    """Build a valid claim set, overridable per test."""
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now + 3600,
        "sub": "user-1",
        "scope": "evidence-pack:read",
    }
    claims.update(overrides)
    return claims


def _config(required_scopes: tuple[str, ...] = ()) -> oauth.OAuthConfig:
    """Build an :class:`OAuthConfig` for the test issuer/audience."""
    return oauth.OAuthConfig(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_url=f"{ISSUER}/.well-known/jwks.json",
        required_scopes=required_scopes,
    )


# --------------------------------------------------------------------------
# OAuthConfig.from_env
# --------------------------------------------------------------------------


def test_from_env_empty_returns_none() -> None:
    """No OAuth variables set yields ``None``."""
    assert oauth.OAuthConfig.from_env(environ={}) is None


def test_from_env_partial_exits() -> None:
    """A partial config (issuer only) exits loudly."""
    with pytest.raises(SystemExit):
        oauth.OAuthConfig.from_env(environ={oauth.OAUTH_ISSUER_ENV: ISSUER})


def test_from_env_full_defaults_jwks() -> None:
    """A full config derives the default JWKS URL from the issuer."""
    config = oauth.OAuthConfig.from_env(
        environ={
            oauth.OAUTH_ISSUER_ENV: ISSUER + "/",
            oauth.OAUTH_AUDIENCE_ENV: AUDIENCE,
        }
    )
    assert config is not None
    assert config.jwks_url == ISSUER + "/.well-known/jwks.json"
    assert config.required_scopes == ()


def test_from_env_explicit_jwks_and_scopes() -> None:
    """Explicit JWKS URL and scopes are carried through."""
    config = oauth.OAuthConfig.from_env(
        environ={
            oauth.OAUTH_ISSUER_ENV: ISSUER,
            oauth.OAUTH_AUDIENCE_ENV: AUDIENCE,
            oauth.OAUTH_JWKS_URL_ENV: "https://keys.example.com/jwks",
            oauth.OAUTH_SCOPES_ENV: "read write",
        }
    )
    assert config is not None
    assert config.jwks_url == "https://keys.example.com/jwks"
    assert config.required_scopes == ("read", "write")


# --------------------------------------------------------------------------
# resource_metadata_url / protected_resource_metadata
# --------------------------------------------------------------------------


def test_resource_metadata_url_with_path() -> None:
    """A resource URI with a path inserts the well-known segment."""
    url = oauth.resource_metadata_url("https://mcp.example.com/mcp")
    assert url == (
        "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
    )


def test_resource_metadata_url_bare_origin() -> None:
    """A bare-origin resource URI has no trailing resource path."""
    url = oauth.resource_metadata_url("https://mcp.example.com")
    assert url == (
        "https://mcp.example.com/.well-known/oauth-protected-resource"
    )


def test_protected_resource_metadata_without_scopes() -> None:
    """Metadata omits ``scopes_supported`` when no scopes are required."""
    metadata = oauth.protected_resource_metadata(_config())
    assert metadata["resource"] == AUDIENCE
    assert metadata["authorization_servers"] == [ISSUER]
    assert "scopes_supported" not in metadata


def test_protected_resource_metadata_with_scopes() -> None:
    """Metadata lists ``scopes_supported`` when scopes are required."""
    metadata = oauth.protected_resource_metadata(_config(("read",)))
    assert metadata["scopes_supported"] == ["read"]


# --------------------------------------------------------------------------
# JWTVerifier.verify reason codes
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_valid_token() -> None:
    """A valid token yields an ``AccessToken`` with its scopes."""
    key = _rsa_key()
    verifier = oauth.JWTVerifier(_config(), jwks=_cache_with(key))
    access = await verifier.verify(_encode(key, _claims()))
    assert access.scopes == ["evidence-pack:read"]
    assert access.client_id == "user-1"


@pytest.mark.asyncio
async def test_verify_expired() -> None:
    """An expired token fails ``token_expired``."""
    key = _rsa_key()
    verifier = oauth.JWTVerifier(_config(), jwks=_cache_with(key))
    token = _encode(key, _claims(exp=int(time.time()) - 3600))
    with pytest.raises(oauth.TokenValidationError) as info:
        await verifier.verify(token)
    assert info.value.reason == "token_expired"


@pytest.mark.asyncio
async def test_verify_not_yet_valid() -> None:
    """A future ``nbf`` fails ``token_not_yet_valid``."""
    key = _rsa_key()
    verifier = oauth.JWTVerifier(_config(), jwks=_cache_with(key))
    token = _encode(key, _claims(nbf=int(time.time()) + 3600))
    with pytest.raises(oauth.TokenValidationError) as info:
        await verifier.verify(token)
    assert info.value.reason == "token_not_yet_valid"


@pytest.mark.asyncio
async def test_verify_issuer_mismatch() -> None:
    """A wrong ``iss`` fails ``issuer_mismatch``."""
    key = _rsa_key()
    verifier = oauth.JWTVerifier(_config(), jwks=_cache_with(key))
    token = _encode(key, _claims(iss="https://evil.example.com"))
    with pytest.raises(oauth.TokenValidationError) as info:
        await verifier.verify(token)
    assert info.value.reason == "issuer_mismatch"


@pytest.mark.asyncio
async def test_verify_audience_mismatch() -> None:
    """A wrong ``aud`` fails ``audience_mismatch``."""
    key = _rsa_key()
    verifier = oauth.JWTVerifier(_config(), jwks=_cache_with(key))
    token = _encode(key, _claims(aud="https://other.example.com"))
    with pytest.raises(oauth.TokenValidationError) as info:
        await verifier.verify(token)
    assert info.value.reason == "audience_mismatch"


@pytest.mark.asyncio
async def test_verify_signature_invalid() -> None:
    """A token signed by a different key fails ``signature_invalid``."""
    key = _rsa_key()
    other = _rsa_key()
    verifier = oauth.JWTVerifier(_config(), jwks=_cache_with(key))
    token = _encode(other, _claims())
    with pytest.raises(oauth.TokenValidationError) as info:
        await verifier.verify(token)
    assert info.value.reason == "signature_invalid"


@pytest.mark.asyncio
async def test_verify_malformed_token() -> None:
    """A non-JWT string fails ``malformed_token``."""
    key = _rsa_key()
    verifier = oauth.JWTVerifier(_config(), jwks=_cache_with(key))
    with pytest.raises(oauth.TokenValidationError) as info:
        await verifier.verify("not.a.jwt")
    assert info.value.reason == "malformed_token"


@pytest.mark.asyncio
async def test_verify_missing_required_claim() -> None:
    """A token missing ``exp`` fails ``missing_required_claim``."""
    key = _rsa_key()
    verifier = oauth.JWTVerifier(_config(), jwks=_cache_with(key))
    claims = _claims()
    del claims["exp"]
    token = _encode(key, claims)
    with pytest.raises(oauth.TokenValidationError) as info:
        await verifier.verify(token)
    assert info.value.reason == "missing_required_claim"


@pytest.mark.asyncio
async def test_verify_generic_invalid_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unmapped ``InvalidTokenError`` collapses to ``invalid_token``."""
    key = _rsa_key()
    verifier = oauth.JWTVerifier(_config(), jwks=_cache_with(key))

    def _boom(*args: Any, **kwargs: Any) -> Any:
        raise jwt.exceptions.InvalidTokenError("generic")

    monkeypatch.setattr(oauth.jwt, "decode", _boom)
    with pytest.raises(oauth.TokenValidationError) as info:
        await verifier.verify(_encode(key, _claims()))
    assert info.value.reason == "invalid_token"


@pytest.mark.asyncio
async def test_verify_insufficient_scope() -> None:
    """A token lacking a required scope fails ``insufficient_scope``."""
    key = _rsa_key()
    verifier = oauth.JWTVerifier(
        _config(required_scopes=("evidence-pack:write",)),
        jwks=_cache_with(key),
    )
    with pytest.raises(oauth.TokenValidationError) as info:
        await verifier.verify(_encode(key, _claims()))
    assert info.value.reason == "insufficient_scope"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("claim_overrides", "expected"),
    [
        ({"client_id": "cid", "azp": "azp", "sub": "sub"}, "cid"),
        ({"azp": "azp", "sub": "sub"}, "azp"),
        ({"sub": "sub"}, "sub"),
    ],
)
async def test_verify_client_id_precedence(
    claim_overrides: dict[str, Any], expected: str
) -> None:
    """``client_id`` resolves client_id > azp > sub."""
    key = _rsa_key()
    verifier = oauth.JWTVerifier(_config(), jwks=_cache_with(key))
    access = await verifier.verify(_encode(key, _claims(**claim_overrides)))
    assert access.client_id == expected


@pytest.mark.asyncio
async def test_verify_token_returns_none_on_failure() -> None:
    """``verify_token`` returns ``None`` instead of raising on failure."""
    key = _rsa_key()
    verifier = oauth.JWTVerifier(_config(), jwks=_cache_with(key))
    assert await verifier.verify_token("not.a.jwt") is None


@pytest.mark.asyncio
async def test_verify_token_returns_access_on_success() -> None:
    """``verify_token`` returns the ``AccessToken`` on success."""
    key = _rsa_key()
    verifier = oauth.JWTVerifier(_config(), jwks=_cache_with(key))
    access = await verifier.verify_token(_encode(key, _claims()))
    assert access is not None
    assert access.subject == "user-1"


# --------------------------------------------------------------------------
# JWKSCache.get_key
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_key_cached() -> None:
    """A known ``kid`` in a fresh cache is returned directly."""
    key = _rsa_key()
    cache = _cache_with(key)
    assert await cache.get_key("k1") is cache._keys["k1"]


@pytest.mark.asyncio
async def test_get_key_none_single() -> None:
    """A ``None`` kid resolves to the sole key when unambiguous."""
    key = _rsa_key()
    cache = _cache_with(key)
    assert await cache.get_key(None) is cache._keys["k1"]


@pytest.mark.asyncio
async def test_get_key_none_ambiguous() -> None:
    """A ``None`` kid with multiple keys fails ``missing_kid``."""
    key1, key2 = _rsa_key(), _rsa_key()
    cache = oauth.JWKSCache("https://x")
    cache._keys = {
        "k1": jwt.PyJWK(_jwk_entry(key1, "k1")),
        "k2": jwt.PyJWK(_jwk_entry(key2, "k2")),
    }
    cache._fetched_at = float("inf")
    with pytest.raises(oauth.TokenValidationError) as info:
        await cache.get_key(None)
    assert info.value.reason == "missing_kid"


@pytest.mark.asyncio
async def test_get_key_unknown_kid(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unknown ``kid`` triggers a refresh then fails ``unknown_kid``."""
    key = _rsa_key()
    cache = _cache_with(key)

    async def _noop() -> None:
        return None

    monkeypatch.setattr(cache, "_refresh", _noop)
    with pytest.raises(oauth.TokenValidationError) as info:
        await cache.get_key("nope")
    assert info.value.reason == "unknown_kid"


@pytest.mark.asyncio
async def test_get_key_stale_refreshes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stale cache refreshes before resolving the key."""
    key = _rsa_key()
    cache = oauth.JWKSCache("https://x")
    cache._fetched_at = float("-inf")  # stale
    refreshed: list[bool] = []

    async def _refresh() -> None:
        refreshed.append(True)
        cache._keys = {"k1": jwt.PyJWK(_jwk_entry(key, "k1"))}
        cache._fetched_at = float("inf")

    monkeypatch.setattr(cache, "_refresh", _refresh)
    await cache.get_key("k1")
    assert refreshed == [True]


# --------------------------------------------------------------------------
# JWKSCache._refresh (httpx mocked)
# --------------------------------------------------------------------------


class _FakeResponse:
    """A minimal stand-in for an ``httpx.Response``."""

    def __init__(self, payload: Any) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        """No-op: the fake response is always a 200."""

    def json(self) -> Any:
        """Return the canned JSON document."""
        return self._payload


def _fake_client_factory(
    *, payload: Any = None, get_exc: Exception | None = None
) -> type:
    """Build a fake ``httpx.AsyncClient`` class for a single outcome."""

    class _FakeAsyncClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        async def __aenter__(self) -> _FakeAsyncClient:
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def get(self, url: str) -> _FakeResponse:
            if get_exc is not None:
                raise get_exc
            return _FakeResponse(payload)

    return _FakeAsyncClient


@pytest.mark.asyncio
async def test_refresh_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """A well-formed JWKS document populates the key index."""
    key = _rsa_key()
    payload = {"keys": [_jwk_entry(key, "k1")]}
    monkeypatch.setattr(
        oauth.httpx, "AsyncClient", _fake_client_factory(payload=payload)
    )
    cache = oauth.JWKSCache("https://x")
    await cache._refresh()
    assert "k1" in cache._keys


@pytest.mark.asyncio
async def test_refresh_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """An httpx error surfaces as ``jwks_unavailable``."""
    monkeypatch.setattr(
        oauth.httpx,
        "AsyncClient",
        _fake_client_factory(get_exc=httpx.HTTPError("down")),
    )
    cache = oauth.JWKSCache("https://x")
    with pytest.raises(oauth.TokenValidationError) as info:
        await cache._refresh()
    assert info.value.reason == "jwks_unavailable"


@pytest.mark.asyncio
async def test_refresh_missing_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    """A JWKS document with no ``keys`` member fails ``jwks_unavailable``."""
    monkeypatch.setattr(
        oauth.httpx, "AsyncClient", _fake_client_factory(payload={})
    )
    cache = oauth.JWKSCache("https://x")
    with pytest.raises(oauth.TokenValidationError) as info:
        await cache._refresh()
    assert info.value.reason == "jwks_unavailable"


@pytest.mark.asyncio
async def test_refresh_keys_not_list(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-list ``keys`` member fails ``jwks_unavailable``."""
    monkeypatch.setattr(
        oauth.httpx,
        "AsyncClient",
        _fake_client_factory(payload={"keys": "nope"}),
    )
    cache = oauth.JWKSCache("https://x")
    with pytest.raises(oauth.TokenValidationError) as info:
        await cache._refresh()
    assert info.value.reason == "jwks_unavailable"


@pytest.mark.asyncio
async def test_refresh_skips_entry_without_kid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An entry without a ``kid`` is skipped; good keys survive."""
    key = _rsa_key()
    no_kid = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    payload = {"keys": [no_kid, _jwk_entry(key, "k1")]}
    monkeypatch.setattr(
        oauth.httpx, "AsyncClient", _fake_client_factory(payload=payload)
    )
    cache = oauth.JWKSCache("https://x")
    await cache._refresh()
    assert set(cache._keys) == {"k1"}


@pytest.mark.asyncio
async def test_refresh_skips_unusable_jwk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An entry that PyJWK cannot parse is skipped."""
    key = _rsa_key()
    unusable = {"kid": "bad", "kty": "RSA"}  # missing modulus/exponent
    payload = {"keys": [unusable, _jwk_entry(key, "k1")]}
    monkeypatch.setattr(
        oauth.httpx, "AsyncClient", _fake_client_factory(payload=payload)
    )
    cache = oauth.JWKSCache("https://x")
    await cache._refresh()
    assert set(cache._keys) == {"k1"}


# --------------------------------------------------------------------------
# OAuthResourceMiddleware (ASGI)
# --------------------------------------------------------------------------


def _capturing_inner() -> tuple[Any, dict[str, Any]]:
    """Return an inner ASGI app and a dict capturing request context."""
    captured: dict[str, Any] = {}

    async def _inner(scope: Any, receive: Any, send: Any) -> None:
        captured["tenant"] = context.current_tenant()
        captured["scopes"] = context.current_scopes()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"text/plain"]],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    return _inner, captured


def _middleware(
    key: rsa.RSAPrivateKey,
    *,
    required_scopes: tuple[str, ...] = (),
    inner: Any = None,
) -> oauth.OAuthResourceMiddleware:
    """Build the OAuth middleware around ``inner`` (or a no-op app)."""
    config = _config(required_scopes=required_scopes)
    verifier = oauth.JWTVerifier(config, jwks=_cache_with(key))
    if inner is None:

        async def inner(scope: Any, receive: Any, send: Any) -> None:
            await send(
                {"type": "http.response.start", "status": 200, "headers": []}
            )
            await send({"type": "http.response.body", "body": b"ok"})

    return oauth.OAuthResourceMiddleware(inner, verifier, config)


def _client(mw: oauth.OAuthResourceMiddleware) -> httpx.AsyncClient:
    """Build an httpx client wired to the ASGI middleware."""
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mw), base_url="http://test"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        oauth.WELL_KNOWN_PATH,
        "/.well-known/oauth-protected-resource/mcp",
    ],
)
async def test_middleware_metadata_unauthenticated(path: str) -> None:
    """Both metadata paths are served unauthenticated on ``GET``."""
    mw = _middleware(_rsa_key())
    async with _client(mw) as client:
        response = await client.get(path)
    assert response.status_code == 200
    assert response.json()["resource"] == AUDIENCE


@pytest.mark.asyncio
async def test_middleware_missing_bearer_401() -> None:
    """A request with no bearer token is rejected ``401``."""
    mw = _middleware(_rsa_key())
    async with _client(mw) as client:
        response = await client.post("/mcp")
    assert response.status_code == 401
    assert "resource_metadata" in response.headers["WWW-Authenticate"]


@pytest.mark.asyncio
async def test_middleware_invalid_bearer_401() -> None:
    """A request with an invalid bearer token is rejected ``401``."""
    mw = _middleware(_rsa_key())
    async with _client(mw) as client:
        response = await client.post(
            "/mcp", headers={"Authorization": "Bearer not.a.jwt"}
        )
    assert response.status_code == 401
    assert "resource_metadata" in response.headers["WWW-Authenticate"]


@pytest.mark.asyncio
async def test_middleware_insufficient_scope_403() -> None:
    """A valid token lacking the required scope is rejected ``403``."""
    key = _rsa_key()
    mw = _middleware(key, required_scopes=("evidence-pack:write",))
    token = _encode(key, _claims())
    async with _client(mw) as client:
        response = await client.post(
            "/mcp", headers={"Authorization": f"Bearer {token}"}
        )
    assert response.status_code == 403
    assert response.json()["error"] == "insufficient_scope"


@pytest.mark.asyncio
async def test_middleware_valid_forwards_context() -> None:
    """A valid token reaches the inner app, which sees tenant + scopes."""
    key = _rsa_key()
    inner, captured = _capturing_inner()
    mw = _middleware(key, inner=inner)
    token = _encode(key, _claims())
    async with _client(mw) as client:
        response = await client.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {token}",
                "X-MCP-Tenant": "acme",
            },
        )
    assert response.status_code == 200
    assert captured["tenant"] == "acme"
    assert captured["scopes"] == ("evidence-pack:read",)


@pytest.mark.asyncio
async def test_middleware_non_http_passthrough() -> None:
    """A non-HTTP scope is passed straight through to the inner app."""
    seen: list[str] = []

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        seen.append(scope["type"])

    mw = _middleware(_rsa_key(), inner=inner)
    await mw({"type": "lifespan"}, None, None)
    assert seen == ["lifespan"]
