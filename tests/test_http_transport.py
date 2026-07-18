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

"""HTTP transport: bind parsing, static-token middleware, app assembly."""

from __future__ import annotations

import logging
from typing import Any

import httpx
import pytest

from iso20022_evidence_pack_mcp import server as server_mod
from iso20022_evidence_pack_mcp.http import oauth
from iso20022_evidence_pack_mcp.http import transport as transport_mod

TOKEN = "s3cret"  # noqa: S105 - test-only fixture secret


# --------------------------------------------------------------------------
# parse_bind
# --------------------------------------------------------------------------


def test_parse_bind_valid() -> None:
    """A ``HOST:PORT`` string parses into a ``(host, port)`` pair."""
    assert transport_mod.parse_bind("0.0.0.0:8080") == ("0.0.0.0", 8080)


def test_parse_bind_no_colon() -> None:
    """A string without a colon is rejected."""
    with pytest.raises(ValueError, match="HOST:PORT"):
        transport_mod.parse_bind("localhost")


def test_parse_bind_non_int_port() -> None:
    """A non-integer port is rejected."""
    with pytest.raises(ValueError, match="must be an integer"):
        transport_mod.parse_bind("localhost:abc")


def test_parse_bind_out_of_range_port() -> None:
    """A port outside ``0..65535`` is rejected."""
    with pytest.raises(ValueError, match="0..65535"):
        transport_mod.parse_bind("localhost:99999")


# --------------------------------------------------------------------------
# BearerTokenMiddleware
# --------------------------------------------------------------------------


def _capturing_inner() -> tuple[Any, dict[str, Any]]:
    """Return an inner ASGI app and a dict capturing request context."""
    from iso20022_evidence_pack_mcp.http import context

    captured: dict[str, Any] = {}

    async def _inner(scope: Any, receive: Any, send: Any) -> None:
        captured["tenant"] = context.current_tenant()
        await send(
            {"type": "http.response.start", "status": 200, "headers": []}
        )
        await send({"type": "http.response.body", "body": b"ok"})

    return _inner, captured


def _client(app: Any) -> httpx.AsyncClient:
    """Build an httpx client wired to an ASGI ``app``."""
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    )


@pytest.mark.asyncio
async def test_bearer_no_token_401() -> None:
    """A request with no bearer token is rejected ``401``."""
    inner, _ = _capturing_inner()
    mw = transport_mod.BearerTokenMiddleware(inner, TOKEN)
    async with _client(mw) as client:
        response = await client.post("/mcp")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.asyncio
async def test_bearer_wrong_token_401() -> None:
    """A request with the wrong bearer token is rejected ``401``."""
    inner, _ = _capturing_inner()
    mw = transport_mod.BearerTokenMiddleware(inner, TOKEN)
    async with _client(mw) as client:
        response = await client.post(
            "/mcp", headers={"Authorization": "Bearer wrong"}
        )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_bearer_right_token_forwards_tenant() -> None:
    """The correct token reaches the inner app, which sees the tenant."""
    inner, captured = _capturing_inner()
    mw = transport_mod.BearerTokenMiddleware(inner, TOKEN)
    async with _client(mw) as client:
        response = await client.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {TOKEN}",
                "X-MCP-Tenant": "acme",
            },
        )
    assert response.status_code == 200
    assert captured["tenant"] == "acme"


@pytest.mark.asyncio
async def test_bearer_non_http_passthrough() -> None:
    """A non-HTTP scope passes straight through to the inner app."""
    seen: list[str] = []

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        seen.append(scope["type"])

    mw = transport_mod.BearerTokenMiddleware(inner, TOKEN)
    await mw({"type": "lifespan"}, None, None)
    assert seen == ["lifespan"]


# --------------------------------------------------------------------------
# build_http_app
# --------------------------------------------------------------------------


def test_build_http_app_static_token() -> None:
    """A static token yields a :class:`BearerTokenMiddleware` app."""
    app = transport_mod.build_http_app(server_mod.server, token=TOKEN)
    assert isinstance(app, transport_mod.BearerTokenMiddleware)


def test_build_http_app_oauth() -> None:
    """An OAuth config yields an :class:`OAuthResourceMiddleware` app."""
    config = oauth.OAuthConfig(
        issuer="https://iss",
        audience="https://aud",
        jwks_url="https://iss/.well-known/jwks.json",
    )
    app = transport_mod.build_http_app(server_mod.server, oauth_config=config)
    assert isinstance(app, oauth.OAuthResourceMiddleware)


def test_build_http_app_neither_raises() -> None:
    """Neither a token nor an OAuth config is a configuration error."""
    with pytest.raises(ValueError, match="static token or an OAuth config"):
        transport_mod.build_http_app(server_mod.server)


# --------------------------------------------------------------------------
# run_http
# --------------------------------------------------------------------------


def _patch_uvicorn(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Patch ``uvicorn.run`` to record its call kwargs."""
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        transport_mod.uvicorn,
        "run",
        lambda app, **kwargs: calls.append({"app": app, **kwargs}),
    )
    return calls


def test_run_http_oauth_path(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """OAuth config wins, and a set static token is warned about + ignored."""
    calls = _patch_uvicorn(monkeypatch)
    config = oauth.OAuthConfig(
        issuer="https://iss",
        audience="https://aud",
        jwks_url="https://iss/.well-known/jwks.json",
    )
    monkeypatch.setattr(
        oauth.OAuthConfig, "from_env", classmethod(lambda cls: config)
    )
    monkeypatch.setenv(transport_mod.TOKEN_ENV, TOKEN)
    with caplog.at_level(logging.WARNING):
        transport_mod.run_http(server_mod.server, "127.0.0.1:8080")
    assert len(calls) == 1
    assert calls[0]["host"] == "127.0.0.1"
    assert calls[0]["port"] == 8080
    assert any("OAuth" in rec.message for rec in caplog.records)
    assert isinstance(calls[0]["app"], oauth.OAuthResourceMiddleware)


def test_run_http_oauth_explicit_token_none_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An explicit (falsy) ``token`` skips the env read and the warning."""
    calls = _patch_uvicorn(monkeypatch)
    config = oauth.OAuthConfig(
        issuer="https://iss",
        audience="https://aud",
        jwks_url="https://iss/.well-known/jwks.json",
    )
    monkeypatch.setattr(
        oauth.OAuthConfig, "from_env", classmethod(lambda cls: config)
    )
    # A pre-set env token must be ignored because ``token`` is passed.
    monkeypatch.setenv(transport_mod.TOKEN_ENV, TOKEN)
    transport_mod.run_http(server_mod.server, "127.0.0.1:8080", token="")
    assert len(calls) == 1
    assert isinstance(calls[0]["app"], oauth.OAuthResourceMiddleware)


def test_run_http_static_token_path(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """With no OAuth config, the static token serves in warned dev mode."""
    calls = _patch_uvicorn(monkeypatch)
    monkeypatch.setattr(
        oauth.OAuthConfig, "from_env", classmethod(lambda cls: None)
    )
    monkeypatch.setenv(transport_mod.TOKEN_ENV, TOKEN)
    with caplog.at_level(logging.WARNING):
        transport_mod.run_http(server_mod.server, "127.0.0.1:8080")
    assert len(calls) == 1
    assert isinstance(calls[0]["app"], transport_mod.BearerTokenMiddleware)
    assert any("DEV-MODE" in rec.message for rec in caplog.records)


def test_run_http_no_auth_exits(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neither OAuth nor a static token refuses to serve."""
    _patch_uvicorn(monkeypatch)
    monkeypatch.setattr(
        oauth.OAuthConfig, "from_env", classmethod(lambda cls: None)
    )
    monkeypatch.delenv(transport_mod.TOKEN_ENV, raising=False)
    with pytest.raises(SystemExit, match="requires auth"):
        transport_mod.run_http(server_mod.server, "127.0.0.1:8080")


def test_run_http_bad_bind_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """A malformed bind is rejected before any auth resolution."""
    _patch_uvicorn(monkeypatch)
    with pytest.raises(ValueError, match="HOST:PORT"):
        transport_mod.run_http(server_mod.server, "no-colon")
