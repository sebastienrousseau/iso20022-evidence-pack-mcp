# HTTP transport & authentication

`iso20022-evidence-pack-mcp` speaks **stdio by default** — launched by a local
MCP client, one process per operator, with no network surface and no
authentication. For shared, multi-tenant deployments, v0.0.2 adds an **optional
streamable-HTTP transport** with OAuth 2.1 resource-server authentication
(RFC 9728). This page is the reference for running and securing it.

## Choosing a transport

The transport is selected on the command line:

```sh
# Default: stdio, for a local MCP client.
iso20022-evidence-pack-mcp

# Optional: authenticated streamable HTTP, for a shared service.
iso20022-evidence-pack-mcp --transport=http --bind=127.0.0.1:8080
```

- `--transport` is `stdio` (default) or `http`.
- `--bind` takes `HOST:PORT` and applies only to `--transport=http`. It
  **defaults to loopback `127.0.0.1:8080`**, so exposing the server to a network
  (for example `--bind=0.0.0.0:8080`) is an explicit opt-in.

The HTTP transport pulls in additional dependencies — `pyjwt[crypto]`, `httpx`,
`starlette`, and `uvicorn`. The default stdio transport needs none of them.

!!! warning "HTTP with no auth is refused"
    Starting `--transport=http` without either OAuth 2.1 or a static dev-mode
    token configured **fails to start** rather than silently serving an
    unauthenticated endpoint.

Two auth modes apply, strongest first: OAuth 2.1 (when the
`ISO20022_EVIDENCE_PACK_OAUTH_*` variables are set) else the static dev-mode
token. If both are configured, OAuth wins and the static token is ignored.

## OAuth 2.1 resource server (RFC 9728)

Point the server at your OAuth 2.1 authorization server with these environment
variables:

| Variable | Required | Meaning |
| --- | --- | --- |
| `ISO20022_EVIDENCE_PACK_OAUTH_ISSUER` | yes | The authorization server's issuer identifier; the JWT `iss` claim must match it exactly. |
| `ISO20022_EVIDENCE_PACK_OAUTH_AUDIENCE` | yes | This server's canonical resource URI (RFC 8707); the JWT `aud` claim must contain it. |
| `ISO20022_EVIDENCE_PACK_OAUTH_JWKS_URL` | no | JWKS document URL for signature checks. Defaults to `<issuer>/.well-known/jwks.json`. |
| `ISO20022_EVIDENCE_PACK_OAUTH_SCOPES` | no | Space-separated scopes every token must carry. Unset/empty means no scope gate. |

```sh
ISO20022_EVIDENCE_PACK_OAUTH_ISSUER=https://auth.example.com \
ISO20022_EVIDENCE_PACK_OAUTH_AUDIENCE=https://mcp.example.com/mcp \
iso20022-evidence-pack-mcp --transport=http --bind=0.0.0.0:8080
```

Setting some but not both of `ISSUER` and `AUDIENCE` is a **partial
configuration** and fails loudly at startup, so a typo cannot downgrade a
deployment to weaker auth.

### How a request is validated

Every HTTP request must present `Authorization: Bearer <jwt>`. The JWT is
validated against the JWKS in order: structure, signing-key resolution (by
`kid`), signature, `exp` / `nbf` (with a 30-second clock-skew leeway), `iss`,
`aud`, and any required scopes. The verification algorithm is always taken from
the JWKS key, **never** from the attacker-controlled token header, so `none` /
HMAC downgrade attacks are structurally impossible against an asymmetric key
set. JWKS keys are cached with a short TTL and refreshed on key rotation (an
unknown `kid`).

### Protected-resource metadata and challenges

- The **protected-resource metadata** document (RFC 9728 §2) is served
  unauthenticated on `GET`/`HEAD` to `/.well-known/oauth-protected-resource`
  (and its audience-derived variant). It advertises the `resource`, the
  `authorization_servers`, `bearer_methods_supported`, and any
  `scopes_supported`.
- A missing or invalid token is rejected **`401`**; a valid token that lacks a
  required scope is rejected **`403`**. Both carry a `WWW-Authenticate: Bearer …`
  challenge with a `resource_metadata` pointer (RFC 6750 / RFC 9728 §5.1).

## Static dev-mode bearer token

For local development, set a single shared secret instead of wiring up an
authorization server:

```sh
ISO20022_EVIDENCE_PACK_TOKEN=s3cret \
    iso20022-evidence-pack-mcp --transport=http --bind=127.0.0.1:8080
```

Every request must then send `Authorization: Bearer s3cret` (compared with a
constant-time `hmac.compare_digest`). This is **dev-mode auth**: a single shared
secret, no expiry, and no scopes. Prefer OAuth 2.1 for anything beyond local
testing.

## Multi-tenant scoping

HTTP callers may send an optional `X-MCP-Tenant` header. On an authorized
request it is forwarded, together with the authenticated token's scopes, into a
per-request context that tools can read. Under the stdio transport both are
simply empty, so tool code never has to branch on the transport.

## See also

- [Evidence packs](evidence-packs.md) — the pack schema, sealing, and
  Ed25519 signing.
- [`SECURITY.md`](https://github.com/sebastienrousseau/iso20022-evidence-pack-mcp/blob/main/SECURITY.md)
  — reporting practice, supported versions, and the threat-model note.
- [`ROADMAP.md`](https://github.com/sebastienrousseau/iso20022-evidence-pack-mcp/blob/main/ROADMAP.md)
  — what is planned next.
