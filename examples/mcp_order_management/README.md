# Order Management: a HelixID-protected MCP server (Python)

The Python twin of helix-sdk-js's `mcp-middleware/examples/order-management`: same tools, same wire names, same
environment variables, so a client or test written against one works against the other.

| Tool | Scope | What it does |
|---|---|---|
| `lookup_order` | `orders:read` | Returns an order by id |
| `refund_order` | `orders:admin` | Refunds an order in full (destructive) |

Any other tool name is denied before it runs. Callers present a HelixID VP (`Authorization: HelixVP <vp>`, legacy
`X-Helix-VP`, or MCP `params._meta["x-helix-vp"]`) or an OAuth 2.1 bearer token, discovered through the RFC 9728
metadata at `/.well-known/oauth-protected-resource/mcp`.

## Quickstart (no accounts, no authorization server)

Python 3.10+ (the MCP SDK needs it):

```bash
pip install -e ".[mcp-middleware]" uvicorn
cd examples && DEMO_MODE=1 python -m mcp_order_management
```

`DEMO_MODE=1` accepts two fixed bearer tokens, `demo-reader` (`orders:read`) and `demo-admin` (`orders:read`,
`orders:admin`), and only on a loopback address. In another terminal:

```bash
MCP=http://localhost:3700/mcp
H=(-H 'content-type: application/json' -H 'accept: application/json, text/event-stream')
CALL='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"refund_order","arguments":{"orderId":"ORD-1001","reason":"damaged"}}}'

curl -i "${H[@]}" $MCP -d "$CALL"                                          # 401, WWW-Authenticate points at the metadata
curl -i "${H[@]}" -H 'authorization: Bearer demo-reader' $MCP -d "$CALL"   # 403 insufficient_scope, scope="orders:admin"
curl    "${H[@]}" -H 'authorization: Bearer demo-admin'  $MCP -d "$CALL"   # refunded
```

## With HelixID, and with real authorization servers

The variables are the JS sample's: `HELIX_API_URL` + `HELIX_API_KEY` + `SERVICE_DID` to verify agent VPs and write the
audit log (typed KYA-OS audit events, one `session.established` / `tool.call.*` bracket per call plus the gate's
decisions, with `delegation.verified` naming the presented agent credential; tool names are withheld unless
`AUDIT_INCLUDE_TOOL_NAMES=1`; an audit write that fails fails the call with a 500); `OAUTH_ISSUER` (alone, or with `OAUTH_CLIENT_ID` / `OAUTH_CLIENT_SECRET` for opaque tokens) for one
authorization server; `OAUTH_ISSUERS` for several, with the `entra`, `auth0`, `okta` and `keycloak` presets. See the
docstring of [`__main__.py`](__main__.py) and the JS sample's README for the full table.

## How it is wired ([`app.py`](app.py))

A small ASGI wrapper sits in front of the MCP SDK's Streamable HTTP app. For each `tools/call` in the request body it
awaits `async_helixid_mcp_middleware` with the tool name, `params._meta` and the request headers; a denial becomes a
401 / 400 / 403 through `to_http_error_response()`, an unreachable authorization server a 503, and anything else is
handed, body intact, to the transport. `initialize` and `tools/list` are not gated. The tools
([`orders.py`](orders.py)) contain no auth code.

## KYA-OS session and response proof (story L2-A)

Set `SERVICE_SIGNING_KEY` (the Ed25519 private key, hex, that `SERVICE_DID`'s document lists as `key-1`) and the
server registers the `_kyaos_handshake` tool, opens sessions and signs a detached proof into
`_meta["org.kya-os/response-proof"]` on every tool call outcome, the same as the JS sample (a refusal carries its
`denied` proof in the 400/401/403 body; a tool error is proven like any result). Optional: `KYAOS_PUBLIC_ORIGIN`
(default: the origin of `MCP_RESOURCE`), `KYAOS_CLOCK_SKEW_SECONDS` (30 to 600, default 120), `KYAOS_SESSIONS=0`,
`KYAOS_SESSION_TTL_MINUTES` (default 30).

The replay store is chosen by `KYAOS_NONCE_STORE`, which `helix_mcp_middleware` reads itself
(`nonce_store_from_env()`): `memory` (the default) covers this instance only; `redis` (`KYAOS_REDIS_URL`, needs
`pip install 'helixid-sdk-py[redis]'`) or `dynamo` (`KYAOS_DYNAMO_TABLE`, needs `pip install 'helixid-sdk-py[dynamo]'`)
is shared by every instance, JS or Python. See [`.env.example`](.env.example) and the package README for every
variable. A bad setting or a missing package stops the server at startup.

## KYA-OS `needs_authorization` and resume (story L3-E)

Set `KYAOS_AUTHORIZATION_URL` (the consent page) and a caller whose scopes do not cover a tool gets the signed `needs_authorization` challenge as the call's result instead of a 403, with a resume token bound to the agent, tool and scopes (`KYAOS_RESUME_TTL_SECONDS`, default 600; the token store follows `KYAOS_NONCE_STORE`, chosen by `helix_mcp_middleware` itself: Redis on `KYAOS_REDIS_URL` when the replay store is Redis, sharing records with JS instances, memory otherwise). The retry carries `_kyaos_resume` and the DelegationCredential as `_kyaos_delegation`. In `DEMO_MODE` the bearers `demo-agent` and `demo-agent-2` are agents with a DID and `orders:read` only, and the retry's credential is checked structurally by `demo_authorizer.py` (invoker, invocationTarget, allowedAction, validUntil, a `proof` present; no signature verification, which stories F-2 and L3-H bring); outside demo mode every retry is refused until a verifier is wired in. `AUDIT_LOG_FILE` appends every audit event as a JSON line. The same wire behaviour as the JS sample.

## Discovery at `/.well-known/mcp` (story L1-D)

Whenever `SERVICE_DID` is a `did:web` or `did:key`, the server answers `GET /.well-known/mcp` with the KYA-OS
discovery document, the same bytes the JS sample serves for the same environment: the DID, `endpoints.tools` at
`KYAOS_PUBLIC_ORIGIN` (default: the origin of `MCP_RESOURCE`), `endpoints.handshake` while the KYA-OS layer runs with
sessions, `clockSkewSeconds` (the handshake's), `capabilities` (`proofs` true with `SERVICE_SIGNING_KEY`; the rest
false, nothing else is on in this sample) and, with `STATUS_LIST_CREDENTIAL`, that URL. The document is validated
against the schema at startup; `WELL_KNOWN_MCP=0` turns the route off (404) and `WELL_KNOWN_MCP=1` makes a
`SERVICE_DID` the document cannot carry a startup error. Behind a proxy, forward `/.well-known/mcp` at the origin root
to this process and set `KYAOS_PUBLIC_ORIGIN` (helix-sdk-js's `mcp-middleware/docs/well-known.md` has the nginx, ALB
and API Gateway rules).

```bash
curl -s localhost:3700/.well-known/mcp | python -m json.tool
```

A `SERVICE_DID` of another method (a `did:hedera` from a Helix stack, say) cannot be the document's `serverDid`, so
the route stays off and the `Discovery:` startup line says why.
