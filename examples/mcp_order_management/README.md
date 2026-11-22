# Order Management: a HelixID-protected MCP server (Python)

The Python twin of helix-sdk-js's `mcp-middleware/examples/order-management`: same tools, same wire names, same
environment variables, so a client or test written against one works against the other.

| Tool | Scope | What it does |
|---|---|---|
| `lookup_order` | `orders:read` | Returns an order by id |
| `refund_order` | `orders:admin` | Refunds an order in full (destructive) |

Any other tool name is denied before it runs. Callers present a KYA-OS request proof in MCP
`params._meta["org.kya-os/request-proof"]` (with the delegation chain the request carries in
`params._meta["org.kya-os/delegation-chain"]`), verified in-process by the local verifier, or an OAuth 2.1 bearer
token, discovered through the RFC 9728 metadata at `/.well-known/oauth-protected-resource/mcp`. The Helix VP is no
longer read (story F-2).

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

The variables are the JS sample's. `SERVICE_DID` turns on the KYA-OS door: each request proof is verified in-process
against that DID, from public DID documents, status lists and the agent's Entity Card alone, so the server authorises
with the Helix API unreachable (`KYAOS_TRUSTED_ISSUERS`, `KYAOS_TRUSTED_ROOTS`, `KYAOS_MAX_CHAIN_LENGTH`,
`KYAOS_CARDS_FILE` and, in development, `KYAOS_ALLOW_LOOPBACK_HTTP=1` tune it). `HELIX_API_URL` + `HELIX_API_KEY`
only write the audit log, never on the request path. `OAUTH_ISSUER` (alone, or with `OAUTH_CLIENT_ID` / `OAUTH_CLIENT_SECRET` for opaque tokens) for one
authorization server; `OAUTH_ISSUERS` for several, with the `entra`, `auth0`, `okta` and `keycloak` presets. See the
docstring of [`__main__.py`](__main__.py) and the JS sample's README for the full table.

Status lists (story L3-C): each list's proof is verified before a bit is read, and an unreachable, unsigned, badly
signed, wrong-purpose or out-of-range list reads as revoked. Lists and verdicts are cached (`KYAOS_STATUS_CACHE_TTL`,
`KYAOS_HIGH_PRIVILEGE_SCOPES` / `KYAOS_HIGH_PRIVILEGE_TTL`, `KYAOS_MAX_STALE_SECONDS`, `KYAOS_STATUS_LIST_ISSUERS`), in
Redis with `KYAOS_REDIS_URL`, in the same keys as the JS sample, so JS and Python instances can share it.
`KYAOS_REVOCATION_EVENTS_URL` and/or `KYAOS_REVOCATION_WEBHOOK_PATH`, with `KYAOS_SIGNAL_ISSUERS`, drop a cached verdict
the moment Helix signals the revocation. `KYAOS_VERIFICATION_LOG=1` prints each verification and signal as one JSON line
(a path appends them there). Unlike the JS sample, `KYAOS_REDIS_URL` backs only the status cache here: the Python
middleware has no shared replay store yet (story L2-A).

## How it is wired ([`app.py`](app.py))

A small ASGI wrapper sits in front of the MCP SDK's Streamable HTTP app. For each `tools/call` in the request body it
awaits `async_helixid_mcp_middleware` with the tool name, `params._meta`, the JSON-RPC request as received (the
proof's `requestHash` covers it) and the request headers; a denial becomes a
401 / 400 / 403 through `to_http_error_response()`, an unreachable authorization server a 503, and anything else is
handed, body intact, to the transport. `initialize` and `tools/list` are not gated. The tools
([`orders.py`](orders.py)) contain no auth code.
