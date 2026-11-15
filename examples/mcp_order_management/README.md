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
audit log; `OAUTH_ISSUER` (alone, or with `OAUTH_CLIENT_ID` / `OAUTH_CLIENT_SECRET` for opaque tokens) for one
authorization server; `OAUTH_ISSUERS` for several, with the `entra`, `auth0`, `okta` and `keycloak` presets. See the
docstring of [`__main__.py`](__main__.py) and the JS sample's README for the full table.

## How it is wired ([`app.py`](app.py))

A small ASGI wrapper sits in front of the MCP SDK's Streamable HTTP app. For each `tools/call` in the request body it
awaits `async_helixid_mcp_middleware` with the tool name, `params._meta` and the request headers; a denial becomes a
401 / 400 / 403 through `to_http_error_response()`, an unreachable authorization server a 503, and anything else is
handed, body intact, to the transport. `initialize` and `tools/list` are not gated. The tools
([`orders.py`](orders.py)) contain no auth code.
