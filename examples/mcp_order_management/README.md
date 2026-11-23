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
(with `SERVICE_DID`) only write the audit log, never on the request path: typed KYA-OS audit events, one
`session.established` / `tool.call.*` bracket per call plus the gate's decisions (`proof.verified` at the proof's level,
or `proof.rejected`), delivered to the recorder (`POST /v1/audit/submissions`, story A-2); tool names are withheld unless
`AUDIT_INCLUDE_TOOL_NAMES=1`. A session that cannot be recorded fails the call with a 500; under the default
`AUDIT_DELIVERY=required` a tool whose intent cannot be recorded does not run and answers `audit_delivery_failed`, and
one whose completion cannot be recorded is marked degraded; `AUDIT_DELIVERY=buffered` takes `AUDIT_OUTBOX_DIR`, and
`best-effort` needs `AUDIT_ACCEPT_AAP1=1`, as in the JS sample. `OAUTH_ISSUER` (alone, or with `OAUTH_CLIENT_ID` / `OAUTH_CLIENT_SECRET` for opaque tokens) for one
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
([`orders.py`](orders.py)) contain no auth or audit code: with an audit trail, `audit_tool_handlers(server)` wraps
each one before it is registered, so it runs under the tool call `begin_tool_call` opened for the request (the JS
sample's `auditToolHandlers`).

## Minimum Card level (story C-C)

Every tool demands Card level `L3` by default: a fresh request proof on the call from a fully attested agent whose
status was read live. A chain sent without a proof verifies at `L2` at most; a proof with no token `cnf` to fuse is
`L3-minus`, which meets `L3` unless told otherwise. A call below its tool's minimum is a 401
`insufficient_user_authentication` with `derivedLevel` and `requiredLevel` in the body. With `SERVICE_DID` set:

| Variable | Values | Default |
|---|---|---|
| `KYAOS_MINIMUM_LEVEL` | `L1`, `L2`, `L3` | `L3` |
| `KYAOS_TOOL_LEVELS` | `tool=level,...`, e.g. `lookup_order=L2` | none |
| `KYAOS_L3_MINUS_SATISFIES_L3` | `0`, `1` | `1` |

A level that does not exist is refused at startup, never read as a lower bar. The `_kyaos_handshake` tool takes `L1`.
A bearer token sent with a request proof is the proof's sender constraint: when its `cnf.jkt` matches the proof's
`cnf.jkt` and the signing key, the call is `L3` (SPEC-ENTITY-CARD section 8.6).

## Calling another service on the agent's behalf (story L3-D)

`KYAOS_DOWNSTREAM_URL` (with `SERVICE_DID` and `SERVICE_SIGNING_KEY`) adds `forward_lookup_order` (`orders:read`): it asks another order service's `lookup_order` for the order, through the middleware's `withDelegation` / `with_delegation`, which forwards the chain the agent presented here (`KYA-OS-Delegation-Credential`), a delegation proof this server signs for the target host (`KYA-OS-Delegation-Proof`, 60 s), the agent DID and the session id; `KYAOS_DELEGATION_ADVISORY=1` adds the advisory chain and scope headers. Each attachment is audited: `delegation.outbound_attached` on the typed trail, and a `outbound-delegation` line in `KYAOS_VERIFICATION_LOG`.

The receiving sample accepts such calls from the services in `KYAOS_FORWARDERS` (`*`, the default, or DIDs; `none` for no forwarder) for chains that target them, and always for chains that target itself. `KYAOS_DELEGATION_AUDIENCE` is its host as forwarders name it (default the host of a did:web `SERVICE_DID`). A forwarded call carries no request proof of the agent's, so it comes to at most Card L2: lower the receiving tool's level (`KYAOS_TOOL_LEVELS=lookup_order=L2`). A revocation signal drops the cached verdict of a forwarded chain at once.

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
