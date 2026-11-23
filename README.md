# helixid-sdk-py

Python SDK for [HelixID](https://github.com/helixid/helixid) -- decentralized
agent identity via DID/VC standards (did:hedera, did:key, did:web), delegation,
and KYA-OS request proofs verified in-process.

This is the Python counterpart to
[`helix-sdk-js`](https://github.com/helixid/helix-sdk-js), following the same
**SDK-API-only** architecture: every
SDK, in every language, depends only on the HelixID API -- never on a shared
"core" package -- except for private-key operations that must stay local:
keygen, sign and canonical-hash, which issuers and Service Providers use to sign
with their own keys. Delegation-VC construction and status checks are API calls
made through `HelixClient`.

**Every call carries a request proof (KYA-OS story C-C).** An agent signs each
MCP request with its own Signer (`kyaos.with_request_proof()`): an
`org.kya-os/proof.v1` bound to that request's body and the service's DID, with
its delegation chain beside it in `params._meta`. A service verifies it
in-process (`helix_sdk.verifier`, `helix_mcp_middleware`). The Helix VP
(`sign_vp()`, `verify_vp()`, `VPBuilder`, `X-Helix-VP`) is gone, with no
backward compatibility.

## Documentation

Full documentation is at **[docs.helixid.dev](https://docs.helixid.dev)** — concepts,
guides, and reference. This README covers only what is specific to this repository.

| | |
|---|---|
| **Start here** | [Introduction](https://docs.helixid.dev/) |
| **Concepts** | [The Trust Stack](https://docs.helixid.dev/concepts/trust-stack) · [Two-Issuer Model](https://docs.helixid.dev/concepts/two-issuer-model) · [Delegation](https://docs.helixid.dev/concepts/delegation) · [Revocation](https://docs.helixid.dev/concepts/revocation) |
| **Get started** | [Quick Start](https://docs.helixid.dev/get-started/quick-start) · [Installation & Modes](https://docs.helixid.dev/get-started/installation-and-modes) |
| **Contributing** | [How to Contribute](https://docs.helixid.dev/contributing/how-to-contribute) · [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| **Security** | [Reporting a Vulnerability](https://docs.helixid.dev/security/reporting-a-vulnerability) · [`SECURITY.md`](SECURITY.md) |

---

## Status: v0.1.1, early

This is the first release. Core local-signing primitives and the full
`HelixClient` API surface are implemented and tested; a few areas are
still gaps -- see [Known gaps](#known-gaps) below.

## Install

```bash
pip install helixid-sdk-py
```

Or from source:

```bash
pip install -e .
```

## Cross-language parity

The local-signing primitives (`keys.py`, `crypto/common.py`, `proof.py`) are
verified **byte-for-byte** against the same
`fixtures/golden-vectors/*.json` fixtures that `helix-sdk-js` and
`helix-core` assert against -- same private key, same payload, same
signature, same base58btc-encoded proof value, in every language. See
`tests/test_golden_vectors.py` and `fixtures/golden-vectors/README.md`.

If you regenerate the vectors in `helix-server` (`pnpm generate:golden-vectors`),
re-copy the three JSON files here too, the same way `helix-sdk-js` does.

## Local verifier (KYA-OS story F-2)

`helix_sdk.verifier.verify(proof, seams, options, chain=..., request=..., card=...)` verifies a KYA-OS request proof
(`org.kya-os/proof.v1`) and the delegation chain the request carries, in-process, from the presented artifacts and
what its seams answer (`resolve_did`, `resolve_did_keys`, `fetch_status_list`, `resolve_card`, `nonce_store`, `clock`,
`trusted_issuers`). It never reads a Helix database, and a missing seam fails closed with its reason code
(`helix_sdk.verifier.ReasonCodes`). It is the port of helix-sdk-js's `kyaos.verifier.verify`: same seams, same codes,
same results, which `tests/test_verifier.py` proves over the fixture set helix-core generates
(`fixtures/verifier/*.json`, read from the sibling checkout or `HELIX_CORE_FIXTURES_DIR`).

`helix_sdk.verifier.verify_request_proof(proof, request, seams, options)` checks the request proof alone in the exact
SPEC-ENTITY-CARD section 11.2 order (story C-C), stopping at the first broken binding: schema, `kid` of `did`, the key,
its RFC 7638 thumbprint among the DID's keys, `audience`, `requestHash`, the window (+/-5 s, at most 60 s), the nonce,
the detached JWS, the `cnf` fusion (`L3` with a token `cnf`, `L3-minus` without). `verify()` runs it first; with
`require_proof=False` a chain without a proof verifies at L2 at most, and the result names `agent_did` and
`proof_floor`. `tests/test_request_proof_fixtures.py` runs helix-core's `fixtures/kya-os-helix/request-proof.json`.

`python -m helix_sdk.conformance [vectors_dir]` runs the KYA-OS vector categories `signed-proof`, `delegation-chain`,
`status-list`, `did-key`, `did-web`, `card-proof` and `entity-card` through `helix_sdk.conformance.HelixConformanceAdapter`.

## Status lists and revocation (KYA-OS story L3-C)

`helix_sdk.verifier` reads status lists as SPEC.md §6.6 says, exactly as helix-sdk-js does:

- `read_bitstring_status_list` / `read_status_list_2021` verify the list's own proof (`eddsa-jcs-2022`, or the §6.2
  `Ed25519Signature2020`) by its issuer's `assertionMethod` key before decoding any bit; `create_status_list_fetcher`
  fetches through the host's (Safe)fetch. Unreachable, malformed, unsigned, badly signed, wrong-purpose and out-of-range
  lists read as revoked.
- `create_revocation_checker` (the `check_revocation` seam, fail-closed) applies the keeper rules and caches lists and
  verdicts in a `StatusCache` (`status_cache_ttl`, `high_privilege_scopes` at most 60 s, `max_stale_seconds`,
  `invalidate(credential_id)`); a cached read is `fresh=False`, which demotes a Card L3 request to L2. Its Redis keys and
  JSON match the JavaScript cache, so both can share one store. `check_chain_revocation` walks a chain root to leaf.
- `verify_revocation_signal` checks Helix's revocation SET (RFC 8417): a trusted issuer and its signature, one credential.
- The conformance `status-list` category runs through these production readers, both list formats.

`helix_mcp_middleware` uses them the way `@helixid/mcp-middleware` does:

- `create_local_verifier` reads every list through `create_status_list_fetcher` and a fail-closed revocation checker,
  and exposes `status_cache`. Options: `status_cache` (a `StatusCache`, or a dict of its options), `status_list_issuers`,
  `check_revocation`. The default fetch is `create_resolution_fetch`: https only, a host written as an IP must be public
  unicast, same-origin redirects, 5 s, 1 MiB. Pass your SafeFetch as `fetch` to pin the connection too.
- `RedisStatusCacheStore` shares the cache between instances (any client with redis-py's `get`/`set(px=)`/`delete`/`incr`).
- `RevocationSignalClient` / `create_revocation_signal_client(verifier, trusted_issuers, ...)` receive Helix's SETs:
  over SSE by default (one outbound connection on a background thread, reconnecting with backoff and `Last-Event-ID`),
  or pushed (RFC 8935) through `asgi_webhook()` or the framework-neutral `handle_push()` (202, or 400 `{err, description}`).
  A valid SET calls `status_cache.invalidate(credential_id)`; a bad or foreign one is ignored and reported through
  `on_signal`.

```python
from helix_mcp_middleware import RedisStatusCacheStore, create_local_verifier, create_revocation_signal_client

verifier = create_local_verifier(
    service_did="did:web:mcp.example.com",
    status_cache={"store": RedisStatusCacheStore(redis.Redis()), "status_cache_ttl": 300, "high_privilege_scopes": ["orders:admin"]},
)
signals = create_revocation_signal_client(
    verifier,
    ["did:web:api.helixid.example"],  # the Helix issuer whose SETs are honoured
    events_url="https://api.helixid.example/v1/events/revocations",
    on_signal=lambda report: audit(report.to_dict()),
)
signals.start()  # or mount signals.asgi_webhook() at the URL registered with Helix
```

## Packages in this repo

- **`helix_sdk`** -- core SDK (see Quick example below).
- **`helix_mcp_middleware`** -- Model Context Protocol integration, the same
  Phase 1 surface as `@helixid/mcp-middleware`:
  `helixid_mcp_middleware()` / `async_helixid_mcp_middleware()` gate every
  incoming tool call. A caller presents a KYA-OS request proof (MCP
  `_meta["org.kya-os/request-proof"]`, with its delegation chain at
  `_meta["org.kya-os/delegation-chain"]`), which the gate verifies in-process
  with `helix_sdk.verifier` (`verifier=LocalVerifierOptions(...)` or
  `create_local_verifier()`, story F-2; the Helix API is never asked), or an
  OAuth 2.1 bearer token. A bearer token sent with a proof is the proof's
  sender constraint (`cnf` fusion, L3). The Helix VP is no longer read.
  `tool_scopes` maps each tool to the scopes it needs and denies unlisted
  tools; then `minimum_level` (default `L3`), `tools[name]["minimum_level"]`
  and `l3_minus_satisfies_l3` set the Card level each tool demands (story
  C-C; a call below it raises `LevelError`, 401 `insufficient_user_authentication`
  with `derivedLevel` / `requiredLevel`); every decision goes to `audit_sink`
  (`create_helix_audit_sink()` writes to the HelixID audit log). Since KYA-OS
  story A-1 the log holds typed producer events (AAP-1 Recorded): each
  decision of a KYA-OS caller becomes `proof.verified` (verification code
  `KYAOS_PROOF_<level>`, `_CACHED` when a status was not read live; story C-C
  writes an L3 on an unfused proof as `L3_MINUS` and adds `_CNF_UNFUSED` for
  the `cnf` diagnostic) then `authorization.approved` / `authorization.denied`
  (reason `proof_level_insufficient` for a level refusal), a refused request
  proof `proof.rejected` by its first reason code, strictly validated,
  sequenced per source with `previousSourceEventDigest`, digested and posted
  to `POST /v1/audit-log/events`. For a tool call's whole lifecycle build an
  `McpAuditTrail` with `create_mcp_audit_trail(create_helix_audit_reporter(url,
  key), service_did)`, pass `audit.tool_audit_sink()` as `audit_sink`, and
  wrap each call in `with audit.begin_tool_call(tool_name)`,
  as `examples/mcp_order_management` does. No event holds tool arguments, a
  response, a token or a credential; an OAuth subject is a keyed commitment; tool
  names only with `include_tool_names=True`. The typed events themselves
  (`AuditTrail`, the strict validator, digests, SPEC 7.8 references, the
  evidence vault) are `helix_sdk.audit`.
  `oauth=` takes one trusted issuer or a list: `OAuthIssuerOptions(issuer,
  audience)` is enough (keys come from the issuer's metadata), or use the
  presets `entra()`, `auth0()`, `okta()`, `keycloak()`; opaque tokens are
  checked by RFC 7662 introspection at the one issuer you run.
  `to_http_error_response()` and `build_protected_resource_metadata()` give
  the 401 / 403 challenges and the RFC 9728 document. A runnable server is in
  [`examples/mcp_order_management`](examples/mcp_order_management).
  Install with the `mcp-middleware` extra:
  `pip install helixid-sdk-py[mcp-middleware]`.
- **`helix_langchain`** -- LangChain integration:
  `helix_id_tool_wrapper(tool, signer=..., audience=..., chain=...)` runs the
  tool with the agent's Signer, and inside it `sign_current_request(request)`
  returns the MCP request with a fresh request proof (and the chain) in
  `params._meta`. Tool input is untouched. Also scope-based tool filtering.
  Install with `pip install helixid-sdk-py[langchain]`.
- **`helix_crewai`** -- CrewAI integration, following the same pattern as
  `helix_langchain`. There is no CrewAI counterpart in `helix-sdk-js` --
  this is Python-only. Install with `pip install helixid-sdk-py[crewai]`.

Install everything at once with `pip install helixid-sdk-py[all]`.

### Audit delivery to the recorder (KYA-OS A-2, AAP-2 Chained)

Audit events go to the HelixID recorder (`POST /v1/audit/submissions`), which
assigns sequence, epoch, predecessor and time and signs a receipt. The server
never chooses any of those. The same surface as `@helixid/mcp-middleware`:

```python
audit = create_mcp_audit_trail(
    create_helix_audit_delivery(base_url, api_key, delivery="required"),
    service_did,
)
audit_tool_handlers(server)  # a FastMCP server, before its tools are registered
with audit.begin_tool_call(tool_name, credential=vp):
    ...  # each tool runs audited under this call
```

| `delivery` | What it means |
|---|---|
| `required` (default) | The intent's signed receipt is obtained before the handler runs; if it cannot be, the call answers `audit_delivery_failed` and the handler does not run. If the terminal append fails after the handler ran, the result is marked `_meta["org.kya-os/audit"] = {"status": "degraded", "reason": ...}` with `isError`. |
| `buffered` | Events go to a durable outbox (`outbox_dir`) keyed by `(sourceId, eventId)` and are delivered in the background, in order per source; the outbox survives a restart. An ephemeral outbox is refused at startup. |
| `best-effort` | Refused unless `accept_aap1=True`: delivery is attempted and failures are only reported (AAP-1, capture only). |

The tenant is the producer (the service DID) unless `tenant_ref` says
otherwise; each tenant DID has its own ledger. `audit_tool_handlers` takes the
call explicitly, as the JS one does, or uses the tool call
`begin_tool_call` opened in the current context, since a Python server is
usually built once. `run_audited_tool` / `async_run_audited_tool` wrap a
single handler. `HelixClient.get_audit_log(cursor=...)` reads the log one
page at a time (`{"items": [...], "nextCursor": ...}`). The order-management
sample reads `AUDIT_DELIVERY`, `AUDIT_OUTBOX_DIR` and `AUDIT_ACCEPT_AAP1`.

## Quick example

```python
from helix_sdk import kyaos

# The agent: its own key, read from HELIX_SIGNING_KEY at each signature.
signer = kyaos.EnvSigner("did:web:agent.example.com")
request = kyaos.with_request_proof(
    {"name": "lookup_order", "arguments": {"orderId": "ORD-1001"}},
    signer,
    audience="did:web:orders.example.com",  # the service's DID, from its Entity Card
    chain=hops,                              # the delegation chain, root to leaf
)
# send request["params"] as the MCP tools/call params

# The service: helix_mcp_middleware verifies it in-process.
from helix_mcp_middleware import LocalVerifierOptions, MCPMiddlewareOptions, helixid_mcp_middleware

gate = helixid_mcp_middleware(MCPMiddlewareOptions(
    verifier=LocalVerifierOptions(service_did="did:web:orders.example.com"),
    tool_scopes={"lookup_order": ["orders:read"]},
    tools={"lookup_order": {"minimum_level": "L2"}},  # default L3
))
caller = gate.authorize({"name": name, "input": args, "_meta": params["_meta"], "request": rpc_request})
```

`examples/request_proof_demo.py` runs the sign / verify / replay / tamper cycle offline.

## KYA-OS session, replay store and response proof (`helix_mcp_middleware`, story L2-A)

The Python twin of `@helixid/mcp-middleware`'s KYA-OS layer, with the same wire format, error codes and replay-store
keys, so JS and Python instances serve one DID side by side:

```python
from helix_sdk import kyaos
from helix_mcp_middleware import KyaOsOptions, create_kyaos

kya = create_kyaos(KyaOsOptions(
    signer=kyaos.EnvSigner("did:web:mcp.example.com", env_var="SERVICE_SIGNING_KEY"),  # the key stays in the environment
    public_origin="https://mcp.example.com",
))
# The handshake tool: await kya.handshake_tool_result(args). Every other tool call:
started = await kya.start({"name": name, "arguments": args, "_meta": meta}, authorize=lambda: gate.authorize(tool_call))
if started.outcome == "denied":
    ...  # to_http_error_response(started.error, metadata_url, proof=started.proof)
result = await started.finish(await handler(started.arguments))  # the result with _meta["org.kya-os/response-proof"]
```

The client side is `helix_sdk.kyaos` (`create_handshake_request()`, `verify_response_proof()`, which recomputes both
hashes against the server DID). The replay store is the one the environment names unless `nonce_store=` is passed
(`nonce_store_from_env()`):

| Variable | Values | Default |
|---|---|---|
| `KYAOS_NONCE_STORE` | `memory`, `redis`, `dynamo` | `memory` |
| `KYAOS_REDIS_URL` | `redis://` or `rediss://` URL; required for `redis` | |
| `KYAOS_NONCE_KEY_PREFIX` | Redis key prefix | `kyaos:nonce:` |
| `KYAOS_DYNAMO_TABLE` | table name; required for `dynamo` | |
| `KYAOS_DYNAMO_KEY_ATTRIBUTE` | partition key attribute (string) | `pk` |
| `KYAOS_DYNAMO_TTL_ATTRIBUTE` | the table's TTL attribute (Unix seconds) | `expiresAt` |
| `KYAOS_DYNAMO_REGION` | AWS region | boto3's own |
| `KYAOS_DYNAMO_ENDPOINT` | endpoint URL, for DynamoDB Local | boto3's own |

AWS credentials come from boto3's standard chain, never from these variables. The clients are optional extras,
imported only when chosen: `pip install 'helixid-sdk-py[redis]'` (redis-py, used through `redis.asyncio`) and
`pip install 'helixid-sdk-py[dynamo]'` (boto3, called from a worker thread). It fails closed: an unknown store, a
missing required variable or a missing package raises `NonceStoreConfigError` when the runtime is built, and nothing
falls back to memory. One startup line on the `helix_mcp_middleware.kyaos` logger names the store without secrets (a
Redis password is shown as `***`); memory with `ENV` or `NODE_ENV` set to `production` also warns that it covers one
process only.

## KYA-OS signed `needs_authorization` and resume (story L3-E)

Server side (`helix_mcp_middleware`): when a caller is identified but its delegation does not cover the tool's scopes, the gate answers with the SPEC §9.2 challenge instead of a plain 403: `{"error": "needs_authorization", "message", "authorizationUrl", "resumeToken", "expiresAt", "scopes", "display"?}`. Under the KYA-OS runtime it is the call's tool result, signed with `outcome: needs_authorization` and a `responseHash` over the whole result, so `authorizationUrl` is covered by the service signature.

```python
from helix_mcp_middleware import MCPMiddlewareOptions, NeedsAuthorizationOptions, create_needs_authorization

needs_authorization = create_needs_authorization(NeedsAuthorizationOptions(
    authorization_url=lambda c: f"https://consent.example/authorize?tool={c.tool}",
    ttl_seconds=600,              # resume-token lifetime
    # store: default follows KYAOS_NONCE_STORE (resume_token_store_from_env: Redis on KYAOS_REDIS_URL, else memory)
    authorizer=verify_delegation, # the seam stories F-2 and L3-H implement; default refuses every retry
    audit_sink=audit_sink,        # every challenge: AUTHZ_DENIED, reason "needs_authorization"
))
options = MCPMiddlewareOptions(..., needs_authorization=needs_authorization)
```

The resume token is opaque, bound to the agent, tool and scopes, single-use and gone at `expiresAt`; a retry carries it as the `_kyaos_resume` control argument and the new DelegationCredential as `_kyaos_delegation`. Completing consent alone never authorises the call. With `async_helixid_mcp_middleware` the store, authorizer and audit sink may be async. Client side (`helix_sdk.needs_authorization`): `handle_needs_authorization(response, service_did, resolve_did, request=...)` verifies the challenge's proof, recomputing both hashes, before it surfaces the URL; `retry_with_resume(resume_token, hop, call=..., send=...)` retries with the token and the credential.

## The `/.well-known/mcp` discovery document (`helix_mcp_middleware`, story L1-D)

`create_well_known_mcp()` builds the KYA-OS discovery document from config, validates it against the vendored
`well-known-mcpi.json` schema at startup (raising `WellKnownMcpError` with the schema's complaints) and serves it over
ASGI; for the same config it is byte for byte the document `@helixid/mcp-middleware`'s `createWellKnownMcp()` serves.

```python
from helix_mcp_middleware import create_well_known_mcp

well_known = create_well_known_mcp(
    public_origin="https://mcp.example.com",   # the origin agents connect to; required, never the bind address
    server_did="did:web:mcp.example.com",       # did:web or did:key; required
    tools_endpoint="/mcp",                       # path at public_origin, or an absolute URL there
    kyaos=kya.describe(),                        # proofs, the handshake and the skew from the L2-A layer
    status_list_credential="https://mcp.example.com/credentials/status/1",  # optional
    capabilities={"delegation": False, "statusList": False, "crisp": False},  # each true only while that feature is on
)

async def app(scope, receive, send):
    if await well_known.handle(scope, receive, send):  # GET / HEAD /.well-known/mcp; False for anything else
        return
    ...
# any other host: well_known.respond() is (status, headers, body)
```

`enabled=False` answers 404. Validation needs `jsonschema` (in the `mcp-middleware` and `all` extras); the `uri`,
`uri-reference` and `email` formats are checked with ajv-formats' own expressions, so both languages refuse the same
documents with the same messages. Route `/.well-known/mcp` at your origin root to the middleware: helix-sdk-js's
`mcp-middleware/docs/well-known.md` has the nginx, ALB and API Gateway rules and the `public_origin` rule. The client
side is `helix_sdk.kyaos.fetch_well_known_mcp(origin)` / `read_well_known_mcp(document)`, which fill
`clockSkewSeconds` with 120 when absent and resolve relative endpoints, for `create_handshake_request()` timing and
`verify_response_proof(..., skew_seconds=document["clockSkewSeconds"])`.

## Examples

See `examples/`:

- `request_proof_demo.py` -- an agent signs one MCP call with
  `kyaos.with_request_proof()` and a service verifies it in-process in the
  section 11.2 order; a replay, another body and another service are refused.
  Runs offline:

```bash
python examples/request_proof_demo.py
```

## CLI

Platform-operator workflows (DID/wallet/status-list/VC lifecycle) are covered
by `helix-sdk-js`'s `cli` package -- the CLI has a single canonical
implementation rather than one per SDK language.

The one exception is custody (KYA-OS story F-3): `helix-custody init`,
`helix-custody activate` and `helix-custody custody take` (`take` alone also
works; or `python -m helix_sdk.custody`) do and print what `helix init`,
`helix activate` and `helix custody take` do, with the same options, for
Python-only hosts. `--json` prints the result as JSON instead. They exit 0
when the command ran, an agent still waiting for its documents included, and
1 with the error on stderr. The same steps are functions: `helix_init`,
`activate_agent`, `change_to_self_custody`.

With own hosting you do not have to run `activate`: Helix re-checks an agent
waiting for its documents in the background and activates it once they are
live.

A self-custody agent's key is generated on its host and never sent. A
custodial agent signs through `HelixCustodialSigner`, which calls the Helix
API. Both are Signers, so `helix_sdk.verifier.sign_request_proof` and `sign_jws` work
the same with either. Custodial agents are labelled `custody: helix` and are
not counted in KYA-OS conformance claims; their proofs still verify.

## Testing

```bash
pip install -e ".[dev,all]"
pytest
```

`pytest` always runs with coverage (`[tool.pytest.ini_options]` in
`pyproject.toml`) and fails under 60% -- the measured baseline as of
2026-09-03, not a target. `helix-sdk-js`/`helix-api` enforce 90%
lines/statements, 85% branches, 90% functions; closing this gap (some
modules, like `did.py`, currently have no direct unit tests at all) is
real follow-up work, not something this tooling change did on its own.

- `tests/test_golden_vectors.py` -- cross-language crypto parity (no network).
- `tests/test_wallet.py` -- `AgentWallet` encrypted persistence, credential
  storage/queries, and a local-signing round trip. (`delegate()`
  and its mocked-HTTP tests were removed along with the rest of agent
  self-custody.)
- `tests/test_mcp_middleware.py` -- the middleware's Phase 1 cases (credentials,
  scopes, JWT / introspection / several issuers / discovery / presets, HTTP
  challenges, audit); `tests/test_mcp_order_management_example.py` runs the
  sample behind the MCP SDK's HTTP transport (Python 3.10+).
- `tests/test_framework_adapters.py` -- exercises `helix_mcp_middleware`,
  `helix_langchain`, and `helix_crewai` against the real installed
  `langchain-core` and `crewai` packages (not mocks of them), so a real
  interface drift in either framework would fail these tests. Skips
  gracefully on Python < 3.10, since both frameworks require it.

There is currently no automated **live** integration test against a real
`helix-api` instance in this repo's CI (see Known gaps) -- if you have a
running instance, you can exercise the real network path with the
delegation example above.

## Known gaps

- **No live network integration test yet.** The mocked tests above verify
  the SDK's logic faithfully, but nothing here has been run against a real,
  live `helix-api` process end-to-end. (The sandbox used to build this SDK
  could not start one -- `helix-api`'s `server.ts` imports the generated
  Prisma client unconditionally, even in SQLite storage mode, and `prisma
  generate` needs network access to `binaries.prisma.sh`, which was outside
  that environment's egress allowlist. This is a sandbox-only limitation,
  not a code issue, and shouldn't block real CI or local development where
  Prisma can actually run.) Running the two example scripts against a real
  instance is the recommended way to close this gap.
- **`HttpAdapter` is synchronous** (built on `requests`), unlike
  `helix-sdk-js`'s async `fetch`-based adapter. This was a deliberate v0
  choice -- most Python agent/automation call sites are synchronous -- not
  an oversight; an async variant can be added later without breaking this
  one.
- **No `did:hedera` package yet.** DID resolution generally is always an
  API call in this architecture, so
  this is really about offline Hedera anchoring specifically, which
  `helix-sdk-js`'s `cli` package supports via a separate `did-hedera`
  package this repo hasn't ported. Since the CLI itself is JS-only, this gap only matters if this SDK's
  own local-signing primitives grow a `did:hedera` creation path.
- **No `widget` package** (helix-sdk-js's browser-embeddable consent
  widget has no obvious Python equivalent and hasn't been attempted).
- **`HelixIDCallbackHandler` in `helix_langchain` is a no-op.** LangChain
  Python's `on_tool_start` callback is a notification hook, not an
  interceptor. Request signing happens in `helix_id_tool_wrapper()`, which
  hands the tool `sign_current_request()`; the callback handler is kept only
  for observability use. (The JS SDK has dropped its callback form,
  `HelixIDMiddleware`, entirely.)
- **Version numbering does not yet track `helix-sdk-js`'s version.** This SDK's version should track the JS
  SDK's; that mapping strategy hasn't been decided yet, so this starts at
  `0.1.0` independently.

## The HelixID ecosystem

| Repository | What it is |
|---|---|
| [helixid](https://github.com/helixid/helixid) | HelixID API — the issuer and verifier service |
| [helix-core](https://github.com/helixid/helix-core) | `@helixid/core` — crypto, schemas, resolver, verification primitives |
| [helix-sdk-js](https://github.com/helixid/helix-sdk-js) | JS/TS SDK, CLI, LangChain + MCP middleware, consent widget |
| **helix-sdk-py** — you are here | `helixid-sdk-py` — the Python SDK |
| [helix-console](https://github.com/helixid/helix-console) | Operator Console SPA |
| [helix-wiki](https://github.com/helixid/helix-wiki) | Source for [docs.helixid.dev](https://docs.helixid.dev) |

---

## License

Apache-2.0
