# helixid-sdk-py

Python SDK for [HelixID](https://github.com/helixid/helixid) -- decentralized
agent identity via DID/VC standards (did:hedera, did:key, did:web), delegation,
and Verifiable Presentation verification.

This is the Python counterpart to
[`helix-sdk-js`](https://github.com/helixid/helix-sdk-js), following the same
**SDK-API-only** architecture (see `docs/proposal-sdk-api-only.md` and
`docs/proposal-retire-core-package.md` in the `helixid/helixid` repo): every
SDK, in every language, depends only on the HelixID API -- never on a shared
"core" package -- except for private-key operations that must stay local:
keygen, sign, canonical-hash, `VPBuilder.sign()`, and `self_issue_vc()` (a
dev-only flow). Verification, delegation-VC construction, DID resolution, and
status checks are all API calls made through `HelixClient`.

## Status: v0.1.0, early

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

The local-signing primitives (`keys.py`, `vp_crypto.py`, `proof.py`,
`vp_builder.py`) are verified **byte-for-byte** against the same
`fixtures/golden-vectors/*.json` fixtures that `helix-sdk-js` and
`helix-core` assert against -- same private key, same payload, same
signature, same base58btc-encoded proof value, in every language. See
`tests/test_golden_vectors.py` and `fixtures/golden-vectors/README.md`.

If you regenerate the vectors in `helix-server` (`pnpm generate:golden-vectors`),
re-copy the three JSON files here too, the same way `helix-sdk-js` does.

## Packages in this repo

- **`helix_sdk`** -- core SDK (see Quick example below).
- **`helix_cli`** -- `helix` command-line tool for platform operators
  (DID/wallet/status-list/VC lifecycle, fully offline except `did:hedera`
  anchoring, which is not yet ported -- see Known gaps). Install with the
  `cli` extra: `pip install helixid-sdk-py[cli]`.
- **`helix_mcp`** -- Model Context Protocol integration: server-side VP
  verification middleware and client-side VP attachment. No extra
  dependencies beyond the core SDK.
- **`helix_langchain`** -- LangChain integration: a tool wrapper that
  injects a signed VP into every tool call, plus scope-based tool
  filtering. Install with `pip install helixid-sdk-py[langchain]`.
- **`helix_crewai`** -- CrewAI integration, following the same pattern as
  `helix_langchain`. There is no CrewAI counterpart in `helix-sdk-js` --
  this is Python-only. Install with `pip install helixid-sdk-py[crewai]`.

Install everything at once with `pip install helixid-sdk-py[all]`.

## Quick example

```python
from helix_sdk import AgentWallet, HelixClient, VPBuilder, delegate

client = HelixClient("https://your-helix-api.example.com")

# ... onboard an agent (see examples/agent_delegation_demo.py for the full
# enrollment-token -> challenge -> onboard flow) ...

sub_agent_vc = delegate(
    delegator_wallet,
    to=sub_agent_wallet.get_did(),
    scopes=["read:orders"],
    expires_in=3600,
)

vp = VPBuilder(
    credentials=[sub_agent_vc],
    holder_did=sub_agent_wallet.get_did(),
    target_service="https://api.example.com/v1/tools/orders",
).sign(sub_agent_wallet.get_private_key_hex(), f"{sub_agent_wallet.get_did()}#key-1")

result = client.verify_vp(vp)
print(result["valid"], result["effectiveScopes"])
```

## Examples

See `examples/`:

- `agent_delegation_demo.py` -- onboards a delegator and a sub-agent,
  delegates a scope subset via `delegate()`, builds and signs a VP, verifies
  it via the API, and shows a delegation-depth violation being rejected.
- `verify_vp_demo.py` -- onboards an agent, builds/signs/verifies a VP,
  exercises `check_scope()`/`require_scope()`, then revokes the VC and shows
  the next verification attempt fail with `VC_REVOKED`.

Both require a running `helix-api` instance:

```bash
HELIX_API_URL=http://127.0.0.1:3579 \
HELIX_ADMIN_API_KEY=your-admin-key \
python examples/agent_delegation_demo.py
```

These are **not** ports of `helix-server/examples/delegation-demo.ts` --
that file imports `buildDelegationVC` from the retired `@helixid/core`
package and is a known, not-yet-rewritten broken example. These scripts
instead follow the current, correct pattern used by helix-api's own live
integration test (`tests/live/agent-delegation.live.integration.test.ts`)
-- `delegate()` + the prepare/finalize API, not a local `buildDelegationVC()`.

## CLI

The `helix` command line tool (install with `pip install helixid-sdk-py[cli]`)
covers the same platform-operator workflows as helix-sdk-js's `cli`
package -- entirely offline, no running `helix-api` instance required:

```bash
export HELIX_WALLET_PASSPHRASE=your-passphrase

# Create a did:web issuer wallet + its initial status list
helix did create --method web --domain example.com --wallet issuer.json

# Create a did:key agent wallet
helix did create --method key --wallet agent.json

# Issue an agent credential
helix vc issue --agent-did did:key:z6Mk... --scopes read:orders,write:orders \
  --expires 90d --status-list status-list.json \
  --base-url https://example.com/.well-known/helix-status-list.json \
  --wallet issuer.json --output agent-vc.json

# Revoke it
helix revoke --vc-id <vc-id> --status-list status-list.json --wallet issuer.json

# Self-issue a dev-only credential directly into an agent wallet
helix vc self-issue --scopes read:orders --expires 24h --wallet agent.json

# Inspect a wallet (never prints the private key)
helix wallet inspect --wallet agent.json
```

`helix did create --method hedera` is not yet implemented in this Python
CLI (the `did-hedera` package hasn't been ported -- see Known gaps) and
fails with a clear error rather than silently producing an unanchored
wallet.

## Testing

```bash
pip install -e ".[dev,all]"
pytest
```

- `tests/test_golden_vectors.py` -- cross-language crypto parity (no network).
- `tests/test_delegation_flow_mocked.py` -- exercises the full
  `delegate()` / `VPBuilder` / wallet flow against a mocked HTTP layer that
  faithfully reproduces helix-api's real prepare/finalize contract,
  including asserting the delegator's private key never appears in any
  outgoing request body.
- `tests/test_langchain_crewai.py` -- exercises `helix_mcp`,
  `helix_langchain`, and `helix_crewai` against the real installed
  `langchain-core` and `crewai` packages (not mocks of them), so a real
  interface drift in either framework would fail these tests. Skips
  gracefully on Python < 3.10, since both frameworks require it.
- `tests/test_cli.py` -- runs the actual `helix` command tree end-to-end
  via Click's `CliRunner`, against real wallet and status-list files on
  disk (did:web/did:key creation, VC issuance, revocation, self-issuance,
  wallet inspection, and the relevant error paths).

There is currently no automated **live** integration test against a real
`helix-api` instance in this repo's CI (see Known gaps) -- if you have a
running instance, you can exercise the real network path with the two
example scripts above.

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
- **No `did:hedera` package yet.** `helix_cli`'s `did create --method
  hedera` fails with a clear "not yet supported" error rather than
  producing an unanchored wallet. DID resolution generally is always an
  API call in this architecture (per `docs/proposal-sdk-api-only.md`), so
  this is really about offline Hedera anchoring specifically, which the JS
  CLI supports via a separate `did-hedera` package this repo hasn't ported.
- **No `widget` package** (helix-sdk-js's browser-embeddable consent
  widget has no obvious Python equivalent and hasn't been attempted).
- **`HelixIDCallbackHandler` in `helix_langchain` cannot rewrite tool
  input before execution** -- documented in its own docstring. LangChain
  Python's `on_tool_start` callback is a notification hook, not an
  interceptor (unlike the JS SDK's bespoke `RunnableConfigLike.
  handleToolStart`, which really can mutate input first). Real VP
  injection happens through `helix_id_tool_wrapper()` instead; the
  callback handler is offered for observability/wallet-warming only. This
  is a genuine LangChain Python API constraint, not an incomplete port.
- **Version numbering does not yet track `helix-sdk-js`'s version.** Per
  `docs/decision-sdk-py-scope.md`, this SDK's version should track the JS
  SDK's; that mapping strategy hasn't been decided yet, so this starts at
  `0.1.0` independently.

## License

Apache-2.0
