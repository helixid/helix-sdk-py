# Contributing to the HelixID Python SDK

This repository is `helixid-sdk-py` — the Python SDK, plus the LangChain,
CrewAI, and MCP middleware.

This is the code that runs inside other people's agents and services — it
holds wallets and builds presentations — so correctness and clear public
APIs matter more than internal convenience.

> **New to HelixID?** Read
> [docs.helixid.dev](https://docs.helixid.dev) first — it covers the concepts
> (DIDs, verifiable credentials, the two-issuer model, delegation, revocation)
> that the rest of this document assumes. This file is the authoritative
> process for *this* repository; the docs site is the orientation.

---

## Open-Source Scope

This repository is Apache-2.0 and public. It is the Python counterpart to
[`helix-sdk-js`](https://github.com/helixid/helix-sdk-js), and deliberately mirrors
its behaviour: where the two disagree about verification semantics, that is a bug
in one of them.

If you are adding something the JS SDK already has, match its naming and shape
unless there is a Python reason not to — and say so in the PR when you diverge.

---

## Ways to Contribute

1. **Framework middleware** — integrations for additional agent frameworks.
   Follow the pattern in `src/helix_langchain/` and `src/helix_crewai/`.
2. **Parity gaps** — behaviour the JS SDK supports and this one does not.
3. **Typing** — improving the public surface's type hints.
4. **Bug reports** with a minimal reproduction.

---

## Before You Start

**Open a Discussion or Issue first** for any non-trivial change. Trivial means: typos, obviously incorrect code, a missing test for existing behavior, a small doc improvement. Anything else — new features, new dependencies, API changes, performance optimizations that change behavior, new packages — needs a design sketch and sign-off from a maintainer before a PR lands.

This saves time on both sides. A rejected PR after two weeks of work is a worse outcome than a fifteen-minute design conversation.

---

## Development Setup

### Prerequisites

- Python ≥ 3.9 (`requires-python = ">=3.9"`)
- Git

Some optional extras need a newer interpreter — the MCP middleware is gated
behind Python ≥ 3.10.

### Clone and Bootstrap

```bash
git clone https://github.com/helixid/helix-sdk-py.git
cd helix-sdk-py
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,all]"
```

`[dev]` brings the test tooling; `[all]` brings every optional integration
(`mcp-middleware`, `langchain`, `crewai`), which is what CI installs.

### Run Tests

```bash
pytest              # the full suite, with coverage
pytest -v           # what CI runs
pytest tests/<file> # a single file while iterating
```

Coverage is configured in `pyproject.toml` and reports across `helix_sdk`,
`helix_langchain`, `helix_crewai`, and `helix_mcp_middleware`.

---

## Repository Structure

```
helix-sdk-py/
├── src/
│   ├── helix_sdk/             # the SDK itself
│   ├── helix_langchain/       # LangChain adapter
│   ├── helix_crewai/          # CrewAI adapter
│   └── helix_mcp_middleware/  # MCP verification middleware
├── tests/
├── fixtures/                  # shared test fixtures
└── examples/                  # runnable snippets
```

`helix_sdk` is the highest-stakes: it is the public API every consumer builds
against.

The rest of the system lives in separate repositories — see
[Project Structure](https://docs.helixid.dev/get-started/project-structure).

---

## Branching and Commits

### Branch Names

```
<type>/<short-kebab-description>

feat/did-web-resolver
fix/statuslist-cache-invalidation
docs/delegation-tutorial
```

### Conventional Commits (required)

We use [Conventional Commits](https://www.conventionalcommits.org/). The release tooling parses commit messages to generate changelogs and bump versions.

```
<type>(<scope>): <summary>

[optional body]

[optional footer(s)]
```

Allowed types: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `build`, `ci`, `chore`, `revert`.

Scope is the package or area: `core`, `api`, `sdk-js`, `mcp`, `langchain`, `cli`, `docs`.

Examples:

```
feat(sdk): add did:web resolver with HTTPS pinning

fix(api): invalidate status-list cache after credential revocation

perf(sdk): avoid re-parsing JWS on repeated verification

BREAKING CHANGE: verifyPresentation now returns DelegationChain,
not string[]. Migration: use result.delegationChain.dids.
```

**Breaking changes** must include a `BREAKING CHANGE:` footer and a migration note in the PR description.

### Sign Your Commits (DCO)

Every commit must be signed off under the [Developer Certificate of Origin](https://developercertificate.org/). We deliberately use DCO instead of a CLA — it's a lightweight attestation with no corporate-legal review tax. By signing off, you affirm that you have the right to submit the work under Apache 2.0.

```bash
git commit -s -m "feat(sdk): add did:web resolver"
```

This appends a `Signed-off-by: Your Name <your.email@example.com>` line. Our CI rejects PRs missing DCO on any commit. If you forget, rebase with `git rebase --signoff`.

---

## Pull Requests

### Before Opening a PR

- [ ] Rebase on the latest `main`
- [ ] Run `pytest` locally and pass
- [ ] Add or update tests — no untested code merges
- [ ] Update docs if you changed public API
- [ ] PR title (or commits) follows [Conventional Commits](https://www.conventionalcommits.org/) — release-please parses it for versioning/changelog
- [ ] Every commit is DCO-signed

### PR Description

Use this template — it mirrors what reviewers and release notes need:

```markdown
## What
<short summary of the change>

## Why
<motivation, linked issue, relevant context>

## How
<implementation approach, trade-offs considered, alternatives rejected>

## Testing
<how you verified this works — unit, integration, manual scenarios>

## Risk & Rollback
<what could break, how to revert if this ships bad>

## Breaking Changes
<none | description + migration path>

Closes #<issue>
```

### Review Expectations

- Two maintainer approvals required for changes in `helix-core` or `helix-sdk-js`
- One maintainer approval for everything else
- Reviewers respond within 3 business days — if silent longer, ping in Discussions
- We squash-merge by default; commit history on `main` is one commit per PR

### Merging

Only maintainers merge. Do not merge your own PR even if you have permissions.

---

## Coding Standards

### Python

- Type hints on every public function and method. The SDK is consumed by people
  relying on their editor to tell them what a call returns.
- Keep the public surface explicit — prefer `__all__` over implicit exports.
- Match the JS SDK's naming where a concept exists in both, translated to
  `snake_case` (`maxDelegationDepth` → `max_delegation_depth`).

### Cryptography and Security-Sensitive Code

- Never hand-roll primitives. Use the vetted libraries already in the dependency tree.
- Wallet code must never log or serialize key material — that includes exception
  messages and tracebacks, which are easy to leak by accident in Python.
- Never `pickle` or `eval` anything derived from a credential, DID document, or
  status list.
- Changes to verification or presentation-building require a second maintainer
  review and a threat-model note in the PR.

### Testing

- Tests live in `tests/`, mirroring the `src/` package layout.
- A bug fix should come with the test that would have caught it.
- `pytest` must pass before you open a PR.

---

## Security Disclosure

**Do not open public issues for security vulnerabilities.** Use one of:

- Email `hello@dgverse.in`
- [GitHub Security Advisory](https://github.com/helixid/helix-sdk-py/security/advisories/new) (private)

We acknowledge within 48 hours, triage within 7 business days, and practice coordinated disclosure with a default 90-day embargo. Full scope, safe-harbor terms, and response policy: [`SECURITY.md`](SECURITY.md).

---

## Release Process

`helixid-sdk-py` is published to PyPI as a **public package**, versioned with
[release-please](https://github.com/googleapis/release-please) — the closest
Python equivalent of the changesets flow `helix-core`/`helix-sdk-js` use.

Use [Conventional Commits](https://www.conventionalcommits.org/) in your PR title
or commits; release-please parses them to decide the next version and to write
`CHANGELOG.md`. On every push to `main` it opens/updates a
`chore(main): release X.Y.Z` PR that bumps `pyproject.toml` and
`src/helix_sdk/__init__.py`'s `__version__`. Nothing is published until a
maintainer merges that PR — merging tags the release and triggers
`.github/workflows/release.yml`'s publish job, which builds and uploads to PyPI.

Until the first PyPI release ships, or as a fallback, consumers can still install
straight from this repository:

```bash
pip install "helixid-sdk-py @ git+https://github.com/helixid/helix-sdk-py"
```

Extras work the same way — for example
`"helixid-sdk-py[mcp-middleware] @ git+https://github.com/helixid/helix-sdk-py"`.

---

## Community and Code of Conduct

- **Discussions:** [github.com/helixid/helixid/discussions](https://github.com/helixid/helixid/discussions) — design questions, use cases, show-and-tell
- **Issues:** [github.com/helixid/helixid/issues](https://github.com/helixid/helixid/issues) — bugs and concrete feature requests
- **Security:** `hello@dgverse.in`
- **General contact:** `hello@dgverse.in`

We follow the [Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). Short version: be respectful, assume good faith, keep technical debate on technical merits, and escalate conduct concerns to `hello@dgverse.in`.

---

## Licensing of Contributions

Contributions are licensed under [Apache License 2.0](LICENSE), same as the project. DCO sign-off on each commit is the full legal attestation — no CLA, no separate agreement, no surprise relicensing. See the DCO section above.

---

## Quick Reference

| Task | Command |
|---|---|
| Create a venv | `python -m venv .venv && source .venv/bin/activate` |
| Install (dev + all extras) | `pip install -e ".[dev,all]"` |
| Test | `pytest` |
| Test (verbose, as CI) | `pytest -v` |
| Single file | `pytest tests/<file>` |
