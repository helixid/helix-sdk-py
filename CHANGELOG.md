# Changelog

## [3.1.0](https://github.com/helixid/helix-sdk-py/compare/helixid-sdk-py-v3.0.0...helixid-sdk-py-v3.1.0) (2026-11-26)


### Features

* **custody:** keep a final card.json on activation; say Helix activates on its own ([93d53e5](https://github.com/helixid/helix-sdk-py/commit/93d53e5e38aff7127d04940aae52bf6c27726539))
* **custody:** keep the final card.json; Helix activates on its own ([3da7dd2](https://github.com/helixid/helix-sdk-py/commit/3da7dd24310de907bb09a6df5da0794ad3afc838))

## [3.0.0](https://github.com/helixid/helix-sdk-py/compare/helixid-sdk-py-v2.1.0...helixid-sdk-py-v3.0.0) (2026-11-26)


### ⚠ BREAKING CHANGES

* VP-based verification and the delegate-authority APIs are removed; agents sign each call with a KYA-OS request proof.

### Features

* KYA-OS conformance ([ada0f04](https://github.com/helixid/helix-sdk-py/commit/ada0f046841ad8f1e81ac0d6f6a755bea9d88476))
* **mcp-middleware:** MCP SDK 2, one-line ASGI gate, parity with sdk-js ([2d22454](https://github.com/helixid/helix-sdk-py/commit/2d2245452b9ceba7d1b75ce636379cd86373ffbe))


### Documentation

* services bind the Helix issuer to its status list (Harish's pick (i)) ([c70efcb](https://github.com/helixid/helix-sdk-py/commit/c70efcbc184ab69b7310238c1e4d2fe04e2937b9))

## [2.1.0](https://github.com/helixid/helix-sdk-py/compare/helixid-sdk-py-v2.0.0...helixid-sdk-py-v2.1.0) (2026-11-15)


### Features

* **mcp-middleware:** Phase 1 auth gate, OAuth, per-tool scopes, audit and order-management sample ([06c5797](https://github.com/helixid/helix-sdk-py/commit/06c579779497a8df17b7894c5849b55f07b75669))
* **mcp-middleware:** Phase 1 auth gate, OAuth, per-tool scopes, audit and order-management sample ([6066c03](https://github.com/helixid/helix-sdk-py/commit/6066c03a6fd74347bdd72af71af7cb5cb60c9255))


### Bug Fixes

* **mcp-middleware:** review fixes for the Phase 1 port ([e97b103](https://github.com/helixid/helix-sdk-py/commit/e97b103e8e361734e89c113212f6ee8a21828879))

## [2.0.0](https://github.com/helixid/helix-sdk-py/compare/helixid-sdk-py-v1.0.0...helixid-sdk-py-v2.0.0) (2026-10-27)


### ⚠ BREAKING CHANGES

* issue_grant, revoke_grant, prepare_grant, finalize_grant and IssuerKeyMaterial are removed. Grants are now issued server-side via issue_service_delegation_grant and VPs are sent in the X-Helix-VP header or MCP _meta["x-helix-vp"].

### Features

* SDK revamp — VP transport, client updates, audit fixes ([#11](https://github.com/helixid/helix-sdk-py/issues/11)) ([0ca7d35](https://github.com/helixid/helix-sdk-py/commit/0ca7d3516aedbcfa54042e188dceca4c025994e2))

## [1.0.0](https://github.com/helixid/helix-sdk-py/compare/helixid-sdk-py-v0.1.1...helixid-sdk-py-v1.0.0) (2026-09-09)


### ⚠ BREAKING CHANGES

* HelixClient no longer reads HELIX_API_URL from the environment; pass base_url explicitly to override the hosted default.

### Features

* default HelixClient's enterprise base_url to the hosted API ([98ba09b](https://github.com/helixid/helix-sdk-py/commit/98ba09b5d1cee9576ccc23263712f1a5ecc6e66d))

## [0.1.1](https://github.com/helixid/helix-sdk-py/compare/helixid-sdk-py-v0.1.0...helixid-sdk-py-v0.1.1) (2026-09-09)


### Bug Fixes

* **ci:** gate mcp dependency behind python_version &gt;= 3.10 ([7c5d547](https://github.com/helixid/helix-sdk-py/commit/7c5d5478b2ee76bc458326a109f06e7c3fa70f0a))
* **release:** use generic extra-files updater for __init__.py version ([#6](https://github.com/helixid/helix-sdk-py/issues/6)) ([8769e31](https://github.com/helixid/helix-sdk-py/commit/8769e315ff3c5009283449604618358af4882339))


### Documentation

* add standard contributor, security and PR docs ([94facbf](https://github.com/helixid/helix-sdk-py/commit/94facbfd80f8f77af7ca9a39ec7eed068336e76c))
* add standard contributor, security and PR docs ([542878b](https://github.com/helixid/helix-sdk-py/commit/542878b24999ab399ea8552c4adef75f7d5be9f1))
