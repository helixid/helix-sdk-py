# Changelog

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
