# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
HTTP adapter, ported from helix-sdk-js's src/http/HttpAdapter.ts.

Synchronous (uses `requests`), unlike the JS side's async fetch -- this is
a deliberate v0 design choice for the Python SDK's first release rather
than a parity gap: most Python agent/automation call sites are
synchronous, and an async variant can be added alongside this one later
without breaking callers, the same way helix-sdk-js could add a sync
wrapper without removing its async API.
"""

from __future__ import annotations

from typing import Any, Optional

import requests

from .errors import map_api_error


class HttpAdapter:
    def __init__(self, base_url: str, admin_api_key: Optional[str] = None, timeout: float = 30.0) -> None:
        self._base_url = base_url[:-1] if base_url.endswith("/") else base_url
        self._admin_api_key = admin_api_key
        self._timeout = timeout

    def has_admin_api_key(self) -> bool:
        return bool(self._admin_api_key)

    def get(self, path: str) -> Any:
        return self._request("GET", path)

    def post(self, path: str, body: Optional[Any] = None) -> Any:
        return self._request("POST", path, body)

    def delete(self, path: str) -> Any:
        return self._request("DELETE", path)

    def _request(self, method: str, path: str, body: Optional[Any] = None) -> Any:
        url = path if path.startswith("http") else f"{self._base_url}{path}"
        headers = {}
        if body is not None:
            headers["content-type"] = "application/json"
        if self._admin_api_key:
            headers["x-admin-api-key"] = self._admin_api_key

        response = requests.request(
            method, url, json=body if body is not None else None, headers=headers, timeout=self._timeout
        )

        if response.status_code == 204:
            return {}

        try:
            data = response.json()
        except ValueError:
            data = {}

        if not response.ok:
            raise map_api_error({**(data if isinstance(data, dict) else {}), "status": response.status_code})
        return data
