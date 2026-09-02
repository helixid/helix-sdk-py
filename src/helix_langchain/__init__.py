# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
helix_langchain -- LangChain integration for HelixID, mirroring
helix-sdk-js's langchain package (adapted to LangChain Python's actual
tool/callback interfaces -- see middleware.py's module docstring for the
one real behavioral difference from the JS version).
"""

from __future__ import annotations

from .middleware import helix_id_tool_wrapper, HelixIDCallbackHandler, encode_base64url_json_public
from .scope_filter import filter_tools_by_scope

__all__ = [
    "helix_id_tool_wrapper",
    "HelixIDCallbackHandler",
    "encode_base64url_json_public",
    "filter_tools_by_scope",
]
