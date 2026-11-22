# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""
The request signing the framework adapters share (helix_langchain,
helix_crewai), the Python twin of helix-sdk-js's ``signCurrentRequest``
(KYA-OS story C-C). A wrapped tool runs with a signer for the call in
progress; inside it, ``sign_current_request(request)`` returns the MCP
request the tool is about to send with a fresh request proof (and the
delegation chain) in ``params._meta``. The signer reaches the tool out of
band, never through the tool input, so nothing reaches the model's
arguments, and no request ever carries the private key.

The Helix VP, its ``X-Helix-VP`` header and ``current_helix_vp_headers()``
are gone.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Callable, Dict, Iterator, Mapping, Optional, Sequence, Union

from .crypto.jws import Signer
from .request_proof import with_request_proof

RequestSigner = Callable[[Mapping[str, Any]], Dict[str, Any]]
"""Signs one outbound MCP request: the request with the proof (and chain) in ``params._meta``."""

ChainSource = Union[Sequence[Any], Callable[[], Optional[Sequence[Any]]], None]
"""The delegation chain the agent acts under, root to leaf, or a function returning the current one."""

_current_signer: "ContextVar[Optional[RequestSigner]]" = ContextVar("helix_request_signer", default=None)


def request_signer(signer: Signer, audience: str, chain: ChainSource = None, cnf_jkt: Optional[str] = None) -> RequestSigner:
    """A RequestSigner over ``signer`` for the service ``audience`` (its DID); ``chain`` is read at every call."""

    def sign(call: Mapping[str, Any]) -> Dict[str, Any]:
        hops = chain() if callable(chain) else chain
        return with_request_proof(call, signer, audience=audience, chain=hops, cnf_jkt=cnf_jkt)

    return sign


@contextmanager
def signing_context(sign: RequestSigner) -> Iterator[None]:
    """Runs the block with ``sign`` as the current request signer."""
    token = _current_signer.set(sign)
    try:
        yield
    finally:
        _current_signer.reset(token)


def sign_current_request(call: Mapping[str, Any]) -> Dict[str, Any]:
    """Inside a wrapped tool: signs the MCP request the tool is about to send,
    returning it with ``_meta["org.kya-os/request-proof"]`` (and
    ``_meta["org.kya-os/delegation-chain"]``) set. Each request gets its own
    proof, bound to its body and the service. Raises outside a wrapped call."""
    sign = _current_signer.get()
    if sign is None:
        raise RuntimeError("sign_current_request: not inside a Helix-wrapped tool call")
    return sign(call)


__all__ = ["ChainSource", "RequestSigner", "request_signer", "sign_current_request", "signing_context"]
