"""Forwarding an agent's authority on a downstream call (KYA-OS story L3-D,
SPEC.md §8). Ported from helix-sdk-js's mcp-middleware/src/delegation/outbound.ts.

``with_delegation(request)`` wraps the HTTP ``request(method, url, headers=..., **kw)``
callable a tool handler uses for downstream HTTP and MCP calls (``requests.request``,
``httpx.Client().request``, ``httpx.AsyncClient().request``). Every request it
sends carries the chain (``KYA-OS-Delegation-Credential``), the §8.2 proof this
service signs for the target host (``KYA-OS-Delegation-Proof``), the agent DID,
the session id when there is one, and optionally the advisory chain and scope
headers. Re-delegation appends the service's own hop, checked for attenuation
before anything is sent. Every attachment is audited (L3.26).

The context comes from the gate: ``delegation_context_of(caller)`` after
``authorize()``, made current with ``run_with_delegation(context)`` (a context
manager); or it is given to ``with_delegation`` directly. A call with no context
is refused, never sent without authority.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Union
from urllib.parse import urlsplit

from helix_sdk.crypto.jws import Signer
from helix_sdk.credentials import MAX_DELEGATION_DEPTH
from helix_sdk.verifier.chain import evaluate_delegation_chain_rules

from .headers import DELEGATION_HEADERS, encode_delegation_credential
from .proof_jwt import build_chain_string, delegation_id_of, mint_delegation_proof_jwt


@dataclass(frozen=True)
class DelegationContext:
    """The authority a tool call carries, as the gate established it."""

    agent_did: str
    """The agent DID recovered from the inbound request proof's signature."""
    chain: Sequence[Any]
    """The chain the agent presented, root first."""
    scopes: Sequence[str]
    """The caller's effective scopes at this service."""
    session_id: Optional[str] = None
    correlation_id: Optional[str] = None


@dataclass
class OutboundAttachment:
    """One outbound attachment, as it is audited."""

    timestamp: str
    audience: str
    """The proof's ``aud``: the target host."""
    chain_string: str
    chain: Sequence[Any]
    delegation_id: str
    agent_did: str
    responsible_party: str
    """The root hop's issuer, the proof's ``sub``."""
    forwarder: str
    """This service's DID, the proof's ``iss``."""
    jti: str
    scopes: List[str] = field(default_factory=list)
    redelegated: bool = False
    correlation_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """The camelCase shape helix-sdk-js reports (the chain left out)."""
        out: Dict[str, Any] = {
            "timestamp": self.timestamp,
            "audience": self.audience,
            "chainString": self.chain_string,
            "delegationId": self.delegation_id,
            "agentDid": self.agent_did,
            "responsibleParty": self.responsible_party,
            "forwarder": self.forwarder,
            "jti": self.jti,
            "scopes": list(self.scopes),
            "redelegated": self.redelegated,
        }
        if self.correlation_id is not None:
            out["correlationId"] = self.correlation_id
        return out


OutboundAudit = Callable[[OutboundAttachment], Any]


class DelegationContextMissingError(RuntimeError):
    code = "DELEGATION_CONTEXT_MISSING"

    def __init__(self, message: str = "with_delegation: no delegation context; run the handler inside run_with_delegation(delegation_context_of(caller))") -> None:
        super().__init__(message)


class RedelegationError(ValueError):
    code = "REDELEGATION_INVALID"

    def __init__(self, reasons: Sequence[str]) -> None:
        self.reasons = list(reasons)
        super().__init__(f"with_delegation: the service's own hop does not attenuate the chain: {'; '.join(self.reasons)}")


_CONTEXT: "ContextVar[Optional[DelegationContext]]" = ContextVar("helix_mcp_middleware_delegation", default=None)


@contextmanager
def run_with_delegation(context: Optional[DelegationContext]) -> Iterator[Optional[DelegationContext]]:
    """Makes ``context`` the current delegation for the block (and the tasks it starts)."""
    token = _CONTEXT.set(context)
    try:
        yield context
    finally:
        _CONTEXT.reset(token)


def current_delegation() -> Optional[DelegationContext]:
    return _CONTEXT.get()


def delegation_context_of(caller: Any, session_id: Optional[str] = None, correlation_id: Optional[str] = None) -> Optional[DelegationContext]:
    """The delegation context of a caller the gate authorized (an AuthorizedCaller),
    or None when it carried no chain (an OAuth caller, an agent without delegation)."""
    chain = getattr(caller, "chain", None)
    agent_did = getattr(caller, "agent_did", None)
    if getattr(caller, "auth_method", None) != "kyaos" or agent_did is None or not chain:
        return None
    return DelegationContext(agent_did=agent_did, chain=list(chain), scopes=list(getattr(caller, "scopes", []) or []), session_id=session_id, correlation_id=correlation_id)


def _leaf_actions(chain: Sequence[Any]) -> List[str]:
    leaf = chain[-1] if chain else None
    subject = leaf.get("credentialSubject") if isinstance(leaf, dict) else None
    actions = subject.get("allowedAction") if isinstance(subject, dict) else None
    return [action for action in actions if isinstance(action, str)] if isinstance(actions, list) else []


def _root_issuer(chain: Sequence[Any]) -> Optional[str]:
    root = chain[0] if chain else None
    return root.get("issuer") if isinstance(root, dict) and isinstance(root.get("issuer"), str) else None


def host_of(url: str) -> str:
    """The ``host[:port]`` of a URL as WHATWG ``URL.host`` writes it: lower-cased,
    no userinfo, the scheme's default port left out (the proof's ``aud``)."""
    parts = urlsplit(url)
    hostname = parts.hostname or ""
    host = f"[{hostname}]" if ":" in hostname else hostname
    port = parts.port
    if port is None or (parts.scheme == "http" and port == 80) or (parts.scheme == "https" and port == 443):
        return host
    return f"{host}:{port}"


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def build_outbound_delegation(
    target: str,
    context: DelegationContext,
    signer: Signer,
    *,
    scopes: Union[None, Sequence[str], Callable[[DelegationContext, str], Sequence[str]]] = None,
    redelegate: Optional[Callable[[DelegationContext, str], Any]] = None,
    advisory_headers: bool = False,
    max_chain_length: int = MAX_DELEGATION_DEPTH,
    clock: Optional[Callable[[], int]] = None,
) -> "tuple[Dict[str, str], OutboundAttachment]":
    """The §8.1 headers for a request to ``target`` on behalf of ``context``,
    and what is audited about them. Raises RedelegationError when the
    service's own hop does not attenuate the chain."""
    now = (clock or _now_ms)()
    chain: List[Any] = list(context.chain)
    redelegated = False
    if redelegate is not None:
        own = redelegate(context, target)
        hops = [] if own is None else list(own) if isinstance(own, (list, tuple)) else [own]
        if hops:
            chain = [*chain, *hops]
            redelegated = True
            rules = evaluate_delegation_chain_rules(chain, now_ms=now, max_chain_length=max_chain_length)
            if not rules.ok:
                raise RedelegationError(rules.reasons)
            if any(not isinstance(hop, dict) or hop.get("issuer") != signer.did for hop in hops):
                raise RedelegationError(["a re-delegated hop must be issued by this service"])
    responsible_party = _root_issuer(chain)
    delegation_id = delegation_id_of(chain)
    if responsible_party is None or delegation_id is None:
        raise DelegationContextMissingError("with_delegation: the delegation context holds no chain to forward")
    chain_string = build_chain_string(chain)
    allowed = set(_leaf_actions(chain))
    forwarded = [scope for scope in context.scopes if scope in allowed]
    if scopes is not None:
        narrowed = set(scopes(context, target) if callable(scopes) else scopes)
        forwarded = [scope for scope in forwarded if scope in narrowed]
    audience = host_of(target)
    jti = f"urn:uuid:{uuid.uuid4()}"
    proof = mint_delegation_proof_jwt(
        signer, sub=responsible_party, aud=audience, delegation_id=delegation_id, delegation_chain=chain_string, scope=forwarded, jti=jti, now_ms=now
    )
    headers = {
        DELEGATION_HEADERS["credential"]: encode_delegation_credential(chain),
        DELEGATION_HEADERS["proof"]: proof,
        DELEGATION_HEADERS["agent_did"]: context.agent_did,
    }
    if context.session_id is not None:
        headers[DELEGATION_HEADERS["session_id"]] = context.session_id
    if advisory_headers:
        headers[DELEGATION_HEADERS["chain"]] = chain_string
        headers[DELEGATION_HEADERS["granted_scopes"]] = ",".join(forwarded)
    attachment = OutboundAttachment(
        timestamp=datetime.fromtimestamp(now / 1000, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        audience=audience,
        chain_string=chain_string,
        chain=chain,
        delegation_id=delegation_id,
        agent_did=context.agent_did,
        responsible_party=responsible_party,
        forwarder=signer.did,
        jti=jti,
        scopes=forwarded,
        redelegated=redelegated,
        correlation_id=context.correlation_id,
    )
    return headers, attachment


def with_delegation(
    request: Callable[..., Any],
    signer: Signer,
    *,
    context: Union[None, DelegationContext, Callable[[], Optional[DelegationContext]]] = None,
    scopes: Union[None, Sequence[str], Callable[[DelegationContext, str], Sequence[str]]] = None,
    redelegate: Optional[Callable[[DelegationContext, str], Any]] = None,
    advisory_headers: bool = False,
    audit: Optional[OutboundAudit] = None,
    on_audit_error: Optional[Callable[[BaseException], Any]] = None,
    max_chain_length: int = MAX_DELEGATION_DEPTH,
    clock: Optional[Callable[[], int]] = None,
) -> Callable[..., Any]:
    """A ``request(method, url, headers=None, **kwargs)`` that forwards the current
    delegation on every call (story L3-D point 1). Headers the caller set are kept,
    except the KYA-OS ones, which are this helper's alone. An async ``request``
    (``httpx.AsyncClient().request``) returns its awaitable for the caller to await."""

    def forward(method: str, url: str, headers: Optional[Dict[str, str]] = None, **kwargs: Any) -> Any:
        current = context() if callable(context) else context if context is not None else current_delegation()
        if current is None:
            raise DelegationContextMissingError()
        delegation, attachment = build_outbound_delegation(
            url, current, signer, scopes=scopes, redelegate=redelegate, advisory_headers=advisory_headers, max_chain_length=max_chain_length, clock=clock
        )
        names = {name.lower() for name in DELEGATION_HEADERS.values()}
        merged = {name: value for name, value in (headers or {}).items() if name.lower() not in names}
        merged.update(delegation)
        if audit is not None:
            try:
                audit(attachment)
            except Exception as error:  # noqa: BLE001 - auditing never blocks the call
                if on_audit_error is not None:
                    on_audit_error(error)
        return request(method, url, headers=merged, **kwargs)

    return forward
