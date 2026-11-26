"""The delegation graph a service keeps of the chains it has verified or
forwarded (KYA-OS story L3-D; SPEC.md §6.4; conformance L3.14 to L3.19).
Ported from helix-sdk-js's mcp-middleware/src/delegation/graph.ts.

Every hop is a node keyed by its credential id, linked to its parent. The
verification cache drops a revoked credential's cached verdicts together
with those of every descendant. Local state only, never a source of
authority: every chain is verified from its signed hops.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Optional, Sequence


@dataclass
class DelegationNode:
    id: str
    """The credential id (the hop's VC ``id``)."""
    issuer_did: str
    subject_did: str
    """Who the hop delegates to (the ZCAP ``invoker``)."""
    parent_id: Optional[str] = None
    capability_id: Optional[str] = None
    """The capability id (``credentialSubject.id``), for the chain string."""
    credential_status_id: Optional[str] = None
    children: List[str] = field(default_factory=list)


_SAME_FIELDS = ("parent_id", "issuer_did", "subject_did", "capability_id", "credential_status_id")


def node_of_hop(hop: Any, parent_id: Optional[str] = None) -> Optional[DelegationNode]:
    """A Helix hop (SPEC.md §6.10) as a graph node, or None when it is not shaped like one."""
    if not isinstance(hop, dict) or not isinstance(hop.get("id"), str) or not isinstance(hop.get("issuer"), str):
        return None
    subject = hop.get("credentialSubject")
    if not isinstance(subject, dict):
        return None
    invoker = subject.get("invoker") if isinstance(subject.get("invoker"), str) else subject.get("controller")
    if not isinstance(invoker, str):
        return None
    status = hop.get("credentialStatus") if isinstance(hop.get("credentialStatus"), dict) else {}
    status_id = (
        f"{status['statusListCredential']}#{status['statusListIndex']}"
        if isinstance(status.get("statusListCredential"), str) and isinstance(status.get("statusListIndex"), str)
        else None
    )
    return DelegationNode(
        id=hop["id"],
        issuer_did=hop["issuer"],
        subject_did=invoker,
        parent_id=parent_id,
        capability_id=subject.get("id") if isinstance(subject.get("id"), str) else None,
        credential_status_id=status_id,
    )


class DelegationGraph:
    def __init__(self) -> None:
        self._nodes: Dict[str, DelegationNode] = {}

    @property
    def size(self) -> int:
        return len(self._nodes)

    def register_delegation(self, node: DelegationNode) -> DelegationNode:
        """Registers a delegation (L3.14) and links it under its parent (L3.15).
        Registering the same delegation again is a no-op that keeps its
        children; a conflicting registration, an unknown parent, or a parent
        that is the node itself raises."""
        existing = self._nodes.get(node.id)
        if existing is not None:
            conflict = next((name for name in _SAME_FIELDS if getattr(existing, name) != getattr(node, name)), None)
            if conflict is not None:
                raise ValueError(f"delegation {node.id} is already registered with another {conflict}")
            return existing
        if node.parent_id is not None:
            if node.parent_id == node.id:
                raise ValueError(f"delegation {node.id} cannot be its own parent")
            parent = self._nodes.get(node.parent_id)
            if parent is None:
                raise ValueError(f"parent delegation {node.parent_id} is not registered")
            if node.id not in parent.children:
                parent.children.append(node.id)
        stored = replace(node, children=[])
        self._nodes[node.id] = stored
        return stored

    def register_chain(self, chain: Sequence[Any]) -> DelegationNode:
        """Registers a Helix chain, root first; returns the leaf node."""
        parent_id: Optional[str] = None
        leaf: Optional[DelegationNode] = None
        for index, hop in enumerate(chain):
            node = node_of_hop(hop, parent_id)
            if node is None:
                raise ValueError(f"hop {index} is not a delegation credential")
            leaf = self.register_delegation(node)
            parent_id = node.id
        if leaf is None:
            raise ValueError("an empty chain has no delegation to register")
        return leaf

    def get_node(self, id: str) -> Optional[DelegationNode]:  # noqa: A002 - the reference suite's name
        return self._nodes.get(id)

    def get_children(self, id: str) -> List[DelegationNode]:  # noqa: A002
        node = self._nodes.get(id)
        return [self._nodes[child] for child in (node.children if node else []) if child in self._nodes]

    def get_descendants(self, id: str) -> List[DelegationNode]:  # noqa: A002
        """Every descendant of ``id``, depth first (L3.19)."""
        out: List[DelegationNode] = []
        seen = {id}

        def walk(current: str) -> None:
            for child in self.get_children(current):
                if child.id in seen:
                    continue
                seen.add(child.id)
                out.append(child)
                walk(child.id)

        walk(id)
        return out

    def get_chain(self, id: str) -> List[DelegationNode]:  # noqa: A002
        """The chain from the root to ``id``, root first (L3.18); empty when ``id`` is unknown."""
        chain: List[DelegationNode] = []
        seen = set()
        current = self._nodes.get(id)
        while current is not None and current.id not in seen:
            seen.add(current.id)
            chain.insert(0, current)
            current = self._nodes.get(current.parent_id) if current.parent_id is not None else None
        return chain

    def is_ancestor(self, ancestor_id: str, id: str) -> bool:  # noqa: A002
        return any(node.id == ancestor_id and node.id != id for node in self.get_chain(id))

    def get_depth(self, id: str) -> int:  # noqa: A002
        """0 for a root, 1 for its child, and so on; -1 when unknown."""
        return len(self.get_chain(id)) - 1

    def validate_chain(self, id: str) -> Dict[str, Any]:  # noqa: A002
        """Issuer/subject continuity along the chain to ``id`` (L3.16, L3.17)."""
        chain = self.get_chain(id)
        if not chain:
            return {"valid": False, "reason": f"delegation {id} is not registered"}
        if chain[0].parent_id is not None:
            return {"valid": False, "reason": f"the parent {chain[0].parent_id} of {chain[0].id} is not registered"}
        for parent, child in zip(chain, chain[1:]):
            if child.parent_id != parent.id:  # pragma: no cover - get_chain follows parent_id, so this holds
                return {"valid": False, "reason": f"{child.id} does not link to {parent.id}"}
            if child.issuer_did != parent.subject_did:
                return {"valid": False, "reason": f"{child.id} is issued by {child.issuer_did}, not by {parent.subject_did}, the subject of its parent"}
        return {"valid": True}

    def chain_string(self, id: str) -> str:  # noqa: A002
        """The §8.3 chain string to ``id``: ``<vcId>><capabilityId>`` per hop, root first."""
        return ">".join(node.id if node.capability_id is None else f"{node.id}>{node.capability_id}" for node in self.get_chain(id))

    def remove_delegation(self, id: str) -> None:  # noqa: A002
        """Removes ``id`` and unlinks it from its parent; its children stay, orphaned."""
        node = self._nodes.pop(id, None)
        if node is None or node.parent_id is None:
            return
        parent = self._nodes.get(node.parent_id)
        if parent is not None:
            parent.children = [child for child in parent.children if child != id]


def create_delegation_graph() -> DelegationGraph:
    return DelegationGraph()
