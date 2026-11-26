"""KYA-OS story L3-D: the delegation graph, conformance L3.14 to L3.19 (the
reference suite's ``delegation-graph.test.ts`` cases, by name); the Python
twin of helix-sdk-js mcp-middleware/tests/delegation-graph.test.ts."""

from __future__ import annotations

import pytest

from helix_mcp_middleware import DelegationGraph, DelegationNode, create_delegation_graph, node_of_hop


def node(id: str, issuer: str, subject: str, parent: str = None) -> DelegationNode:  # noqa: A002, RUF013
    return DelegationNode(id=id, issuer_did=issuer, subject_did=subject, parent_id=parent)


def tree() -> DelegationGraph:
    """root (rp → user) → a (user → agentA) → { b (agentA → agentB) → d (agentB → agentD), c (agentA → agentC) }"""
    graph = create_delegation_graph()
    graph.register_delegation(node("root", "did:rp", "did:user"))
    graph.register_delegation(node("a", "did:user", "did:agentA", "root"))
    graph.register_delegation(node("b", "did:agentA", "did:agentB", "a"))
    graph.register_delegation(node("c", "did:agentA", "did:agentC", "a"))
    graph.register_delegation(node("d", "did:agentB", "did:agentD", "b"))
    return graph


def test_should_register_a_root_delegation_l3_14() -> None:
    graph = DelegationGraph()
    stored = graph.register_delegation(node("root", "did:rp", "did:user"))
    assert (stored.id, stored.children, stored.parent_id, graph.size) == ("root", [], None, 1)


def test_should_register_a_child_delegation_and_link_to_parent_l3_15() -> None:
    graph = tree()
    assert graph.get_node("a").parent_id == "root"
    assert graph.get_node("root").children == ["a"]
    assert [child.id for child in graph.get_children("a")] == ["b", "c"]


def test_should_include_credential_status_id() -> None:
    graph = DelegationGraph()
    graph.register_delegation(DelegationNode(id="root", issuer_did="did:rp", subject_did="did:user", credential_status_id="https://l/1#4"))
    assert graph.get_node("root").credential_status_id == "https://l/1#4"


def test_identical_registration_is_a_no_op_and_a_conflict_is_refused() -> None:
    graph = tree()
    graph.register_delegation(node("a", "did:user", "did:agentA", "root"))
    assert graph.get_node("a").children == ["b", "c"]
    with pytest.raises(ValueError, match="subject_did"):
        graph.register_delegation(node("a", "did:user", "did:other", "root"))
    assert graph.get_node("a").subject_did == "did:agentA"


def test_own_parent_unknown_parent_and_no_duplicate_children() -> None:
    graph = tree()
    with pytest.raises(ValueError, match="own parent"):
        graph.register_delegation(node("x", "did:a", "did:b", "x"))
    with pytest.raises(ValueError, match="not registered"):
        graph.register_delegation(node("y", "did:a", "did:b", "missing"))
    graph.register_delegation(node("c", "did:agentA", "did:agentC", "a"))
    assert graph.get_node("a").children == ["b", "c"]


def test_children_and_descendants_l3_19() -> None:
    assert tree().get_children("d") == [] and tree().get_children("missing") == []
    assert [n.id for n in tree().get_descendants("a")] == ["b", "d", "c"]
    assert sorted(n.id for n in tree().get_descendants("root")) == ["a", "b", "c", "d"]
    assert tree().get_descendants("d") == []


def test_should_return_chain_from_root_to_node_l3_18() -> None:
    assert [n.id for n in tree().get_chain("d")] == ["root", "a", "b", "d"]
    assert [n.id for n in tree().get_chain("root")] == ["root"]
    assert tree().get_chain("missing") == []


def test_is_ancestor_and_depth() -> None:
    graph = tree()
    assert graph.is_ancestor("a", "b") and graph.is_ancestor("root", "d")
    assert not graph.is_ancestor("c", "d") and not graph.is_ancestor("d", "root") and not graph.is_ancestor("d", "d")
    assert [graph.get_depth(i) for i in ("root", "a", "d", "missing")] == [0, 1, 3, -1]


def test_should_validate_correct_chain_l3_16() -> None:
    assert tree().validate_chain("d") == {"valid": True}


def test_should_invalidate_chain_with_mismatched_issuer_subject_l3_17() -> None:
    graph = tree()
    graph.register_delegation(node("bad", "did:mallory", "did:agentE", "b"))
    result = graph.validate_chain("bad")
    assert result["valid"] is False and "did:mallory" in result["reason"]


def test_invalid_for_unknown_and_orphaned() -> None:
    graph = tree()
    assert graph.validate_chain("missing")["valid"] is False
    graph.remove_delegation("a")
    result = graph.validate_chain("d")
    assert result["valid"] is False and "parent a" in result["reason"]


def test_remove_delegation() -> None:
    graph = tree()
    graph.remove_delegation("c")
    assert graph.get_node("c") is None and graph.get_node("a").children == ["b"]
    graph.remove_delegation("missing")
    graph.remove_delegation("root")
    graph.remove_delegation("a")
    assert graph.size == 2


def _hop(id: str, issuer: str, invoker: str, status: bool = True) -> dict:  # noqa: A002
    hop = {"id": id, "issuer": issuer, "credentialSubject": {"id": f"{id}-cap", "invoker": invoker}}
    if status:
        hop["credentialStatus"] = {"statusListCredential": "https://l/1", "statusListIndex": "3"}
    return hop


def test_helix_hops() -> None:
    graph = DelegationGraph()
    leaf = graph.register_chain([_hop("vc-1", "did:owner", "did:agent"), _hop("vc-2", "did:agent", "did:service", status=False)])
    assert (leaf.id, leaf.parent_id, leaf.capability_id) == ("vc-2", "vc-1", "vc-2-cap")
    assert graph.get_node("vc-1").credential_status_id == "https://l/1#3"
    assert graph.chain_string("vc-2") == "vc-1>vc-1-cap>vc-2>vc-2-cap"
    assert graph.validate_chain("vc-2") == {"valid": True}
    graph.register_delegation(node("bare", "did:x", "did:y"))
    assert graph.chain_string("bare") == "bare"


def test_node_of_hop_and_refusals() -> None:
    assert node_of_hop({"id": "v", "issuer": "did:a", "credentialSubject": {"controller": "did:b"}}).subject_did == "did:b"
    assert node_of_hop({"id": "v", "issuer": "did:a", "credentialSubject": {}}) is None
    assert node_of_hop({"id": "v", "issuer": "did:a"}) is None
    assert node_of_hop("hop") is None
    with pytest.raises(ValueError, match="hop 0"):
        DelegationGraph().register_chain([{"id": 1}])
    with pytest.raises(ValueError, match="empty"):
        DelegationGraph().register_chain([])
