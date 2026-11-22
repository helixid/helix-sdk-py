# Copyright 2026 DgVerse LLP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
"""Story A-2 in the Python SDK and middleware: the recorder client, the
outboxes (the reference contract, restart durability, dead letters), the
delivery modes (required by default, buffered refusing an ephemeral outbox,
best-effort only with AAP-1 accepted), and the audited tool wrappers."""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from helix_sdk.audit import (
    AUDIT_BINDING_MCP,
    AuditDeliveryConfigError,
    AuditDeliveryError,
    AuditDeliverySink,
    AuditOutboxConflictError,
    AuditOutboxItem,
    AuditRecorderSubmission,
    AuditTrail,
    DurableOutbox,
    HttpAuditRecorderClient,
    MemoryAuditOutbox,
    MemoryAuditSink,
    TeeAuditSink,
    assert_audit_outbox_contract,
    assert_entry_binds_submission,
    audit_event_digest,
    audit_submission_wire,
    create_audit_delivery,
    evaluate_audit_outbox_provider_contract,
    pairwise_did,
    same_audit_submission,
)
from helix_mcp_middleware import (
    AUDIT_META_KEY,
    McpAuditTrail,
    async_run_audited_tool,
    audit_unavailable_response,
    create_helix_audit_delivery,
    create_mcp_audit_trail,
    mark_audit_degraded,
    run_audited_tool,
)

PRODUCER = pairwise_did("did:web:orders.example.com")
EVIDENCE_REF = {
    "objectId": "evi_1",
    "ciphertextDigest": "sha256:" + "1" * 64,
    "mediaType": "text/plain",
    "size": "3",
    "encryption": {"suite": "A256GCM", "keyId": "k", "nonce": "n", "aadDigest": "sha256:" + "2" * 64},
}


def trail_over(sink: Any, source_id: str = "mcp-middleware:orders") -> AuditTrail:
    return AuditTrail(sink=sink, source_id=source_id, producer=PRODUCER, tenant_ref=PRODUCER, binding=AUDIT_BINDING_MCP, clock=lambda: 1_780_000_000_000)


def event_of(event_id: str, source_id: str = "mcp-middleware:orders") -> Dict[str, Any]:
    return trail_over(MemoryAuditSink(), source_id).build(
        {"eventId": event_id, "eventType": "tool.call.completed", "action": {"category": "tool.call"}, "outcome": "succeeded", "details": {"family": "tool", "phase": "completed", "attempt": "1"}}
    )


STARTED = {"eventType": "tool.call.started", "action": {"category": "tool.call"}, "outcome": "unknown", "details": {"family": "tool", "phase": "started", "attempt": "1"}}


class FakeRecorder:
    """Answers like the recorder: sequence, receipt, the same entry on redelivery; `down` and `fail_on` refuse."""

    def __init__(self) -> None:
        self.submissions: List[AuditRecorderSubmission] = []
        self.entries: Dict[str, Dict[str, Any]] = {}
        self.down = False
        self.fail_on: set = set()

    def submit(self, submission: AuditRecorderSubmission) -> Dict[str, Any]:
        self.submissions.append(submission)
        event = submission.producer_event
        if self.down or event["eventType"] in self.fail_on or event["eventId"] in self.fail_on:
            raise AuditDeliveryError("recorder unreachable", 503, "AUDIT_JOURNAL_FAILURE")
        key = f"{event['source']['sourceId']}\0{event['eventId']}"
        if key in self.entries:
            return self.entries[key]
        sequence = str(len(self.entries) + 1)
        digest = audit_event_digest(event)
        entry = {
            "core": {"ledgerId": submission.ledger_id or "ledger_x", "ledgerEpochId": "epoch-1", "sequence": sequence, "eventDigest": digest, "event": event},
            "eventDigest": digest,
            "entryDigest": "sha256:" + sequence.zfill(64),
            "recorderReceipt": {"core": {"sequence": sequence}, "jws": f"receipt-{sequence}"},
        }
        self.entries[key] = entry
        return entry

    @property
    def recorded(self) -> List[str]:
        return [entry["core"]["event"]["eventType"] for entry in self.entries.values()]


class FakeResponse:
    def __init__(self, status: int, body: Any) -> None:
        self.status_code = status
        self._body = body

    def json(self) -> Any:
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class FakeHttp:
    def __init__(self, answer: Any) -> None:
        self.answer = answer
        self.calls: List[Dict[str, Any]] = []

    def post(self, url: str, json: Any, headers: Dict[str, str], timeout: float) -> Any:  # noqa: A002 - requests' name
        self.calls.append({"url": url, "json": json, "headers": headers, "timeout": timeout})
        return self.answer(json) if callable(self.answer) else self.answer


# -- recorder client ---------------------------------------------------------------


def test_http_recorder_client_posts_the_wire_and_returns_an_entry_that_binds_it() -> None:
    recorder = FakeRecorder()
    http = FakeHttp(lambda wire: FakeResponse(201, {"entry": recorder.submit(AuditRecorderSubmission(producer_event=wire["producerEvent"], ledger_id=wire.get("ledgerId")))}))
    client = HttpAuditRecorderClient("https://api.example.com/", "k1", timeout_seconds=2.0, http=http)
    event = event_of("http-1")
    entry = client.submit(AuditRecorderSubmission(producer_event=event, encrypted_evidence=[(EVIDENCE_REF, b"\x01\x02\x03")], ledger_id="ledger_x", expected_ledger_epoch_id="epoch-1"))
    assert entry["core"]["event"] == event
    call = http.calls[0]
    assert call["url"] == "https://api.example.com/v1/audit/submissions"
    assert call["headers"] == {"authorization": "Bearer k1"}
    assert call["timeout"] == 2.0
    assert call["json"] == {"ledgerId": "ledger_x", "expectedLedgerEpochId": "epoch-1", "producerEvent": event, "encryptedEvidence": [{"ref": EVIDENCE_REF, "ciphertextBase64url": "AQID"}]}
    assert audit_submission_wire(AuditRecorderSubmission(producer_event=event)) == {"producerEvent": event}


@pytest.mark.parametrize(
    "answer,message,status,code",
    [
        (FakeResponse(503, {"error": {"code": "AUDIT_JOURNAL_FAILURE"}}), r"refused the submission \(503 AUDIT_JOURNAL_FAILURE\)", 503, "AUDIT_JOURNAL_FAILURE"),
        (FakeResponse(500, ValueError("not json")), r"refused the submission \(500\)", 500, None),
        (FakeResponse(201, {}), r"refused the submission \(201\)", 201, None),
    ],
)
def test_http_recorder_client_turns_refusals_into_delivery_errors(answer: Any, message: str, status: int, code: Optional[str]) -> None:
    with pytest.raises(AuditDeliveryError, match=message) as raised:
        HttpAuditRecorderClient("https://api.example.com", "k", http=FakeHttp(answer)).submit(AuditRecorderSubmission(producer_event=event_of("x")))
    assert raised.value.status == status
    assert raised.value.code == code


def test_http_recorder_client_refuses_an_unreachable_recorder_and_an_answer_for_another_event() -> None:
    class Broken:
        def post(self, *args: Any, **kwargs: Any) -> Any:
            raise ConnectionError("refused")

    with pytest.raises(AuditDeliveryError, match="could not be reached"):
        HttpAuditRecorderClient("https://api.example.com", "k", http=Broken()).submit(AuditRecorderSubmission(producer_event=event_of("x")))
    other = FakeRecorder().submit(AuditRecorderSubmission(producer_event=event_of("someone-else")))
    with pytest.raises(AuditDeliveryError, match="does not bind"):
        HttpAuditRecorderClient("https://api.example.com", "k", http=FakeHttp(FakeResponse(201, {"entry": other}))).submit(AuditRecorderSubmission(producer_event=event_of("x")))
    entry = FakeRecorder().submit(AuditRecorderSubmission(producer_event=event_of("y")))
    with pytest.raises(AuditDeliveryError):
        assert_entry_binds_submission(entry, AuditRecorderSubmission(producer_event=event_of("y"), ledger_id="ledger_other"))
    with pytest.raises(AuditDeliveryError):
        assert_entry_binds_submission("not an entry", AuditRecorderSubmission(producer_event=event_of("y")))


def test_the_default_http_client_is_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    import requests

    recorder = FakeRecorder()
    monkeypatch.setattr(requests, "post", lambda url, json, headers, timeout: FakeResponse(201, {"entry": recorder.submit(AuditRecorderSubmission(producer_event=json["producerEvent"]))}))
    assert HttpAuditRecorderClient("https://api.example.com", "k").submit(AuditRecorderSubmission(producer_event=event_of("r")))["core"]["sequence"] == "1"


# -- outboxes ----------------------------------------------------------------------


def test_both_outboxes_pass_the_reference_outbox_contract(tmp_path: Path) -> None:
    assert_audit_outbox_contract(evaluate_audit_outbox_provider_contract(MemoryAuditOutbox))
    counter = {"n": 0}

    def durable() -> DurableOutbox:
        counter["n"] += 1
        return DurableOutbox(str(tmp_path / f"outbox-{counter['n']}"))

    report = evaluate_audit_outbox_provider_contract(durable)
    assert [check.passed for check in report.checks] == [True, True, True, True]
    assert_audit_outbox_contract(report)


def test_the_contract_reports_an_outbox_that_loses_order() -> None:
    class Reversed(MemoryAuditOutbox):
        def pending(self, limit: Optional[int] = None) -> Any:
            return iter(list(super().pending(limit))[::-1])

    report = evaluate_audit_outbox_provider_contract(Reversed)
    assert not report.passed
    with pytest.raises(AssertionError, match="declares and preserves FIFO order per source"):
        assert_audit_outbox_contract(report)


def test_a_durable_outbox_keeps_items_evidence_and_failures_across_a_restart(tmp_path: Path) -> None:
    directory = str(tmp_path / "outbox")
    first = DurableOutbox(directory)
    with_evidence = AuditOutboxItem("e1", AuditRecorderSubmission(producer_event={**event_of("e1"), "evidence": [EVIDENCE_REF]}, encrypted_evidence=[(EVIDENCE_REF, b"\x07\x08\x09")]), 1)
    first.enqueue(with_evidence)
    first.enqueue(AuditOutboxItem("e2", AuditRecorderSubmission(producer_event=event_of("e2"), ledger_id="ledger_x", expected_ledger_epoch_id="epoch-9"), 2))
    first.mark_failed("e1", RuntimeError("offline"))

    restarted = DurableOutbox(directory)
    items = list(restarted.pending())
    assert [(item.event_id, item.attempts) for item in items] == [("e1", 1), ("e2", 0)]
    assert items[0].submission.encrypted_evidence[0][1] == b"\x07\x08\x09"
    assert items[1].submission.ledger_id == "ledger_x" and items[1].submission.expected_ledger_epoch_id == "epoch-9"
    assert same_audit_submission(items[0].submission, with_evidence.submission)
    with pytest.raises(AuditOutboxConflictError):
        restarted.enqueue(AuditOutboxItem("e1", AuditRecorderSubmission(producer_event=with_evidence.submission.producer_event, encrypted_evidence=[(EVIDENCE_REF, b"\x00")]), 1))
    restarted.enqueue(AuditOutboxItem("e3", AuditRecorderSubmission(producer_event=event_of("e3")), 3))
    assert [item.event_id for item in DurableOutbox(directory).pending(2)] == ["e1", "e2"]
    restarted.mark_delivered("missing")
    restarted.mark_failed("missing", RuntimeError("x"))


def test_a_durable_outbox_moves_items_to_dead_letters_and_skips_vanished_or_foreign_files(tmp_path: Path) -> None:
    directory = tmp_path / "dead"
    outbox = DurableOutbox(str(directory), max_attempts=2)
    outbox.enqueue(AuditOutboxItem("d1", AuditRecorderSubmission(producer_event=event_of("d1")), 1))
    outbox.enqueue(AuditOutboxItem("d2", AuditRecorderSubmission(producer_event=event_of("d2")), 2))
    for _ in range(2):
        outbox.mark_failed(("mcp-middleware:orders", "d1"), RuntimeError("x"))
    assert [(item.event_id, item.attempts) for item in outbox.dead_letters()] == [("d1", 2)]
    reopened = DurableOutbox(str(directory), max_attempts=2)
    reopened.enqueue(AuditOutboxItem("d3", AuditRecorderSubmission(producer_event=event_of("d3")), 3))
    names = sorted(os.listdir(directory / "pending"))
    assert len(names) == 2
    iterator = reopened.pending()
    assert next(iterator).event_id == "d2"
    os.unlink(directory / "pending" / names[1])
    assert list(iterator) == []
    assert DurableOutbox(str(tmp_path / "never")).dead_letters() == []

    foreign = tmp_path / "foreign"
    DurableOutbox(str(foreign)).enqueue(AuditOutboxItem("f1", AuditRecorderSubmission(producer_event=event_of("f1")), 1))
    (name,) = os.listdir(foreign / "pending")
    (foreign / "pending" / name).write_text(json.dumps({"format": "other"}))
    with pytest.raises(ValueError, match="Not a helix audit outbox item"):
        DurableOutbox(str(foreign)).enqueue(AuditOutboxItem("f2", AuditRecorderSubmission(producer_event=event_of("f2")), 1))


@pytest.mark.parametrize("make", [MemoryAuditOutbox, None])
def test_an_outbox_refuses_a_bare_event_id_that_several_sources_have_pending(tmp_path: Path, make: Any) -> None:
    outbox = make() if make is not None else DurableOutbox(str(tmp_path / "shared"))
    outbox.enqueue(AuditOutboxItem("same", AuditRecorderSubmission(producer_event=event_of("same", "source-a")), 1))
    outbox.enqueue(AuditOutboxItem("same", AuditRecorderSubmission(producer_event=event_of("same", "source-b")), 2))
    with pytest.raises(ValueError, match="several sources"):
        outbox.mark_delivered("same")
    outbox.mark_delivered(("source-a", "same"))
    outbox.mark_delivered("same")
    assert list(outbox.pending()) == []


# -- delivery modes ------------------------------------------------------------------


def test_delivery_refuses_misconfiguration_at_startup() -> None:
    recorder = FakeRecorder()
    with pytest.raises(AuditDeliveryConfigError):
        create_audit_delivery(recorder, delivery="sometimes")
    with pytest.raises(AuditDeliveryConfigError, match="durable outbox"):
        create_audit_delivery(recorder, delivery="buffered")
    with pytest.raises(AuditDeliveryConfigError, match="ephemeral outbox is refused"):
        create_audit_delivery(recorder, delivery="buffered", outbox=MemoryAuditOutbox())
    with pytest.raises(AuditDeliveryConfigError, match="AAP-1 only"):
        create_audit_delivery(recorder, delivery="best-effort")
    assert create_audit_delivery(recorder).delivery == "required"
    assert create_audit_delivery(recorder).profile == "AAP-2"
    assert create_audit_delivery(recorder, delivery="best-effort", accept_aap1=True).profile == "AAP-1"


def test_required_delivery_returns_the_receipt_and_fails_without_one() -> None:
    recorder = FakeRecorder()
    failures: List[BaseException] = []
    trail = trail_over(create_audit_delivery(recorder, ledger_id="ledger_x", expected_ledger_epoch_id="epoch-1", on_delivery_failure=lambda e, _ev: failures.append(e)))
    recorded = trail.record(dict(STARTED))
    assert recorded.receipt is not None and recorded.receipt["recorderReceipt"]["jws"] == "receipt-1"
    assert recorder.submissions[0].ledger_id == "ledger_x" and recorder.submissions[0].expected_ledger_epoch_id == "epoch-1"
    recorder.down = True
    with pytest.raises(AuditDeliveryError):
        trail.record(dict(STARTED))
    assert len(failures) == 1

    class Lying(FakeRecorder):
        def submit(self, submission: AuditRecorderSubmission) -> Dict[str, Any]:
            return {**super().submit(submission), "eventDigest": "sha256:" + "0" * 64}

    with pytest.raises(AuditDeliveryError, match="does not bind"):
        trail_over(create_audit_delivery(Lying())).record(dict(STARTED))


def test_best_effort_delivery_reports_a_failure_and_goes_on() -> None:
    recorder = FakeRecorder()
    recorder.down = True
    failures: List[BaseException] = []
    trail = trail_over(create_audit_delivery(recorder, delivery="best-effort", accept_aap1=True, on_delivery_failure=lambda e, _ev: failures.append(e)))
    assert trail.record(dict(STARTED)).receipt is None
    assert len(failures) == 1
    recorder.down = False
    assert trail.record(dict(STARTED)).receipt is not None


def test_buffered_delivery_survives_a_restart_and_delivers_in_order(tmp_path: Path) -> None:
    directory = str(tmp_path / "buffered")
    recorder = FakeRecorder()
    recorder.down = True
    before = create_audit_delivery(recorder, delivery="buffered", outbox=DurableOutbox(directory), ledger_id="ledger_x", expected_ledger_epoch_id="never-pinned")
    trail = trail_over(before)
    ids = []
    for phase in ("started", "completed"):
        recorded = trail.record({"eventType": f"tool.call.{phase}", "action": {"category": "tool.call"}, "outcome": "unknown", "details": {"family": "tool", "phase": phase, "attempt": "1"}})
        assert recorded.receipt is None
        ids.append(recorded.event["eventId"])
    assert (before.flush().delivered, before.flush().failed) == (0, 1)

    recorder.down = False
    after = create_audit_delivery(recorder, delivery="buffered", outbox=DurableOutbox(directory))
    result = after.flush()
    assert (result.delivered, result.failed) == (2, 0)
    assert [entry["core"]["event"]["eventId"] for entry in recorder.entries.values()] == ids
    assert all(submission.expected_ledger_epoch_id is None for submission in recorder.submissions)
    assert os.listdir(os.path.join(directory, "pending")) == []


def test_buffered_delivery_blocks_only_the_failing_source_reports_ack_failures_and_flushes_on_a_thread(tmp_path: Path) -> None:
    recorder = FakeRecorder()
    outbox = DurableOutbox(str(tmp_path / "ordered"))
    acks: List[BaseException] = []
    sink = AuditDeliverySink(recorder, delivery="buffered", outbox=outbox, on_acknowledgement_failure=lambda e, _ev: acks.append(e))
    trail_over(sink, "source-a").record({**STARTED, "eventId": "a1"})
    trail_over(sink, "source-a").record({**STARTED, "eventId": "a2"})
    trail_over(sink, "source-b").record({**STARTED, "eventId": "b1"})
    recorder.fail_on.add("a1")
    result = sink.flush()
    assert (result.delivered, result.failed) == (1, 1)
    assert [(item.event_id, item.attempts) for item in outbox.pending()] == [("a1", 1), ("a2", 0)]
    recorder.fail_on.clear()
    original = outbox.mark_delivered
    outbox.mark_delivered = lambda key: (_ for _ in ()).throw(OSError("disk"))  # type: ignore[method-assign]
    assert sink.flush().delivered == 2
    assert len(acks) == 2
    outbox.mark_delivered = original  # type: ignore[method-assign]
    sink.start(0.01)
    sink.start(0.01)
    deadline = time.time() + 2
    while list(outbox.pending()) and time.time() < deadline:
        time.sleep(0.01)
    sink.stop()
    sink.stop()
    assert list(outbox.pending()) == []
    assert len(recorder.entries) == 3


def test_flush_is_a_no_op_outside_buffered_mode_and_a_tee_returns_the_first_receipt() -> None:
    recorder = FakeRecorder()
    sink = create_audit_delivery(recorder)
    assert (sink.flush().delivered, sink.flush().failed) == (0, 0)
    sink.start()
    sink.stop()
    echo = MemoryAuditSink()
    recorded = trail_over(TeeAuditSink([echo, sink])).record(dict(STARTED))
    assert recorded.receipt["recorderReceipt"]["jws"] == "receipt-1"
    assert len(echo.entries) == 1


# -- middleware ----------------------------------------------------------------------


def mcp_trail(recorder: FakeRecorder, on_error: Any = None) -> McpAuditTrail:
    return create_mcp_audit_trail(create_audit_delivery(recorder), "did:web:orders.example", on_error=on_error)


OK = {"content": [{"type": "text", "text": '{"orderId":"ORD-1"}'}], "_meta": {"other": 1}}


def test_run_audited_tool_records_intent_before_and_completion_after() -> None:
    recorder = FakeRecorder()
    audit = mcp_trail(recorder)
    with audit.begin_tool_call("lookup_order") as call:
        seen: List[str] = []
        assert run_audited_tool(call, lambda: (seen.extend(recorder.recorded), OK)[1]) is OK
    assert seen == ["session.established", "tool.call.started"]
    assert recorder.recorded[-1] == "tool.call.completed"


def test_run_audited_tool_does_not_run_the_handler_without_an_intent_receipt() -> None:
    for on_error in (None, lambda error: None):
        recorder = FakeRecorder()
        recorder.fail_on.add("tool.call.started")
        errors: List[str] = []
        with mcp_trail(recorder, on_error).begin_tool_call("refund_order") as call:
            ran: List[bool] = []
            result = run_audited_tool(call, lambda: (ran.append(True), OK)[1], on_audit_error=lambda e, phase: errors.append(phase))
        assert ran == []
        assert result == audit_unavailable_response()
        assert json.loads(result["content"][0]["text"])["error"]["code"] == "audit_delivery_failed"
        assert errors == (["intent"] if on_error is None else [])


def test_run_audited_tool_marks_a_result_degraded_when_the_completion_is_not_recorded() -> None:
    recorder = FakeRecorder()
    recorder.fail_on.add("tool.call.completed")
    with mcp_trail(recorder).begin_tool_call(None) as call:
        result = run_audited_tool(call, lambda: {**OK, "_meta": {"other": 1, AUDIT_META_KEY: {"proofs": True}}})
    assert result["isError"] is True
    assert result["_meta"] == {"other": 1, AUDIT_META_KEY: {"proofs": True, "status": "degraded", "reason": "Required terminal audit delivery failed after the tool ran"}}
    assert mark_audit_degraded({"_meta": {AUDIT_META_KEY: "x"}}, "r")["_meta"] == {AUDIT_META_KEY: {"status": "degraded", "reason": "r"}}


def test_run_audited_tool_records_a_throwing_handler_as_failed_and_rethrows() -> None:
    recorder = FakeRecorder()
    with mcp_trail(recorder).begin_tool_call(None) as call:
        with pytest.raises(RuntimeError, match="secret"):
            run_audited_tool(call, lambda: (_ for _ in ()).throw(RuntimeError("secret")))
    assert recorder.recorded[-1] == "tool.call.failed"


def test_async_run_audited_tool_runs_async_and_sync_handlers() -> None:
    recorder = FakeRecorder()
    audit = mcp_trail(recorder)

    async def handler() -> Dict[str, Any]:
        return OK

    async def scenario() -> None:
        with audit.begin_tool_call(None) as call:
            assert await async_run_audited_tool(call, handler) is OK
        with audit.begin_tool_call(None) as call:
            assert await async_run_audited_tool(call, lambda: OK) is OK
        recorder.fail_on.add("tool.call.completed")
        with audit.begin_tool_call(None) as call:
            assert (await async_run_audited_tool(call, handler))["isError"] is True
        recorder.fail_on.add("tool.call.started")
        with audit.begin_tool_call(None) as call:
            assert await async_run_audited_tool(call, handler) == audit_unavailable_response()
        recorder.fail_on.clear()

        async def boom() -> Dict[str, Any]:
            raise RuntimeError("boom")

        with audit.begin_tool_call(None) as call:
            with pytest.raises(RuntimeError):
                await async_run_audited_tool(call, boom)

    asyncio.run(scenario())


def test_create_helix_audit_delivery_defaults_to_required_and_refuses_misconfiguration(tmp_path: Path) -> None:
    recorder = FakeRecorder()
    http = FakeHttp(lambda wire: FakeResponse(201, {"entry": recorder.submit(AuditRecorderSubmission(producer_event=wire["producerEvent"]))}))
    sink = create_helix_audit_delivery("https://api.example.com", "k", http=http, ledger_id=None)
    assert sink.delivery == "required"
    assert trail_over(sink).record(dict(STARTED)).receipt is not None
    with pytest.raises(AuditDeliveryConfigError, match="durable outbox"):
        create_helix_audit_delivery("https://api.example.com", "k", delivery="buffered")
    with pytest.raises(AuditDeliveryConfigError, match="ephemeral"):
        create_helix_audit_delivery("https://api.example.com", "k", delivery="buffered", outbox="memory")
    with pytest.raises(AuditDeliveryConfigError, match="AAP-1"):
        create_helix_audit_delivery("https://api.example.com", "k", delivery="best-effort")
    buffered = create_helix_audit_delivery("https://api.example.com", "k", delivery="buffered", outbox_dir=str(tmp_path / "o"), http=http, flush_interval_seconds=0.01)
    try:
        trail_over(buffered, "buffered-source").record(dict(STARTED))
        deadline = time.time() + 2
        while len(recorder.entries) < 2 and time.time() < deadline:
            time.sleep(0.01)
        assert len(recorder.entries) == 2
    finally:
        buffered.stop()
    custom = create_helix_audit_delivery("https://api.example.com", "k", delivery="buffered", outbox=DurableOutbox(str(tmp_path / "custom")), flush_interval_seconds=60)
    custom.stop()
