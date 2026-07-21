"""Tests for canonical audit receipts and the bounded local event stream."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal
from typing import cast

import pytest

from solguard.audit import (
    AUDIT_SCHEMA_VERSION,
    AuditEvent,
    AuditEventStream,
    compute_receipt_digest,
    policy_digest,
    receipt_from_dict,
)
from solguard.contracts import AgentMandate, Decision, JsonValue, PaymentRequest
from solguard.gateway import GatewayOutcome, build_simulated_gateway
from solguard.privacy import MetadataSanitizer
from tests.test_contracts import mandate_data, payment_data

NOW = datetime(2026, 7, 25, 10, 0, tzinfo=UTC)


def mandate() -> AgentMandate:
    return AgentMandate.from_dict(mandate_data(allowed_recipients=[]))


def request(**overrides: object) -> PaymentRequest:
    return PaymentRequest.from_dict(payment_data(**overrides))


def allowed_outcome(payment: PaymentRequest) -> GatewayOutcome:
    ticks = iter((1_000_000, 2_000_000))
    gateway = build_simulated_gateway(
        mandates={payment.agent_id: mandate()},
        balances={payment.agent_id: Decimal("100")},
        clock=lambda: NOW,
        timer_ns=lambda: next(ticks),
    )
    return gateway.process(payment)


def publish(
    stream: AuditEventStream,
    payment: PaymentRequest | None = None,
) -> AuditEvent:
    actual = payment or request()
    return stream.publish(
        request=actual,
        outcome=allowed_outcome(actual),
        mandate=mandate(),
        sanitized_metadata=MetadataSanitizer().sanitize_payment(actual),
    )


def test_policy_digest_is_stable_for_equivalent_mandate() -> None:
    first = mandate()
    second = AgentMandate.from_dict(
        mandate_data(allowed_recipients=[], blocked_recipients=["attacker-wallet"])
    )

    assert policy_digest(first) == policy_digest(second)
    assert policy_digest(first).startswith("sha256:")


def test_publish_creates_complete_sanitized_receipt() -> None:
    stream = AuditEventStream()
    payment = request(metadata={"contact": "alice@example.com", "scenario": "normal"})

    event = publish(stream, payment)
    receipt = event.to_dict()

    assert receipt["schema_version"] == AUDIT_SCHEMA_VERSION
    assert receipt["sequence"] == 1
    assert receipt["decision"] == "ALLOW"
    assert receipt["request_digest"] == payment.digest
    assert str(receipt["policy_version"]).startswith("sha256:")
    assert receipt["settlement_reference"] is not None
    assert receipt["signing_state"] == "SIGNED_SIMULATED"
    assert receipt["traffic_type"] == "SIMULATED"
    assert receipt["previous_receipt_digest"] is None
    assert str(receipt["receipt_digest"]).startswith("sha256:")
    rendered = json.dumps(receipt)
    assert "alice@example.com" not in rendered
    assert "EMAIL" in rendered
    assert stream.verify_receipt(event)


def test_dashboard_dict_contains_safe_runtime_fields() -> None:
    event = publish(AuditEventStream())

    dashboard = event.dashboard_dict()

    assert dashboard["decision"] == "ALLOW"
    assert dashboard["receipt_digest"] == event.receipt_digest
    assert dashboard["request_id"] == "req_01"
    assert dashboard["traffic_type"] == "SIMULATED"


def test_event_properties_are_read_from_immutable_canonical_payload() -> None:
    event = publish(AuditEventStream())
    copy = cast(dict[str, JsonValue], dict(event.payload))
    copy["amount"] = "999"

    assert event.sequence == 1
    assert event.decision is Decision.ALLOW
    assert event.amount == Decimal("0.05")
    assert event.latency_ms == "1"
    assert event.payload["amount"] == "0.05"


def test_chained_receipts_verify_in_order() -> None:
    stream = AuditEventStream()
    first = publish(stream)
    second = publish(
        stream,
        request(request_id="req_02", nonce="nonce-02"),
    )

    events = stream.snapshot()
    assert events == (first, second)
    assert second.previous_receipt_digest == first.receipt_digest
    assert AuditEventStream.verify_chain(events)


def test_modified_receipt_content_changes_expected_digest() -> None:
    event = publish(AuditEventStream())
    changed = dict(event.payload)
    changed["amount"] = "999"

    changed_digest = compute_receipt_digest(changed, event.previous_receipt_digest)

    assert changed_digest != event.receipt_digest


def test_verify_receipt_detects_wrong_digest() -> None:
    event = publish(AuditEventStream())
    tampered = AuditEvent(
        _payload_json=event._payload_json,
        previous_receipt_digest=event.previous_receipt_digest,
        receipt_digest="sha256:wrong",
    )

    assert not AuditEventStream.verify_receipt(tampered)
    assert not AuditEventStream.verify_chain((tampered,))


def test_verify_chain_detects_broken_link_and_sequence() -> None:
    stream = AuditEventStream()
    first = publish(stream)
    second = publish(stream, request(request_id="req_02", nonce="nonce-02"))
    wrong_link = AuditEvent.create(second.payload, previous_receipt_digest="sha256:wrong")
    wrong_sequence_payload = dict(second.payload)
    wrong_sequence_payload["sequence"] = 10
    wrong_sequence = AuditEvent.create(
        wrong_sequence_payload, previous_receipt_digest=first.receipt_digest
    )

    assert not AuditEventStream.verify_chain((first, wrong_link))
    assert not AuditEventStream.verify_chain((first, wrong_sequence))


def test_stream_bounds_retention_without_breaking_retained_chain() -> None:
    stream = AuditEventStream(max_events=2)
    publish(stream)
    second = publish(stream, request(request_id="req_02", nonce="nonce-02"))
    third = publish(stream, request(request_id="req_03", nonce="nonce-03"))

    assert stream.snapshot() == (second, third)
    assert AuditEventStream.verify_chain(stream.snapshot())
    assert second.previous_receipt_digest is not None


def test_stream_requires_positive_retention() -> None:
    with pytest.raises(ValueError, match="positive"):
        AuditEventStream(max_events=0)


def test_subscriber_receives_ordered_events_and_can_unsubscribe() -> None:
    stream = AuditEventStream()
    received: list[int] = []
    unsubscribe = stream.subscribe(lambda event: received.append(event.sequence))

    publish(stream)
    publish(stream, request(request_id="req_02", nonce="nonce-02"))
    unsubscribe()
    unsubscribe()
    publish(stream, request(request_id="req_03", nonce="nonce-03"))

    assert received == [1, 2]


def test_late_subscriber_replays_retained_events_or_can_skip_replay() -> None:
    stream = AuditEventStream()
    publish(stream)
    publish(stream, request(request_id="req_02", nonce="nonce-02"))
    replayed: list[int] = []
    future_only: list[int] = []

    stream.subscribe(lambda event: replayed.append(event.sequence))
    stream.subscribe(lambda event: future_only.append(event.sequence), replay=False)
    publish(stream, request(request_id="req_03", nonce="nonce-03"))

    assert replayed == [1, 2, 3]
    assert future_only == [3]


def test_replay_failure_is_isolated_from_subscription() -> None:
    stream = AuditEventStream()
    publish(stream)

    def broken(_: AuditEvent) -> None:
        raise RuntimeError("replay consumer unavailable")

    unsubscribe = stream.subscribe(broken)
    unsubscribe()


def test_failing_subscriber_does_not_block_other_consumers() -> None:
    stream = AuditEventStream()
    received: list[int] = []

    def broken(_: AuditEvent) -> None:
        raise RuntimeError("consumer unavailable")

    stream.subscribe(broken)
    stream.subscribe(lambda event: received.append(event.sequence))

    event = publish(stream)

    assert received == [1]
    assert stream.snapshot() == (event,)


def test_receipt_round_trip_reconstructs_portable_event() -> None:
    event = publish(AuditEventStream())

    reconstructed = receipt_from_dict(event.to_dict())

    assert reconstructed == event
    assert AuditEventStream.verify_receipt(reconstructed)


def test_receipt_reconstruction_rejects_tampered_content() -> None:
    event = publish(AuditEventStream())
    value = event.to_dict()
    value["amount"] = "999"

    with pytest.raises(ValueError, match="verification failed"):
        receipt_from_dict(value)


@pytest.mark.parametrize(
    "value",
    [
        {},
        {"previous_receipt_digest": 1, "receipt_digest": "sha256:x"},
        {"previous_receipt_digest": None, "receipt_digest": 1},
    ],
)
def test_receipt_reconstruction_rejects_invalid_digest_fields(
    value: dict[str, JsonValue],
) -> None:
    with pytest.raises(ValueError):
        receipt_from_dict(value)


@pytest.mark.parametrize(
    "field_value",
    [
        {"observed_at": "not-a-time"},
        {"sequence": "one"},
        {"sequence": True},
        {"sequence": 0},
        {"decision": "UNKNOWN"},
        {"schema_version": "2.0"},
    ],
)
def test_receipt_reconstruction_rejects_invalid_required_payload(
    field_value: dict[str, JsonValue],
) -> None:
    event = publish(AuditEventStream())
    value = event.to_dict()
    value.update(field_value)

    with pytest.raises((ValueError, KeyError)):
        receipt_from_dict(value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("receipt_digest", "invalid"),
        ("receipt_digest", f"sha256:{'z' * 64}"),
        ("previous_receipt_digest", "invalid"),
    ],
)
def test_receipt_reconstruction_rejects_invalid_digest_format(field: str, value: str) -> None:
    event = publish(AuditEventStream())
    receipt = event.to_dict()
    receipt[field] = value

    with pytest.raises(ValueError, match="SHA-256"):
        receipt_from_dict(receipt)


def test_receipt_reconstruction_rejects_non_string_digest_types() -> None:
    event = publish(AuditEventStream())
    receipt = event.to_dict()
    receipt["previous_receipt_digest"] = 1
    with pytest.raises(ValueError, match="string or null"):
        receipt_from_dict(receipt)

    receipt = event.to_dict()
    receipt["receipt_digest"] = 1
    with pytest.raises(ValueError, match="must be a string"):
        receipt_from_dict(receipt)


def test_receipt_reconstruction_rejects_unknown_field() -> None:
    event = publish(AuditEventStream())
    receipt = event.to_dict()
    receipt["unknown"] = "value"

    with pytest.raises(ValueError, match="schema"):
        receipt_from_dict(receipt)
