"""Tests for basic request expiry and per-agent nonce replay protection."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from itertools import count

import pytest

from solguard.authorization import WalletAuthorizationGuard
from solguard.contracts import AgentMandate, Decision, PaymentRequest, ReasonCode
from solguard.detection import BehaviourEngine
from solguard.gateway import PaymentGateway
from solguard.integrity import InMemoryNonceStore, RequestIntegrityGuard
from solguard.policy import MandatePolicyEngine
from solguard.simulation import SimulatedSettlement
from tests.test_contracts import mandate_data, payment_data

NOW = datetime(2026, 7, 25, 10, 0, tzinfo=UTC)
AGENT_ID = "research-agent-01"


def payment(**overrides: object) -> PaymentRequest:
    return PaymentRequest.from_dict(payment_data(**overrides))


class TrackingNonceStore:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.seen: set[tuple[str, str]] = set()

    def consume_if_unused(self, agent_id: str, nonce: str) -> bool:
        key = (agent_id, nonce)
        self.calls.append(key)
        if key in self.seen:
            return False
        self.seen.add(key)
        return True


class FailingNonceStore:
    def consume_if_unused(self, agent_id: str, nonce: str) -> bool:
        del agent_id, nonce
        raise RuntimeError("private nonce-store failure")


class InvalidNonceStore:
    def consume_if_unused(self, agent_id: str, nonce: str) -> bool:
        del agent_id, nonce
        return None  # type: ignore[return-value]


def gateway(
    *,
    integrity: RequestIntegrityGuard | None = None,
    observed_at: datetime = NOW,
) -> tuple[PaymentGateway, SimulatedSettlement]:
    active_mandate = AgentMandate.from_dict(mandate_data())
    settlement = SimulatedSettlement(
        {AGENT_ID: Decimal("100")},
        authorization_guard=WalletAuthorizationGuard(clock=lambda: observed_at),
    )
    ticks = count(start=1_000_000, step=1_000_000)
    instance = PaymentGateway(
        policy=MandatePolicyEngine({AGENT_ID: active_mandate}),
        detection=BehaviourEngine(),
        integrity=integrity,
        settlement=settlement,
        clock=lambda: observed_at,
        timer_ns=lambda: next(ticks),
    )
    return instance, settlement


def test_fresh_nonce_is_consumed_once_then_rejected_as_replay() -> None:
    guard = RequestIntegrityGuard()
    request = payment()

    fresh = guard.evaluate(request, observed_at=NOW)
    replayed = guard.evaluate(request, observed_at=NOW + timedelta(seconds=1))

    assert fresh.decision is Decision.ALLOW
    assert fresh.reason_codes == ()
    assert fresh.evidence["nonce_state"] == "CONSUMED"
    assert replayed.decision is Decision.BLOCK
    assert replayed.reason_codes == (ReasonCode.REQUEST_REPLAYED,)
    assert replayed.evidence["nonce_state"] == "ALREADY_CONSUMED"


def test_request_is_fresh_immediately_before_expiry() -> None:
    guard = RequestIntegrityGuard()
    request = payment()

    result = guard.evaluate(request, observed_at=request.expires_at - timedelta(microseconds=1))

    assert result.decision is Decision.ALLOW


def test_request_is_expired_at_exact_boundary_without_consuming_nonce() -> None:
    store = TrackingNonceStore()
    guard = RequestIntegrityGuard(store)
    request = payment()

    expired = guard.evaluate(request, observed_at=request.expires_at)
    fresh = guard.evaluate(request, observed_at=NOW)

    assert expired.decision is Decision.BLOCK
    assert expired.reason_codes == (ReasonCode.REQUEST_EXPIRED,)
    assert expired.evidence["nonce_state"] == "NOT_CONSUMED"
    assert fresh.decision is Decision.ALLOW
    assert store.calls == [(AGENT_ID, request.nonce)]


def test_same_nonce_is_isolated_between_agents() -> None:
    guard = RequestIntegrityGuard()
    first = payment(nonce="shared-nonce")
    second = payment(
        request_id="other-request",
        agent_id="other-agent",
        nonce="shared-nonce",
    )

    assert guard.evaluate(first, observed_at=NOW).decision is Decision.ALLOW
    assert guard.evaluate(second, observed_at=NOW).decision is Decision.ALLOW


def test_naive_integrity_clock_is_rejected() -> None:
    guard = RequestIntegrityGuard()

    with pytest.raises(ValueError, match="timezone"):
        guard.evaluate(payment(), observed_at=datetime(2026, 7, 25, 10, 0))


def test_nonce_store_must_return_boolean() -> None:
    guard = RequestIntegrityGuard(InvalidNonceStore())

    with pytest.raises(TypeError, match="boolean"):
        guard.evaluate(payment(), observed_at=NOW)


def test_gateway_allows_fresh_request_then_blocks_reused_nonce_before_settlement() -> None:
    instance, settlement = gateway()
    request = payment()

    first = instance.process(request)
    replayed = instance.process(request)

    assert first.result.decision is Decision.ALLOW
    assert first.result.evidence["integrity"] == {
        "expires_at": "2026-07-25T10:01:00Z",
        "nonce_state": "CONSUMED",
        "observed_at": "2026-07-25T10:00:00Z",
    }
    assert replayed.result.decision is Decision.BLOCK
    assert replayed.result.reason_codes == (ReasonCode.REQUEST_REPLAYED,)
    assert replayed.result.authorization is None
    assert replayed.settlement is None
    assert settlement.attempt_count == 1


def test_gateway_blocks_expired_request_before_settlement() -> None:
    request = payment()
    instance, settlement = gateway(observed_at=request.expires_at)

    outcome = instance.process(request)

    assert outcome.result.decision is Decision.BLOCK
    assert outcome.result.reason_codes == (ReasonCode.REQUEST_EXPIRED,)
    assert outcome.result.evidence["stage"] == "REQUEST_INTEGRITY"
    assert outcome.result.authorization is None
    assert settlement.attempt_count == 0


def test_gateway_rejects_missing_nonce_as_invalid_contract() -> None:
    store = TrackingNonceStore()
    instance, settlement = gateway(integrity=RequestIntegrityGuard(store))

    outcome = instance.process(payment_data(nonce=""))

    assert outcome.result.decision is Decision.BLOCK
    assert outcome.result.reason_codes == (ReasonCode.REQUEST_INVALID,)
    assert store.calls == []
    assert settlement.attempt_count == 0


def test_nonce_store_failure_fails_closed_without_leaking_details() -> None:
    instance, settlement = gateway(integrity=RequestIntegrityGuard(FailingNonceStore()))

    outcome = instance.process(payment())

    assert outcome.result.decision is Decision.BLOCK
    assert outcome.result.reason_codes == (ReasonCode.SYSTEM_FAILURE,)
    assert outcome.result.evidence["stage"] == "SECURITY_PATH"
    assert "private nonce-store failure" not in str(outcome.result.to_dict())
    assert outcome.result.authorization is None
    assert settlement.attempt_count == 0


def test_policy_blocked_request_consumes_nonce_at_integrity_boundary() -> None:
    instance, settlement = gateway()

    policy_blocked = instance.process(payment(amount="3"))
    replayed = instance.process(payment(amount="1"))

    assert policy_blocked.result.decision is Decision.BLOCK
    assert policy_blocked.result.reason_codes == (ReasonCode.POLICY_AMOUNT_LIMIT,)
    assert replayed.result.reason_codes == (ReasonCode.REQUEST_REPLAYED,)
    assert settlement.attempt_count == 0


def test_in_memory_nonce_store_is_atomic_for_sequential_consumption() -> None:
    store = InMemoryNonceStore()

    assert store.consume_if_unused(AGENT_ID, "nonce") is True
    assert store.consume_if_unused(AGENT_ID, "nonce") is False
    assert store.consume_if_unused("other-agent", "nonce") is True
