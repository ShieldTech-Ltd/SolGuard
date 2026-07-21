"""End-to-end tests for the fail-closed Phase 1 gateway."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from decimal import Decimal
from typing import cast

import pytest

from solguard.contracts import (
    AgentMandate,
    Decision,
    PaymentRequest,
    ReasonCode,
    SigningAuthorization,
)
from solguard.detection import BehaviourEngine, DetectionResult
from solguard.gateway import PaymentGateway, build_simulated_gateway
from solguard.policy import MandatePolicyEngine, PolicyResult
from solguard.simulation import SimulatedSettlement, SimulatedSettlementResult
from tests.test_contracts import mandate_data, payment_data

NOW = datetime(2026, 7, 25, 10, 0, tzinfo=UTC)


def mandate(**overrides: object) -> AgentMandate:
    return AgentMandate.from_dict(mandate_data(**overrides))


def request(**overrides: object) -> PaymentRequest:
    return PaymentRequest.from_dict(payment_data(**overrides))


def timer(values: tuple[int, ...] = (1_000_000, 2_234_566)) -> Iterator[int]:
    return iter(values)


def gateway(
    *,
    policy: object | None = None,
    detection: object | None = None,
    settlement: object | None = None,
    timer_values: tuple[int, ...] = (1_000_000, 2_234_566),
) -> tuple[PaymentGateway, SimulatedSettlement]:
    adapter = (
        settlement
        if settlement is not None
        else SimulatedSettlement({"research-agent-01": Decimal("100")})
    )
    ticks = timer(timer_values)
    instance = PaymentGateway(
        policy=cast(
            MandatePolicyEngine,
            policy if policy is not None else MandatePolicyEngine({"research-agent-01": mandate()}),
        ),
        detection=cast(
            BehaviourEngine,
            detection if detection is not None else BehaviourEngine(),
        ),
        settlement=cast(SimulatedSettlement, adapter),
        clock=lambda: NOW,
        timer_ns=lambda: next(ticks),
    )
    return instance, cast(SimulatedSettlement, adapter)


def test_clean_payment_allows_settles_and_updates_clean_baseline() -> None:
    instance, adapter = gateway(timer_values=(1_000_000, 2_234_567, 3_000_000, 4_000_000))

    first = instance.process(request(amount="1"))
    second = instance.process(request(request_id="req_02", nonce="nonce-02", amount="1"))

    assert first.result.decision is Decision.ALLOW
    assert first.result.authorization is not None
    assert first.settlement is not None
    assert isinstance(first.settlement, SimulatedSettlementResult)
    assert first.settlement.balance_before == Decimal("100")
    assert first.settlement.balance_after == Decimal("99")
    assert first.result.evidence["latency_ms"] == "1.234567"
    assert first.result.evidence["settlement"] == first.settlement.to_dict()
    assert second.result.evidence["detection"] == {
        "amount_multiple": "1",
        "baseline_average": "1",
        "baseline_count": 1,
        "recipient_state": "KNOWN",
        "triggered_rules": [],
        "velocity_count": 2,
        "velocity_window_seconds": 10,
    }
    assert adapter.attempt_count == 2


def test_policy_block_never_reaches_simulated_settlement() -> None:
    instance, adapter = gateway()

    outcome = instance.process(request(amount="5"))

    assert outcome.result.decision is Decision.BLOCK
    assert ReasonCode.POLICY_AMOUNT_LIMIT in outcome.result.reason_codes
    assert outcome.result.authorization is None
    assert outcome.settlement is None
    assert adapter.attempt_count == 0


def test_detection_flag_maps_to_require_approval_without_settlement() -> None:
    engine = BehaviourEngine()
    engine.record_allowed(request(amount="1"))
    instance, adapter = gateway(detection=engine)

    outcome = instance.process(request(recipient="market-data-api", amount="1"))

    assert outcome.result.decision is Decision.REQUIRE_APPROVAL
    assert outcome.result.reason_codes == (ReasonCode.DETECTION_RECIPIENT_NOVEL,)
    assert outcome.result.authorization is None
    assert adapter.attempt_count == 0


def test_detection_block_outranks_other_results_without_settlement() -> None:
    engine = BehaviourEngine()
    for index in range(3):
        engine.record_allowed(
            request(request_id=f"seed-{index}", nonce=f"seed-{index}", amount="1")
        )
    instance, adapter = gateway(detection=engine)

    outcome = instance.process(request(amount="9"))

    assert outcome.result.decision is Decision.BLOCK
    assert ReasonCode.DETECTION_AMOUNT_ANOMALY in outcome.result.reason_codes
    assert adapter.attempt_count == 0


def test_malformed_payload_fails_closed_without_exposing_payload() -> None:
    instance, adapter = gateway()
    payload = payment_data(amount=0.1, metadata={"secret": "do-not-log"})

    outcome = instance.process(payload)

    assert outcome.result.decision is Decision.BLOCK
    assert outcome.result.reason_codes == (ReasonCode.REQUEST_INVALID,)
    assert outcome.result.request_id == "req_01"
    assert outcome.result.request_digest.startswith("sha256:")
    assert "do-not-log" not in str(outcome.result.to_dict())
    assert adapter.attempt_count == 0


def test_invalid_payload_without_request_id_uses_explicit_unparsed_identifier() -> None:
    instance, _ = gateway()

    outcome = instance.process({"amount": "1"})

    assert outcome.result.request_id == "unparsed"
    assert outcome.result.decision is Decision.BLOCK


def test_invalid_non_finite_payload_uses_safe_computed_digest_fallback() -> None:
    instance, _ = gateway()

    outcome = instance.process(payment_data(amount=float("nan")))

    assert outcome.result.decision is Decision.BLOCK
    assert outcome.result.request_digest.startswith("sha256:")


def test_insufficient_simulated_funds_becomes_block_without_baseline_update() -> None:
    policy = MandatePolicyEngine({"research-agent-01": mandate(max_single_payment="200")})
    detection = BehaviourEngine()
    instance, adapter = gateway(policy=policy, detection=detection)

    outcome = instance.process(request(amount="101"))

    assert outcome.result.decision is Decision.BLOCK
    assert outcome.result.reason_codes == (ReasonCode.SETTLEMENT_INSUFFICIENT_FUNDS,)
    assert outcome.result.evidence["settlement"] == {
        "amount": "101",
        "settlement_type": "SIMULATED",
        "status": "INSUFFICIENT_FUNDS",
    }
    assert adapter.balances["research-agent-01"] == Decimal("100")
    assert adapter.attempt_count == 1


class BrokenPolicy:
    def evaluate(self, payment: PaymentRequest) -> PolicyResult:
        del payment
        raise RuntimeError("private failure detail")


class BrokenDetection(BehaviourEngine):
    def evaluate(self, payment: PaymentRequest, *, observed_at: datetime) -> DetectionResult:
        del payment, observed_at
        raise RuntimeError("detection unavailable")


class BrokenSettlement(SimulatedSettlement):
    def settle(
        self, payment: PaymentRequest, authorization: SigningAuthorization
    ) -> SimulatedSettlementResult:
        del payment, authorization
        self._attempt_count += 1
        raise RuntimeError("wallet unavailable")


@pytest.mark.parametrize(
    ("component", "dependency", "expected_attempts"),
    [
        ("policy", BrokenPolicy(), 0),
        ("detection", BrokenDetection(), 0),
        (
            "settlement",
            BrokenSettlement({"research-agent-01": Decimal("100")}),
            1,
        ),
    ],
)
def test_critical_dependency_failure_blocks_without_leaking_error(
    component: str, dependency: object, expected_attempts: int
) -> None:
    if component == "policy":
        instance, adapter = gateway(policy=dependency)
    elif component == "detection":
        instance, adapter = gateway(detection=dependency)
    else:
        instance, adapter = gateway(settlement=dependency)

    outcome = instance.process(request())

    assert outcome.result.decision is Decision.BLOCK
    assert outcome.result.reason_codes == (ReasonCode.SYSTEM_FAILURE,)
    assert "private failure detail" not in str(outcome.result.to_dict())
    assert adapter.attempt_count == expected_attempts


def test_negative_timer_delta_is_clamped_to_zero() -> None:
    instance, _ = gateway(timer_values=(2_000_000, 1_000_000))

    outcome = instance.process(request())

    assert outcome.result.evidence["latency_ms"] == "0"


def test_build_simulated_gateway_rejects_unvalidated_mandate() -> None:
    with pytest.raises(ValueError, match="validated AgentMandate"):
        build_simulated_gateway(
            mandates={"research-agent-01": cast(AgentMandate, object())},
            balances={"research-agent-01": Decimal("100")},
        )


def test_build_simulated_gateway_creates_working_local_path() -> None:
    ticks = timer()
    instance = build_simulated_gateway(
        mandates={"research-agent-01": mandate()},
        balances={"research-agent-01": Decimal("100")},
        clock=lambda: NOW,
        timer_ns=lambda: next(ticks),
    )

    outcome = instance.process(request())

    assert outcome.result.decision is Decision.ALLOW
    assert outcome.settlement is not None
