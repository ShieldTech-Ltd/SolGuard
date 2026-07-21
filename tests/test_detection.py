"""Exact-threshold tests for the four SolGuard detection rules."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from solguard.contracts import PaymentRequest, ReasonCode
from solguard.detection import BehaviourEngine, DetectionSignal
from tests.test_contracts import payment_data

BASE_TIME = datetime(2026, 7, 25, 10, 0, tzinfo=UTC)


def request(**overrides: object) -> PaymentRequest:
    """Build a valid payment request for detection tests."""

    return PaymentRequest.from_dict(payment_data(**overrides))


def seed_clean_baseline(
    engine: BehaviourEngine,
    *,
    amounts: tuple[str, ...] = ("10", "10", "10"),
    recipient: str = "weather-api",
    agent_id: str = "research-agent-01",
) -> None:
    """Record only explicitly allowed traffic as the clean baseline."""

    for index, amount in enumerate(amounts):
        engine.record_allowed(
            request(
                request_id=f"seed-{index}",
                nonce=f"seed-nonce-{index}",
                agent_id=agent_id,
                amount=amount,
                recipient=recipient,
            )
        )


def evaluate_attempts(
    engine: BehaviourEngine,
    payment: PaymentRequest,
    *,
    count: int,
    start: datetime = BASE_TIME,
) -> list[DetectionSignal]:
    """Evaluate a deterministic burst one second apart."""

    return [
        engine.evaluate(payment, observed_at=start + timedelta(seconds=index)).signal
        for index in range(count)
    ]


def test_clean_payment_has_no_triggered_rule() -> None:
    engine = BehaviourEngine()
    seed_clean_baseline(engine)

    result = engine.evaluate(request(amount="10"), observed_at=BASE_TIME)

    assert result.signal is DetectionSignal.CLEAN
    assert result.reason_codes == ()
    assert result.evidence == {
        "amount_multiple": "1",
        "baseline_average": "10",
        "baseline_count": 3,
        "recipient_state": "KNOWN",
        "triggered_rules": [],
        "velocity_count": 1,
        "velocity_window_seconds": 10,
    }


def test_velocity_flags_on_fifth_attempt_and_never_blocks_by_itself() -> None:
    engine = BehaviourEngine()
    seed_clean_baseline(engine)
    payment = request(amount="10")

    signals = evaluate_attempts(engine, payment, count=6)
    result = engine.evaluate(payment, observed_at=BASE_TIME + timedelta(seconds=6))

    assert signals[:4] == [DetectionSignal.CLEAN] * 4
    assert signals[4:] == [DetectionSignal.FLAG, DetectionSignal.FLAG]
    assert result.signal is DetectionSignal.FLAG
    assert result.reason_codes == (ReasonCode.DETECTION_VELOCITY,)


def test_attempt_outside_ten_second_window_is_removed() -> None:
    engine = BehaviourEngine()
    seed_clean_baseline(engine)
    payment = request(amount="10")
    engine.evaluate(payment, observed_at=BASE_TIME)

    result = engine.evaluate(payment, observed_at=BASE_TIME + timedelta(seconds=11))

    assert result.signal is DetectionSignal.CLEAN
    assert result.evidence["velocity_count"] == 1


def test_attempt_at_exact_window_boundary_is_included() -> None:
    engine = BehaviourEngine()
    seed_clean_baseline(engine)
    payment = request(amount="10")
    for seconds in (0, 2, 4, 6):
        engine.evaluate(payment, observed_at=BASE_TIME + timedelta(seconds=seconds))

    result = engine.evaluate(payment, observed_at=BASE_TIME + timedelta(seconds=10))

    assert result.signal is DetectionSignal.FLAG
    assert result.evidence["velocity_count"] == 5


def test_amount_anomaly_requires_three_clean_warmup_payments() -> None:
    engine = BehaviourEngine()
    seed_clean_baseline(engine, amounts=("10", "10"))

    result = engine.evaluate(request(amount="100"), observed_at=BASE_TIME)

    assert result.signal is DetectionSignal.CLEAN
    assert ReasonCode.DETECTION_AMOUNT_ANOMALY not in result.reason_codes
    assert result.evidence["baseline_count"] == 2


def test_amount_exactly_eight_times_average_blocks() -> None:
    engine = BehaviourEngine()
    seed_clean_baseline(engine)

    result = engine.evaluate(request(amount="80"), observed_at=BASE_TIME)

    assert result.signal is DetectionSignal.BLOCK
    assert result.reason_codes == (ReasonCode.DETECTION_AMOUNT_ANOMALY,)
    assert result.evidence["amount_multiple"] == "8"
    assert result.evidence["triggered_rules"] == ["AMOUNT_ANOMALY"]


def test_amount_greater_than_eight_times_average_blocks() -> None:
    engine = BehaviourEngine()
    seed_clean_baseline(engine)

    result = engine.evaluate(request(amount="80.01"), observed_at=BASE_TIME)

    assert result.signal is DetectionSignal.BLOCK
    assert result.reason_codes == (ReasonCode.DETECTION_AMOUNT_ANOMALY,)
    assert result.evidence["triggered_rules"] == ["AMOUNT_ANOMALY"]


def test_first_seen_recipient_flags_after_history_exists() -> None:
    engine = BehaviourEngine()
    seed_clean_baseline(engine)

    result = engine.evaluate(request(recipient="new-api", amount="10"), observed_at=BASE_TIME)

    assert result.signal is DetectionSignal.FLAG
    assert result.reason_codes == (ReasonCode.DETECTION_RECIPIENT_NOVEL,)
    assert result.evidence["recipient_state"] == "FIRST_SEEN"


def test_first_payment_has_no_recipient_novelty_flag() -> None:
    engine = BehaviourEngine()

    result = engine.evaluate(request(recipient="new-api"), observed_at=BASE_TIME)

    assert result.signal is DetectionSignal.CLEAN
    assert result.evidence["recipient_state"] == "NO_HISTORY"
    assert result.evidence["baseline_average"] is None
    assert result.evidence["amount_multiple"] is None


def test_compound_drain_blocks_new_recipient_over_two_times_average_at_velocity() -> None:
    engine = BehaviourEngine()
    seed_clean_baseline(engine)
    payment = request(recipient="attacker-wallet", amount="20.01")

    evaluate_attempts(engine, payment, count=4)
    result = engine.evaluate(payment, observed_at=BASE_TIME + timedelta(seconds=4))

    assert result.signal is DetectionSignal.BLOCK
    assert result.reason_codes == (
        ReasonCode.DETECTION_VELOCITY,
        ReasonCode.DETECTION_RECIPIENT_NOVEL,
        ReasonCode.DETECTION_COMPOUND_DRAIN,
    )
    assert result.evidence["triggered_rules"] == [
        "VELOCITY",
        "RECIPIENT_NOVELTY",
        "DRAIN_COMBINATION",
    ]


def test_compound_drain_blocks_at_exactly_two_times_average() -> None:
    engine = BehaviourEngine()
    seed_clean_baseline(engine)
    payment = request(recipient="new-api", amount="20")

    evaluate_attempts(engine, payment, count=4)
    result = engine.evaluate(payment, observed_at=BASE_TIME + timedelta(seconds=4))

    assert result.signal is DetectionSignal.BLOCK
    assert result.reason_codes == (
        ReasonCode.DETECTION_VELOCITY,
        ReasonCode.DETECTION_RECIPIENT_NOVEL,
        ReasonCode.DETECTION_COMPOUND_DRAIN,
    )


def test_amount_anomaly_and_compound_rules_report_together() -> None:
    engine = BehaviourEngine()
    seed_clean_baseline(engine)
    payment = request(recipient="attacker-wallet", amount="100")

    evaluate_attempts(engine, payment, count=4)
    result = engine.evaluate(payment, observed_at=BASE_TIME + timedelta(seconds=4))

    assert result.signal is DetectionSignal.BLOCK
    assert result.reason_codes == (
        ReasonCode.DETECTION_VELOCITY,
        ReasonCode.DETECTION_AMOUNT_ANOMALY,
        ReasonCode.DETECTION_RECIPIENT_NOVEL,
        ReasonCode.DETECTION_COMPOUND_DRAIN,
    )


def test_rejected_or_pending_attempts_cannot_poison_clean_baseline() -> None:
    engine = BehaviourEngine()
    seed_clean_baseline(engine)
    huge = request(recipient="attacker-wallet", amount="1000")
    blocked = engine.evaluate(huge, observed_at=BASE_TIME)

    later = engine.evaluate(request(amount="10"), observed_at=BASE_TIME + timedelta(seconds=20))

    assert blocked.signal is DetectionSignal.BLOCK
    assert later.evidence["baseline_average"] == "10"
    assert later.evidence["baseline_count"] == 3


def test_recording_allowed_payment_updates_amount_and_recipient_baseline() -> None:
    engine = BehaviourEngine()
    initial = request(recipient="first-api", amount="4")
    engine.record_allowed(initial)

    result = engine.evaluate(request(recipient="first-api", amount="8"), observed_at=BASE_TIME)

    assert result.signal is DetectionSignal.CLEAN
    assert result.evidence["baseline_count"] == 1
    assert result.evidence["baseline_average"] == "4"
    assert result.evidence["recipient_state"] == "KNOWN"


def test_detection_state_is_isolated_per_agent() -> None:
    engine = BehaviourEngine()
    seed_clean_baseline(engine, agent_id="other-agent", recipient="other-api")

    result = engine.evaluate(request(), observed_at=BASE_TIME)

    assert result.signal is DetectionSignal.CLEAN
    assert result.evidence["baseline_count"] == 0
    assert result.evidence["velocity_count"] == 1


def test_naive_observation_time_is_rejected() -> None:
    engine = BehaviourEngine()

    with pytest.raises(ValueError, match="timezone"):
        engine.evaluate(request(), observed_at=datetime(2026, 7, 25, 10, 0))
