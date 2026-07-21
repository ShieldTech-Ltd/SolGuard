"""Adversarial and end-to-end tests for the SolGuard security boundary."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from itertools import count
from typing import cast

import pytest

from solguard.audit import AuditEventStream
from solguard.contracts import (
    AgentMandate,
    Decision,
    PaymentRequest,
    ReasonCode,
    SigningAuthorization,
)
from solguard.detection import BehaviourEngine, DetectionResult
from solguard.gateway import PaymentGateway
from solguard.policy import MandatePolicyEngine, PolicyResult
from solguard.privacy import MetadataSanitizer
from solguard.simulation import (
    SimulatedSettlement,
    SimulatedSettlementError,
    SimulatedSettlementResult,
)
from tests.test_contracts import mandate_data, payment_data

NOW = datetime(2026, 7, 25, 10, 0, tzinfo=UTC)
AGENT_ID = "research-agent-01"


class MutableClock:
    """Deterministic clock controlled by each adversarial scenario."""

    def __init__(self, current: datetime = NOW) -> None:
        self.current = current

    def __call__(self) -> datetime:
        return self.current


def mandate(*, max_payment: str = "1000") -> AgentMandate:
    """Build an open-recipient mandate with one explicit hard block."""

    return AgentMandate.from_dict(
        mandate_data(
            max_single_payment=max_payment,
            allowed_recipients=[],
            blocked_recipients=["prohibited-wallet"],
        )
    )


def payment(sequence: int = 1, **overrides: object) -> PaymentRequest:
    """Build a unique canonical request for repeated gateway attempts."""

    data = payment_data(
        request_id=f"security-{sequence}",
        nonce=f"security-nonce-{sequence}",
        amount="10",
    )
    data.update(overrides)
    return PaymentRequest.from_dict(data)


def security_gateway(
    *,
    engine: BehaviourEngine | None = None,
    active_mandate: AgentMandate | None = None,
    policy: object | None = None,
    detection: object | None = None,
    settlement: object | None = None,
) -> tuple[PaymentGateway, BehaviourEngine, SimulatedSettlement, MutableClock]:
    """Create an isolated full gateway with deterministic local dependencies."""

    behaviour = engine or BehaviourEngine()
    configured_mandate = active_mandate or mandate()
    adapter = settlement or SimulatedSettlement({AGENT_ID: Decimal("10000")})
    clock = MutableClock()
    ticks = count(start=1_000_000, step=1_000_000)
    gateway = PaymentGateway(
        policy=cast(
            MandatePolicyEngine,
            policy or MandatePolicyEngine({AGENT_ID: configured_mandate}),
        ),
        detection=cast(BehaviourEngine, detection or behaviour),
        settlement=cast(SimulatedSettlement, adapter),
        clock=clock,
        timer_ns=lambda: next(ticks),
    )
    return gateway, behaviour, cast(SimulatedSettlement, adapter), clock


def seed_clean_baseline(engine: BehaviourEngine) -> None:
    """Establish the three-payment clean baseline required by amount rules."""

    for sequence in range(1, 4):
        engine.record_allowed(payment(sequence))


def test_normal_payment_and_hard_policy_boundary_reach_settlement_only_when_allowed() -> None:
    gateway, _, settlement, _ = security_gateway(active_mandate=mandate(max_payment="100"))

    boundary = gateway.process(payment(amount="100"))
    over_limit = gateway.process(payment(2, amount="100.01"))

    assert boundary.result.decision is Decision.ALLOW
    assert boundary.result.authorization is not None
    assert boundary.settlement is not None
    assert over_limit.result.decision is Decision.BLOCK
    assert over_limit.result.reason_codes == (ReasonCode.POLICY_AMOUNT_LIMIT,)
    assert over_limit.result.authorization is None
    assert over_limit.settlement is None
    assert settlement.attempt_count == 1


def test_velocity_alone_requires_approval_on_exact_fifth_attempt() -> None:
    engine = BehaviourEngine()
    seed_clean_baseline(engine)
    gateway, _, settlement, clock = security_gateway(engine=engine)

    outcomes = []
    for sequence in range(1, 6):
        clock.current = NOW + timedelta(seconds=sequence - 1)
        outcomes.append(gateway.process(payment(10 + sequence)))

    assert [outcome.result.decision for outcome in outcomes[:4]] == [Decision.ALLOW] * 4
    assert outcomes[4].result.decision is Decision.REQUIRE_APPROVAL
    assert outcomes[4].result.reason_codes == (ReasonCode.DETECTION_VELOCITY,)
    assert outcomes[4].result.authorization is None
    assert outcomes[4].settlement is None
    assert settlement.attempt_count == 4


def test_first_seen_recipient_alone_requires_approval_without_settlement() -> None:
    engine = BehaviourEngine()
    seed_clean_baseline(engine)
    gateway, _, settlement, _ = security_gateway(engine=engine)

    outcome = gateway.process(payment(recipient="new-service"))

    assert outcome.result.decision is Decision.REQUIRE_APPROVAL
    assert outcome.result.reason_codes == (ReasonCode.DETECTION_RECIPIENT_NOVEL,)
    assert outcome.result.authorization is None
    assert outcome.settlement is None
    assert settlement.attempt_count == 0


@pytest.mark.parametrize(
    ("amount", "expected_decision", "expected_anomaly"),
    [
        ("80", Decision.ALLOW, False),
        ("80.01", Decision.BLOCK, True),
    ],
)
def test_amount_anomaly_enforces_exact_greater_than_eight_times_boundary(
    amount: str,
    expected_decision: Decision,
    expected_anomaly: bool,
) -> None:
    engine = BehaviourEngine()
    seed_clean_baseline(engine)
    gateway, _, settlement, _ = security_gateway(engine=engine)

    outcome = gateway.process(payment(amount=amount))

    assert outcome.result.decision is expected_decision
    assert (ReasonCode.DETECTION_AMOUNT_ANOMALY in outcome.result.reason_codes) is expected_anomaly
    assert settlement.attempt_count == (0 if expected_anomaly else 1)


@pytest.mark.parametrize(
    ("amount", "expected_decision", "expected_compound"),
    [
        ("20", Decision.REQUIRE_APPROVAL, False),
        ("20.01", Decision.BLOCK, True),
    ],
)
def test_compound_drain_enforces_exact_greater_than_twice_average_boundary(
    amount: str,
    expected_decision: Decision,
    expected_compound: bool,
) -> None:
    engine = BehaviourEngine()
    seed_clean_baseline(engine)
    attempted = payment(recipient="drain-wallet", amount=amount)
    for seconds in range(4):
        engine.evaluate(attempted, observed_at=NOW + timedelta(seconds=seconds))
    gateway, _, settlement, clock = security_gateway(engine=engine)
    clock.current = NOW + timedelta(seconds=4)

    outcome = gateway.process(attempted)

    assert outcome.result.decision is expected_decision
    assert ReasonCode.DETECTION_VELOCITY in outcome.result.reason_codes
    assert ReasonCode.DETECTION_RECIPIENT_NOVEL in outcome.result.reason_codes
    assert (ReasonCode.DETECTION_COMPOUND_DRAIN in outcome.result.reason_codes) is expected_compound
    assert outcome.result.authorization is None
    assert settlement.attempt_count == 0


def test_blocked_poisoning_attempt_cannot_change_clean_baseline() -> None:
    engine = BehaviourEngine()
    seed_clean_baseline(engine)
    gateway, _, settlement, clock = security_gateway(engine=engine)

    blocked = gateway.process(payment(recipient="drain-wallet", amount="1000"))
    clock.current = NOW + timedelta(seconds=20)
    later = gateway.process(payment(2))
    detection_evidence = cast(dict[str, object], later.result.evidence["detection"])

    assert blocked.result.decision is Decision.BLOCK
    assert blocked.result.authorization is None
    assert later.result.decision is Decision.ALLOW
    assert detection_evidence["baseline_average"] == "10"
    assert detection_evidence["baseline_count"] == 3
    assert settlement.attempt_count == 1


def test_sensitive_metadata_is_absent_from_portable_audit_receipt() -> None:
    gateway, _, _, _ = security_gateway()
    request = payment(
        metadata={
            "authorization": "Bearer secret-token-value",
            "contact": "owner@example.com",
        }
    )
    outcome = gateway.process(request)
    stream = AuditEventStream()

    event = stream.publish(
        request=request,
        outcome=outcome,
        mandate=mandate(),
        sanitized_metadata=MetadataSanitizer().sanitize_payment(request),
    )
    encoded = json.dumps(event.to_dict())

    assert "secret-token-value" not in encoded
    assert "owner@example.com" not in encoded
    assert "[REDACTED:BEARER_TOKEN]" in encoded
    assert "[REDACTED:EMAIL]" in encoded


class ExplodingPolicy:
    def evaluate(self, request: PaymentRequest) -> PolicyResult:
        del request
        raise RuntimeError("confidential policy failure")


class ExplodingDetection(BehaviourEngine):
    def evaluate(self, request: PaymentRequest, *, observed_at: datetime) -> DetectionResult:
        del request, observed_at
        raise RuntimeError("confidential detection failure")


class ExplodingSettlement(SimulatedSettlement):
    def settle(
        self,
        request: PaymentRequest,
        authorization: SigningAuthorization,
    ) -> SimulatedSettlementResult:
        del request, authorization
        self._attempt_count += 1
        raise RuntimeError("confidential signer failure")


@pytest.mark.parametrize(
    ("component", "dependency", "expected_attempts"),
    [
        ("policy", ExplodingPolicy(), 0),
        ("detection", ExplodingDetection(), 0),
        ("settlement", ExplodingSettlement({AGENT_ID: Decimal("10000")}), 1),
    ],
)
def test_security_dependency_failures_block_without_leaking_details(
    component: str,
    dependency: object,
    expected_attempts: int,
) -> None:
    if component == "policy":
        gateway, _, settlement, _ = security_gateway(policy=dependency)
    elif component == "detection":
        gateway, _, settlement, _ = security_gateway(detection=dependency)
    else:
        gateway, _, settlement, _ = security_gateway(settlement=dependency)

    outcome = gateway.process(payment())

    assert outcome.result.decision is Decision.BLOCK
    assert outcome.result.reason_codes == (ReasonCode.SYSTEM_FAILURE,)
    assert outcome.result.authorization is None
    assert outcome.settlement is None
    assert "confidential" not in str(outcome.result.to_dict())
    assert settlement.attempt_count == expected_attempts


def test_hard_recipient_block_cannot_be_reduced_by_clean_behaviour() -> None:
    gateway, _, settlement, _ = security_gateway()

    outcome = gateway.process(payment(recipient="prohibited-wallet"))

    assert outcome.result.decision is Decision.BLOCK
    assert ReasonCode.POLICY_RECIPIENT_BLOCKED in outcome.result.reason_codes
    assert outcome.result.authorization is None
    assert settlement.attempt_count == 0


def test_authorization_digest_cannot_settle_a_modified_request() -> None:
    gateway, _, settlement, _ = security_gateway()
    original = payment(amount="10")
    allowed = gateway.process(original)
    authorization = allowed.result.authorization
    assert authorization is not None
    balance_after_original = settlement.balances[AGENT_ID]
    modified = payment(amount="11")

    with pytest.raises(SimulatedSettlementError, match="digest mismatch"):
        settlement.settle(modified, authorization)

    assert settlement.balances[AGENT_ID] == balance_after_original


def test_end_to_end_attack_never_reaches_signer_or_changes_post_baseline_balance() -> None:
    gateway, _, settlement, clock = security_gateway()

    for sequence, seconds in enumerate((-60, -40, -20), start=1):
        clock.current = NOW + timedelta(seconds=seconds)
        seeded = gateway.process(payment(sequence))
        assert seeded.result.decision is Decision.ALLOW

    balance_after_baseline = settlement.balances[AGENT_ID]
    attack_outcomes = []
    for sequence in range(1, 6):
        clock.current = NOW + timedelta(seconds=sequence - 1)
        attack_outcomes.append(
            gateway.process(payment(100 + sequence, recipient="drain-wallet", amount="25"))
        )

    assert [outcome.result.decision for outcome in attack_outcomes] == [
        Decision.REQUIRE_APPROVAL,
        Decision.REQUIRE_APPROVAL,
        Decision.REQUIRE_APPROVAL,
        Decision.REQUIRE_APPROVAL,
        Decision.BLOCK,
    ]
    assert all(outcome.result.authorization is None for outcome in attack_outcomes)
    assert all(outcome.settlement is None for outcome in attack_outcomes)
    assert ReasonCode.DETECTION_COMPOUND_DRAIN in attack_outcomes[-1].result.reason_codes
    assert settlement.attempt_count == 3
    assert settlement.balances[AGENT_ID] == balance_after_baseline
