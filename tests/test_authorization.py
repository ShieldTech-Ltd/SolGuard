"""Tests for single-use authorization at wallet settlement boundaries."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from itertools import count

import pytest

from solguard.authorization import (
    AuthorizationRejected,
    InMemoryAuthorizationStore,
    WalletAuthorizationGuard,
)
from solguard.contracts import (
    AgentMandate,
    Decision,
    PaymentRequest,
    ReasonCode,
    SigningAuthorization,
)
from solguard.detection import BehaviourEngine
from solguard.gateway import PaymentGateway
from solguard.paysh import PayCommandOutput, PayShSandboxSettlement
from solguard.policy import MandatePolicyEngine
from solguard.settlement import SettlementResult
from solguard.simulation import SimulatedSettlement
from tests.test_contracts import mandate_data, payment_data

NOW = datetime(2026, 7, 25, 10, 0, tzinfo=UTC)


def payment(**overrides: object) -> PaymentRequest:
    return PaymentRequest.from_dict(payment_data(**overrides))


def authorization(
    request: PaymentRequest,
    *,
    authorization_id: str = "auth-01",
    request_id: str | None = None,
    request_digest: str | None = None,
    expires_at: datetime | None = None,
) -> SigningAuthorization:
    return SigningAuthorization(
        authorization_id=authorization_id,
        request_id=request_id or request.request_id,
        request_digest=request_digest or request.digest,
        issued_at=NOW,
        expires_at=expires_at or (NOW + timedelta(seconds=30)),
    )


class InvalidAuthorizationStore:
    def consume_if_unused(self, authorization_id: str) -> bool:
        del authorization_id
        return None  # type: ignore[return-value]


class FailingAuthorizationStore:
    def consume_if_unused(self, authorization_id: str) -> bool:
        del authorization_id
        raise RuntimeError("private authorization-store failure")


def test_valid_authorization_is_returned_and_consumed_once() -> None:
    guard = WalletAuthorizationGuard(clock=lambda: NOW)
    request = payment()
    auth = authorization(request)

    assert guard.authorize(request, auth) is auth
    with pytest.raises(AuthorizationRejected) as captured:
        guard.authorize(request, auth)
    assert captured.value.reason_code is ReasonCode.AUTHORIZATION_REPLAYED


def test_missing_authorization_is_rejected_without_consumption() -> None:
    guard = WalletAuthorizationGuard(clock=lambda: NOW)

    with pytest.raises(AuthorizationRejected) as captured:
        guard.authorize(payment(), None)

    assert captured.value.reason_code is ReasonCode.AUTHORIZATION_MISSING


@pytest.mark.parametrize(
    "auth",
    [
        authorization(payment(), request_id="other-request"),
        authorization(payment(), request_digest="sha256:wrong"),
    ],
)
def test_mismatched_authorization_is_rejected_without_consuming_identifier(
    auth: SigningAuthorization,
) -> None:
    guard = WalletAuthorizationGuard(clock=lambda: NOW)
    request = payment()

    with pytest.raises(AuthorizationRejected) as captured:
        guard.authorize(request, auth)
    corrected = authorization(request, authorization_id=auth.authorization_id)

    assert captured.value.reason_code is ReasonCode.AUTHORIZATION_MISMATCH
    assert guard.authorize(request, corrected) is corrected


def test_authorization_expires_at_exact_wallet_clock_boundary() -> None:
    request = payment()
    auth = authorization(request, expires_at=NOW)
    guard = WalletAuthorizationGuard(clock=lambda: NOW)

    with pytest.raises(AuthorizationRejected) as captured:
        guard.authorize(request, auth)

    assert captured.value.reason_code is ReasonCode.AUTHORIZATION_EXPIRED


def test_authorization_clock_requires_timezone() -> None:
    guard = WalletAuthorizationGuard(clock=lambda: datetime(2026, 7, 25, 10, 0))

    with pytest.raises(ValueError, match="timezone"):
        guard.authorize(payment(), authorization(payment()))


def test_authorization_store_must_return_boolean() -> None:
    guard = WalletAuthorizationGuard(InvalidAuthorizationStore(), clock=lambda: NOW)

    with pytest.raises(TypeError, match="boolean"):
        guard.authorize(payment(), authorization(payment()))


def test_in_memory_store_is_single_use_per_authorization_identifier() -> None:
    store = InMemoryAuthorizationStore()

    assert store.consume_if_unused("auth") is True
    assert store.consume_if_unused("auth") is False
    assert store.consume_if_unused("different") is True


def test_simulated_wallet_settles_once_and_rejects_reuse_without_balance_change() -> None:
    request = payment(amount="5")
    auth = authorization(request)
    adapter = SimulatedSettlement(
        {request.agent_id: Decimal("100")},
        authorization_guard=WalletAuthorizationGuard(clock=lambda: NOW),
    )

    settled = adapter.settle(request, auth)
    with pytest.raises(AuthorizationRejected) as captured:
        adapter.settle(request, auth)

    assert settled.balance_after == Decimal("95")
    assert captured.value.reason_code is ReasonCode.AUTHORIZATION_REPLAYED
    assert adapter.attempt_count == 1
    assert adapter.balances[request.agent_id] == Decimal("95")


def test_paysh_wallet_invokes_external_command_once_and_rejects_reuse() -> None:
    request = payment(amount="0.01")
    auth = authorization(request)
    calls = 0

    def runner(arguments: object, timeout: float) -> PayCommandOutput:
        del arguments, timeout
        nonlocal calls
        calls += 1
        return PayCommandOutput(0, '{"result":"ok"}', "")

    adapter = PayShSandboxSettlement(
        endpoint="https://debugger.pay.sh/mpp/quote/AAPL",
        runner=runner,
        authorization_guard=WalletAuthorizationGuard(clock=lambda: NOW),
    )

    settled = adapter.settle(request, auth)
    with pytest.raises(AuthorizationRejected) as captured:
        adapter.settle(request, auth)

    assert settled.settlement_reference.startswith("paysh:sandbox:sha256:")
    assert captured.value.reason_code is ReasonCode.AUTHORIZATION_REPLAYED
    assert calls == 1


class RejectingSettlement:
    def settle(
        self,
        request: PaymentRequest,
        authorization: SigningAuthorization | None,
    ) -> SettlementResult:
        del request, authorization
        raise AuthorizationRejected(ReasonCode.AUTHORIZATION_REPLAYED)


def test_gateway_reports_wallet_authorization_rejection_with_stable_reason() -> None:
    request = payment()
    mandate = AgentMandate.from_dict(mandate_data())
    ticks = count(start=1_000_000, step=1_000_000)
    gateway = PaymentGateway(
        policy=MandatePolicyEngine({request.agent_id: mandate}),
        detection=BehaviourEngine(),
        settlement=RejectingSettlement(),
        clock=lambda: NOW,
        timer_ns=lambda: next(ticks),
    )

    outcome = gateway.process(request)

    assert outcome.result.decision is Decision.BLOCK
    assert outcome.result.reason_codes == (ReasonCode.AUTHORIZATION_REPLAYED,)
    assert outcome.result.evidence["stage"] == "WALLET_AUTHORIZATION"
    assert outcome.result.authorization is None
    assert outcome.settlement is None


def test_authorization_store_failure_fails_closed_without_leaking_details() -> None:
    request = payment()
    mandate = AgentMandate.from_dict(mandate_data())
    settlement = SimulatedSettlement(
        {request.agent_id: Decimal("100")},
        authorization_guard=WalletAuthorizationGuard(
            FailingAuthorizationStore(),
            clock=lambda: NOW,
        ),
    )
    ticks = count(start=1_000_000, step=1_000_000)
    gateway = PaymentGateway(
        policy=MandatePolicyEngine({request.agent_id: mandate}),
        detection=BehaviourEngine(),
        settlement=settlement,
        clock=lambda: NOW,
        timer_ns=lambda: next(ticks),
    )

    outcome = gateway.process(request)

    assert outcome.result.decision is Decision.BLOCK
    assert outcome.result.reason_codes == (ReasonCode.SYSTEM_FAILURE,)
    assert "private authorization-store failure" not in str(outcome.result.to_dict())
    assert settlement.attempt_count == 0
