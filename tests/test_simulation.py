"""Tests for the deterministic local settlement adapter."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from solguard.contracts import PaymentRequest, SigningAuthorization
from solguard.simulation import (
    InsufficientSimulatedFunds,
    SimulatedSettlement,
    SimulatedSettlementError,
)
from tests.test_contracts import payment_data


def request(**overrides: object) -> PaymentRequest:
    return PaymentRequest.from_dict(payment_data(**overrides))


def authorization(payment: PaymentRequest) -> SigningAuthorization:
    issued_at = datetime(2026, 7, 25, 10, 0, tzinfo=UTC)
    return SigningAuthorization(
        authorization_id="auth_test",
        request_id=payment.request_id,
        request_digest=payment.digest,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=30),
    )


def test_simulated_settlement_computes_balance_and_reference() -> None:
    payment = request(amount="5")
    adapter = SimulatedSettlement({payment.agent_id: Decimal("100")})

    result = adapter.settle(payment, authorization(payment))

    assert result.balance_before == Decimal("100")
    assert result.balance_after == Decimal("95")
    assert result.to_dict() == {
        "agent_id": "research-agent-01",
        "amount": "5",
        "balance_after": "95",
        "balance_before": "100",
        "recipient": "weather-api",
        "settlement_reference": result.settlement_reference,
        "settlement_type": "SIMULATED",
    }
    assert result.settlement_reference.startswith("simulated:sha256:")
    assert adapter.attempt_count == 1
    assert adapter.balances[payment.agent_id] == Decimal("95")


def test_simulated_reference_changes_with_real_sequence() -> None:
    payment = request(amount="5")
    adapter = SimulatedSettlement({payment.agent_id: Decimal("100")})

    first = adapter.settle(payment, authorization(payment))
    second = adapter.settle(payment, authorization(payment))

    assert first.settlement_reference != second.settlement_reference
    assert second.balance_after == Decimal("90")


@pytest.mark.parametrize("balance", [Decimal("-1"), Decimal("NaN")])
def test_simulated_settlement_rejects_invalid_initial_balance(balance: Decimal) -> None:
    with pytest.raises(ValueError, match="finite and non-negative"):
        SimulatedSettlement({"agent": balance})


def test_simulated_settlement_rejects_mismatched_request_id() -> None:
    payment = request()
    auth = authorization(payment)
    mismatched = SigningAuthorization(
        authorization_id=auth.authorization_id,
        request_id="other-request",
        request_digest=auth.request_digest,
        issued_at=auth.issued_at,
        expires_at=auth.expires_at,
    )
    adapter = SimulatedSettlement({payment.agent_id: Decimal("100")})

    with pytest.raises(SimulatedSettlementError, match="request_id"):
        adapter.settle(payment, mismatched)


def test_simulated_settlement_rejects_mismatched_digest() -> None:
    payment = request()
    auth = authorization(payment)
    mismatched = SigningAuthorization(
        authorization_id=auth.authorization_id,
        request_id=auth.request_id,
        request_digest="sha256:wrong",
        issued_at=auth.issued_at,
        expires_at=auth.expires_at,
    )
    adapter = SimulatedSettlement({payment.agent_id: Decimal("100")})

    with pytest.raises(SimulatedSettlementError, match="digest"):
        adapter.settle(payment, mismatched)


def test_simulated_settlement_requires_configured_balance() -> None:
    payment = request()
    adapter = SimulatedSettlement({})

    with pytest.raises(SimulatedSettlementError, match="no configured"):
        adapter.settle(payment, authorization(payment))


def test_simulated_settlement_rejects_insufficient_balance_without_mutation() -> None:
    payment = request(amount="101")
    adapter = SimulatedSettlement({payment.agent_id: Decimal("100")})

    with pytest.raises(InsufficientSimulatedFunds):
        adapter.settle(payment, authorization(payment))

    assert adapter.balances[payment.agent_id] == Decimal("100")
    assert adapter.attempt_count == 1
