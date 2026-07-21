"""Deterministic local settlement used when no external payment rail is available."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from types import MappingProxyType

from solguard.contracts import (
    JsonValue,
    PaymentRequest,
    SigningAuthorization,
    canonical_json,
    format_amount,
)


class SimulatedSettlementError(RuntimeError):
    """Raised when the local settlement path cannot safely process a request."""


class InsufficientSimulatedFunds(SimulatedSettlementError):
    """Raised when the configured local balance cannot cover an allowed request."""


@dataclass(frozen=True, slots=True)
class SimulatedSettlementResult:
    """Computed evidence from a successful local balance transfer."""

    settlement_reference: str
    agent_id: str
    recipient: str
    amount: Decimal
    balance_before: Decimal
    balance_after: Decimal

    def to_dict(self) -> dict[str, str]:
        """Return display-safe computed settlement values."""

        return {
            "agent_id": self.agent_id,
            "amount": format_amount(self.amount),
            "balance_after": format_amount(self.balance_after),
            "balance_before": format_amount(self.balance_before),
            "recipient": self.recipient,
            "settlement_reference": self.settlement_reference,
            "settlement_type": "SIMULATED",
        }


class SimulatedSettlement:
    """Apply allowed payments to explicitly configured in-memory balances."""

    def __init__(self, balances: Mapping[str, Decimal]) -> None:
        if any(not balance.is_finite() or balance < 0 for balance in balances.values()):
            raise ValueError("simulated balances must be finite and non-negative")
        self._balances = dict(balances)
        self._attempt_count = 0
        self._settlement_count = 0

    @property
    def attempt_count(self) -> int:
        """Return actual calls made to the simulated settlement boundary."""

        return self._attempt_count

    @property
    def balances(self) -> Mapping[str, Decimal]:
        """Expose a read-only snapshot of current configured balances."""

        return MappingProxyType(dict(self._balances))

    def settle(
        self, request: PaymentRequest, authorization: SigningAuthorization
    ) -> SimulatedSettlementResult:
        """Settle one allowed request and return computed local evidence."""

        self._attempt_count += 1
        if authorization.request_id != request.request_id:
            raise SimulatedSettlementError("authorization request_id mismatch")
        if authorization.request_digest != request.digest:
            raise SimulatedSettlementError("authorization digest mismatch")
        if request.agent_id not in self._balances:
            raise SimulatedSettlementError("agent has no configured simulated balance")

        balance_before = self._balances[request.agent_id]
        if request.amount > balance_before:
            raise InsufficientSimulatedFunds("simulated balance is insufficient")
        balance_after = balance_before - request.amount
        self._settlement_count += 1
        reference_payload: dict[str, JsonValue] = {
            "amount": format_amount(request.amount),
            "authorization_id": authorization.authorization_id,
            "balance_after": format_amount(balance_after),
            "balance_before": format_amount(balance_before),
            "request_digest": request.digest,
            "sequence": self._settlement_count,
        }
        reference_digest = hashlib.sha256(
            canonical_json(reference_payload).encode("utf-8")
        ).hexdigest()
        self._balances[request.agent_id] = balance_after
        return SimulatedSettlementResult(
            settlement_reference=f"simulated:sha256:{reference_digest}",
            agent_id=request.agent_id,
            recipient=request.recipient,
            amount=request.amount,
            balance_before=balance_before,
            balance_after=balance_after,
        )
