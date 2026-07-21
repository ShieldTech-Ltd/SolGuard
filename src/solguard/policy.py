"""Simple deterministic Agent Financial Mandate policy engine."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from solguard.contracts import (
    AgentMandate,
    Decision,
    JsonValue,
    PaymentRequest,
    ReasonCode,
    format_amount,
)


@dataclass(frozen=True, slots=True)
class PolicyResult:
    """Explainable result contributed by the mandate policy engine."""

    decision: Decision
    reason_codes: tuple[ReasonCode, ...]
    evidence: Mapping[str, JsonValue]


class MandatePolicyEngine:
    """Enforce one simple, isolated mandate for each registered agent."""

    def __init__(self, mandates: Mapping[str, AgentMandate]) -> None:
        validated: dict[str, AgentMandate] = {}
        for agent_id, mandate in mandates.items():
            if agent_id != mandate.agent_id:
                raise ValueError("mandate map key must match mandate agent_id")
            validated[agent_id] = mandate
        self._mandates = MappingProxyType(validated)

    def evaluate(self, request: PaymentRequest) -> PolicyResult:
        """Evaluate maximum spend, hard-block list, and optional whitelist."""

        mandate = self._mandates.get(request.agent_id)
        if mandate is None:
            return self._block(
                ReasonCode.POLICY_MISSING,
                {"agent_id": request.agent_id, "policy_state": "MISSING"},
            )
        if mandate.mandate_id != request.mandate_id:
            return self._block(
                ReasonCode.POLICY_MANDATE_MISMATCH,
                {
                    "expected_mandate_id": mandate.mandate_id,
                    "provided_mandate_id": request.mandate_id,
                },
            )

        common_evidence: dict[str, JsonValue] = {
            "agent_id": request.agent_id,
            "amount": format_amount(request.amount),
            "max_single_payment": format_amount(mandate.max_single_payment),
            "recipient": request.recipient,
        }

        # A hard-block entry always wins, including when the same recipient is allowlisted.
        if request.recipient in mandate.blocked_recipients:
            return self._block(
                ReasonCode.POLICY_RECIPIENT_BLOCKED,
                {**common_evidence, "recipient_policy": "HARD_BLOCKED"},
            )
        if request.amount > mandate.max_single_payment:
            return self._block(
                ReasonCode.POLICY_AMOUNT_LIMIT,
                {**common_evidence, "recipient_policy": "NOT_EVALUATED"},
            )
        if mandate.allowed_recipients and request.recipient not in mandate.allowed_recipients:
            return self._block(
                ReasonCode.POLICY_RECIPIENT_NOT_ALLOWED,
                {**common_evidence, "recipient_policy": "NOT_ALLOWLISTED"},
            )

        recipient_policy = "ALLOWLISTED" if mandate.allowed_recipients else "NO_ALLOWLIST"
        return PolicyResult(
            decision=Decision.ALLOW,
            reason_codes=(),
            evidence=MappingProxyType({**common_evidence, "recipient_policy": recipient_policy}),
        )

    @staticmethod
    def _block(reason: ReasonCode, evidence: dict[str, JsonValue]) -> PolicyResult:
        return PolicyResult(
            decision=Decision.BLOCK,
            reason_codes=(reason,),
            evidence=MappingProxyType(evidence),
        )
