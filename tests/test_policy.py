"""Tests for the deliberately small Agent Financial Mandate policy engine."""

from __future__ import annotations

from decimal import Decimal

import pytest

from solguard.contracts import AgentMandate, Decision, PaymentRequest, ReasonCode
from solguard.policy import MandatePolicyEngine
from tests.test_contracts import mandate_data, payment_data


def mandate(**overrides: object) -> AgentMandate:
    """Build a valid mandate for policy tests."""

    return AgentMandate.from_dict(mandate_data(**overrides))


def request(**overrides: object) -> PaymentRequest:
    """Build a valid request for policy tests."""

    return PaymentRequest.from_dict(payment_data(**overrides))


def test_allows_payment_at_exact_maximum_for_allowlisted_recipient() -> None:
    engine = MandatePolicyEngine({"research-agent-01": mandate()})

    result = engine.evaluate(request(amount="2.00"))

    assert result.decision is Decision.ALLOW
    assert result.reason_codes == ()
    assert result.evidence["max_single_payment"] == "2"
    assert result.evidence["recipient_policy"] == "ALLOWLISTED"


def test_allows_any_non_blocked_recipient_without_whitelist() -> None:
    engine = MandatePolicyEngine({"research-agent-01": mandate(allowed_recipients=[])})

    result = engine.evaluate(request(recipient="new-api"))

    assert result.decision is Decision.ALLOW
    assert result.evidence["recipient_policy"] == "NO_ALLOWLIST"


def test_blocks_amount_above_agent_maximum() -> None:
    engine = MandatePolicyEngine({"research-agent-01": mandate()})

    result = engine.evaluate(request(amount="2.01"))

    assert result.decision is Decision.BLOCK
    assert result.reason_codes == (ReasonCode.POLICY_AMOUNT_LIMIT,)
    assert result.evidence == {
        "agent_id": "research-agent-01",
        "amount": "2.01",
        "max_single_payment": "2",
        "recipient": "weather-api",
        "recipient_policy": "NOT_EVALUATED",
    }


def test_blocks_recipient_outside_configured_whitelist() -> None:
    engine = MandatePolicyEngine({"research-agent-01": mandate()})

    result = engine.evaluate(request(recipient="new-api"))

    assert result.decision is Decision.BLOCK
    assert result.reason_codes == (ReasonCode.POLICY_RECIPIENT_NOT_ALLOWED,)
    assert result.evidence["recipient_policy"] == "NOT_ALLOWLISTED"


def test_hard_block_takes_precedence_over_allowlist_and_amount() -> None:
    engine = MandatePolicyEngine(
        {
            "research-agent-01": mandate(
                max_single_payment="1.00",
                allowed_recipients=["attacker-wallet"],
                blocked_recipients=["attacker-wallet"],
            )
        }
    )

    result = engine.evaluate(request(recipient="attacker-wallet", amount="5.00"))

    assert result.decision is Decision.BLOCK
    assert result.reason_codes == (ReasonCode.POLICY_RECIPIENT_BLOCKED,)
    assert result.evidence["recipient_policy"] == "HARD_BLOCKED"


def test_missing_agent_policy_fails_closed_without_cross_agent_fallback() -> None:
    other = mandate(agent_id="other-agent", mandate_id="other-mandate")
    engine = MandatePolicyEngine({"other-agent": other})

    result = engine.evaluate(request())

    assert result.decision is Decision.BLOCK
    assert result.reason_codes == (ReasonCode.POLICY_MISSING,)
    assert result.evidence == {
        "agent_id": "research-agent-01",
        "policy_state": "MISSING",
    }


def test_mandate_identifier_mismatch_fails_closed() -> None:
    engine = MandatePolicyEngine({"research-agent-01": mandate()})

    result = engine.evaluate(request(mandate_id="different-mandate"))

    assert result.decision is Decision.BLOCK
    assert result.reason_codes == (ReasonCode.POLICY_MANDATE_MISMATCH,)


def test_malformed_policy_map_is_rejected() -> None:
    wrong_agent = mandate(agent_id="actual-agent")

    with pytest.raises(ValueError, match="map key"):
        MandatePolicyEngine({"incorrect-agent": wrong_agent})


def test_policy_uses_decimal_comparison_not_float() -> None:
    engine = MandatePolicyEngine({"research-agent-01": mandate(max_single_payment="0.30")})

    result = engine.evaluate(request(amount="0.3"))

    assert result.decision is Decision.ALLOW
    assert request(amount="0.3").amount == Decimal("0.3")
