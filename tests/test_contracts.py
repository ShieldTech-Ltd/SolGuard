"""Tests for canonical SolGuard domain contracts."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal

import pytest

from solguard.contracts import (
    AgentMandate,
    ContractValidationError,
    Decision,
    DecisionResult,
    PaymentRequest,
    ReasonCode,
    SigningAuthorization,
    contract_from_json,
    format_amount,
    parse_amount,
)


def payment_data(**overrides: object) -> dict[str, object]:
    """Return one valid canonical payment mapping."""

    data: dict[str, object] = {
        "request_id": "req_01",
        "agent_id": "research-agent-01",
        "mandate_id": "mandate_01",
        "recipient": "weather-api",
        "amount": "0.0500",
        "asset": "USDC",
        "purpose": "weather research",
        "nonce": "nonce-01",
        "created_at": "2026-07-25T10:00:00Z",
        "expires_at": "2026-07-25T10:01:00+00:00",
        "metadata": {"region": "London", "attempt": 1},
    }
    data.update(overrides)
    return data


def mandate_data(**overrides: object) -> dict[str, object]:
    """Return one valid simple mandate mapping."""

    data: dict[str, object] = {
        "mandate_id": "mandate_01",
        "agent_id": "research-agent-01",
        "purpose": "weather research",
        "asset": "USDC",
        "max_single_payment": "2.00",
        "allowed_recipients": ["weather-api", "market-data-api"],
        "blocked_recipients": ["attacker-wallet"],
        "valid_from": "2026-07-25T09:00:00Z",
        "expires_at": "2026-07-26T00:00:00Z",
    }
    data.update(overrides)
    return data


def test_payment_request_serializes_canonically() -> None:
    request = PaymentRequest.from_dict(payment_data())

    assert request.amount == Decimal("0.0500")
    assert request.to_dict()["amount"] == "0.05"
    assert request.to_dict()["created_at"] == "2026-07-25T10:00:00Z"
    assert request.canonical == json.dumps(
        request.to_dict(),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    assert request.digest.startswith("sha256:")
    assert len(request.digest) == 71


def test_equivalent_requests_have_identical_digest() -> None:
    first = PaymentRequest.from_dict(payment_data(amount="0.0500"))
    second_data = payment_data(
        amount="0.05",
        created_at="2026-07-25T11:00:00+01:00",
        metadata={"attempt": 1, "region": "London"},
    )
    second = PaymentRequest.from_dict(second_data)

    assert first.canonical == second.canonical
    assert first.digest == second.digest


@pytest.mark.parametrize("value", [0.1, 1, "-1", "+1", "1e2", "01.0", "NaN", "0"])
def test_amount_rejects_ambiguous_or_non_positive_values(value: object) -> None:
    with pytest.raises(ContractValidationError):
        parse_amount(value)


def test_amount_format_is_stable_fixed_point() -> None:
    assert format_amount(Decimal("100.5000")) == "100.5"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"unexpected": "field"}, "unknown fields"),
        ({"amount": 0.05}, "decimal string"),
        ({"created_at": 123}, "ISO-8601 string"),
        ({"created_at": "not-a-time"}, "valid ISO-8601"),
        ({"created_at": "2026-07-25T10:00:00"}, "timezone"),
        ({"expires_at": "2026-07-25T09:00:00Z"}, "later than"),
        ({"metadata": {"risk": 1.5}}, "floating-point"),
        ({"metadata": {1: "value"}}, "keys must be strings"),
        ({"metadata": {"value": object()}}, "non-JSON"),
        ({"request_id": " request "}, "trimmed"),
        ({"request_id": "r" * 129}, "exceeds 128"),
    ],
)
def test_payment_request_rejects_invalid_input(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(ContractValidationError, match=message):
        PaymentRequest.from_dict(payment_data(**overrides))


def test_payment_request_rejects_missing_field() -> None:
    data = payment_data()
    del data["nonce"]

    with pytest.raises(ContractValidationError, match="missing fields: nonce"):
        PaymentRequest.from_dict(data)


def test_metadata_is_copied_from_untrusted_input() -> None:
    metadata = {"nested": ["safe"]}
    request = PaymentRequest.from_dict(payment_data(metadata=metadata))
    metadata["nested"] = ["changed"]

    assert request.metadata == {"nested": ["safe"]}


def test_mandate_serializes_with_sorted_recipients() -> None:
    mandate = AgentMandate.from_dict(mandate_data())

    assert mandate.allowed_recipients == ("market-data-api", "weather-api")
    assert mandate.to_dict()["max_single_payment"] == "2"
    assert mandate.to_dict()["valid_from"] == "2026-07-25T09:00:00Z"


@pytest.mark.parametrize(
    "overrides",
    [
        {"allowed_recipients": "weather-api"},
        {"allowed_recipients": ["weather-api", "weather-api"]},
        {"blocked_recipients": [" attacker-wallet"]},
        {"expires_at": "2026-07-25T08:00:00Z"},
        {"max_single_payment": "Infinity"},
    ],
)
def test_mandate_rejects_invalid_input(overrides: dict[str, object]) -> None:
    with pytest.raises(ContractValidationError):
        AgentMandate.from_dict(mandate_data(**overrides))


def test_decision_result_is_stable_and_deduplicates_reasons() -> None:
    result = DecisionResult.create(
        request_id="req_01",
        decision=Decision.BLOCK,
        reason_codes=(ReasonCode.POLICY_AMOUNT_LIMIT, ReasonCode.POLICY_AMOUNT_LIMIT),
        request_digest="sha256:abc",
        evidence={"limit": "2", "amount": "5"},
    )

    assert result.reason_codes == (ReasonCode.POLICY_AMOUNT_LIMIT,)
    assert result.to_dict()["authorization"] is None
    assert result.to_dict()["evidence"] == {"amount": "5", "limit": "2"}


def test_non_allow_decision_rejects_authorization() -> None:
    authorization = SigningAuthorization(
        authorization_id="auth_01",
        request_id="req_01",
        request_digest="sha256:abc",
        issued_at=datetime(2026, 7, 25, 10, 0, tzinfo=UTC),
        expires_at=datetime(2026, 7, 25, 10, 1, tzinfo=UTC),
    )

    with pytest.raises(ContractValidationError, match="only ALLOW"):
        DecisionResult.create(
            request_id="req_01",
            decision=Decision.BLOCK,
            reason_codes=(ReasonCode.SYSTEM_FAILURE,),
            request_digest="sha256:abc",
            evidence={},
            authorization=authorization,
        )


def test_allow_decision_serializes_authorization() -> None:
    authorization = SigningAuthorization(
        authorization_id="auth_01",
        request_id="req_01",
        request_digest="sha256:abc",
        issued_at=datetime(2026, 7, 25, 10, 0, tzinfo=UTC),
        expires_at=datetime(2026, 7, 25, 10, 1, tzinfo=UTC),
    )
    result = DecisionResult.create(
        request_id="req_01",
        decision=Decision.ALLOW,
        reason_codes=(),
        request_digest="sha256:abc",
        evidence={},
        authorization=authorization,
    )

    assert result.to_dict()["authorization"] == authorization.to_dict()


@pytest.mark.parametrize("raw", ["not-json", "[]", '{"amount": NaN}', '{"amount": 1.5}'])
def test_contract_json_rejects_invalid_or_ambiguous_payload(raw: str) -> None:
    with pytest.raises(ContractValidationError):
        contract_from_json(raw)


def test_contract_json_accepts_standard_object() -> None:
    assert contract_from_json('{"safe": true, "count": 1}') == {"safe": True, "count": 1}
