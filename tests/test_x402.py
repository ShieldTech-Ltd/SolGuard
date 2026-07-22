"""Tests for strict x402 v2 mapping and the simulated devnet signing boundary."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, cast

import pytest

import solguard.x402 as x402_module
from solguard.authorization import AuthorizationRejected, WalletAuthorizationGuard
from solguard.contracts import (
    AgentMandate,
    Decision,
    JsonValue,
    PaymentRequest,
    ReasonCode,
    SigningAuthorization,
    format_timestamp,
)
from solguard.detection import BehaviourEngine
from solguard.gateway import PaymentGateway
from solguard.policy import MandatePolicyEngine
from solguard.settlement import SettlementFailureKind, SettlementUnavailable
from solguard.x402 import (
    X402_DEVNET_SETTLEMENT_TYPE,
    X402_SOLANA_DEVNET_NETWORK,
    X402_SOLANA_DEVNET_USDC_MINT,
    X402DevnetSimulatedSettlement,
    X402PaymentRequirement,
    X402ProtocolError,
    main,
    parse_payment_required_header,
    parse_payment_required_response,
    run_x402_devnet_demo,
    safe_resource_url,
    validate_resource_url,
)

NOW = datetime(2026, 7, 25, 10, 0, tzinfo=UTC)
RECIPIENT = "DemoRecipient11111111111111111111111111111"


def requirement_payload(
    *, amount: object = "10000", description: object = "Weather data"
) -> dict[str, Any]:
    resource: dict[str, Any] = {
        "url": "https://api.example.test/weather?session=private",
        "mimeType": "application/json",
    }
    if description is not ...:
        resource["description"] = description
    return {
        "x402Version": 2,
        "error": "PAYMENT-SIGNATURE header is required",
        "resource": resource,
        "accepts": [
            {
                "scheme": "exact",
                "network": X402_SOLANA_DEVNET_NETWORK,
                "amount": amount,
                "asset": X402_SOLANA_DEVNET_USDC_MINT,
                "payTo": RECIPIENT,
                "maxTimeoutSeconds": 60,
                "extra": {"feePayer": "DemoFeePayer111111111111111111111111111111"},
            }
        ],
        "extensions": {},
    }


def encode_header(payload: object) -> str:
    return base64.b64encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    ).decode()


def requirement(*, amount: object = "10000") -> X402PaymentRequirement:
    return parse_payment_required_header(encode_header(requirement_payload(amount=amount)))


def payment_request(
    parsed: X402PaymentRequirement | None = None, *, attempt_id: str = "attempt-001"
) -> PaymentRequest:
    return (parsed or requirement()).to_payment_request(
        agent_id="x402-agent",
        mandate_id="x402-mandate",
        attempt_id=attempt_id,
        observed_at=NOW,
    )


def test_payment_request_can_bind_an_explicit_live_devnet_mode() -> None:
    parsed = requirement()

    request = parsed.to_payment_request(
        agent_id="x402-agent",
        mandate_id="x402-mandate",
        attempt_id="live-attempt",
        observed_at=NOW,
        settlement_mode="LIVE_DEVNET",
    )

    assert request.metadata["settlement_mode"] == "LIVE_DEVNET"
    assert parsed.matches(request, settlement_mode="LIVE_DEVNET") is True
    assert parsed.matches(request) is False
    with pytest.raises(X402ProtocolError, match="settlement_mode"):
        parsed.to_payment_request(
            agent_id="x402-agent",
            mandate_id="x402-mandate",
            attempt_id="invalid-mode",
            observed_at=NOW,
            settlement_mode="MAINNET",
        )


def signature_header(
    parsed: X402PaymentRequirement,
    request: PaymentRequest,
    *,
    version: object = 2,
    accepted: object | None = None,
    payload: object | None = None,
) -> str:
    value = {
        "x402Version": version,
        "resource": {"url": parsed.resource_url},
        "accepted": dict(parsed.accepted) if accepted is None else accepted,
        "payload": ({"transaction": f"SIMULATED:{request.digest}"} if payload is None else payload),
    }
    return encode_header(value)


def authorization(
    request: PaymentRequest, *, identifier: str = "auth-x402"
) -> SigningAuthorization:
    return SigningAuthorization(
        authorization_id=identifier,
        request_id=request.request_id,
        request_digest=request.digest,
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )


def mandate(request: PaymentRequest, *, maximum: str = "0.1") -> AgentMandate:
    return AgentMandate.from_dict(
        {
            "mandate_id": request.mandate_id,
            "agent_id": request.agent_id,
            "purpose": "x402 test",
            "asset": "USDC",
            "max_single_payment": maximum,
            "allowed_recipients": [request.recipient],
            "blocked_recipients": [],
            "valid_from": format_timestamp(NOW - timedelta(minutes=1)),
            "expires_at": format_timestamp(NOW + timedelta(minutes=10)),
        }
    )


def test_payment_required_maps_official_v2_devnet_fields_to_canonical_request() -> None:
    parsed = requirement()
    request = payment_request(parsed)

    assert parsed.network == X402_SOLANA_DEVNET_NETWORK
    assert parsed.asset_mint == X402_SOLANA_DEVNET_USDC_MINT
    assert parsed.amount_atomic == "10000"
    assert parsed.amount == Decimal("0.01")
    assert parsed.recipient == RECIPIENT
    assert parsed.max_timeout_seconds == 60
    assert parsed.payment_required_digest.startswith("sha256:")
    assert parsed.accepted["scheme"] == "exact"
    with pytest.raises(TypeError):
        cast(dict[str, JsonValue], parsed.accepted)["scheme"] = "upto"

    assert request.recipient == RECIPIENT
    assert request.amount == Decimal("0.01")
    assert request.asset == "USDC"
    assert request.created_at == NOW
    assert request.expires_at == NOW + timedelta(seconds=60)
    assert request.metadata == {
        "asset_mint": X402_SOLANA_DEVNET_USDC_MINT,
        "network": X402_SOLANA_DEVNET_NETWORK,
        "payment_protocol": "X402",
        "payment_required_digest": parsed.payment_required_digest,
        "resource_url": "https://api.example.test/weather",
        "scheme": "exact",
        "settlement_mode": "SIMULATED_DEVNET",
        "x402_version": 2,
    }
    assert parsed.matches(request)


def test_http_402_response_finds_header_case_insensitively() -> None:
    parsed = parse_payment_required_response(
        status=402,
        headers={
            "content-type": "application/json",
            "payment-required": encode_header(requirement_payload()),
        },
    )

    assert parsed.amount == Decimal("0.01")


@pytest.mark.parametrize(
    ("status", "headers", "message"),
    [
        (200, {}, "HTTP 402"),
        (402, {}, "exactly one"),
        (
            402,
            {
                "PAYMENT-REQUIRED": "first",
                "payment-required": "second",
            },
            "exactly one",
        ),
    ],
)
def test_http_response_rejects_wrong_status_missing_or_ambiguous_header(
    status: int, headers: dict[str, str], message: str
) -> None:
    with pytest.raises(X402ProtocolError, match=message):
        parse_payment_required_response(status=status, headers=headers)


def test_payment_required_digest_is_canonical_and_attempts_are_unique() -> None:
    payload = requirement_payload()
    reversed_payload = dict(reversed(list(payload.items())))
    first = parse_payment_required_header(encode_header(payload))
    second = parse_payment_required_header(encode_header(reversed_payload))

    assert first.payment_required_digest == second.payment_required_digest
    request_one = payment_request(first, attempt_id="one")
    request_two = payment_request(first, attempt_id="two")
    assert request_one.request_id != request_two.request_id
    assert request_one.nonce != request_two.nonce
    assert request_one.digest != request_two.digest


def test_missing_description_uses_protocol_fallback() -> None:
    parsed = parse_payment_required_header(encode_header(requirement_payload(description=...)))

    assert parsed.description == "x402 protected resource"
    assert payment_request(parsed).purpose == "x402 protected resource"


@pytest.mark.parametrize("observed_at", [datetime(2026, 7, 25, 10, 0), None])
def test_request_rejects_naive_time_and_invalid_canonical_input(
    observed_at: datetime | None,
) -> None:
    parsed = requirement()
    if observed_at is None:
        with pytest.raises(X402ProtocolError, match="canonical"):
            parsed.to_payment_request(
                agent_id=" x402-agent ",
                mandate_id="x402-mandate",
                attempt_id="attempt",
                observed_at=NOW,
            )
    else:
        with pytest.raises(X402ProtocolError, match="timezone"):
            parsed.to_payment_request(
                agent_id="x402-agent",
                mandate_id="x402-mandate",
                attempt_id="attempt",
                observed_at=observed_at,
            )


@pytest.mark.parametrize("attempt_id", ["", " attempt ", "x" * 129, 42])
def test_request_rejects_invalid_attempt_identifier(attempt_id: object) -> None:
    with pytest.raises(X402ProtocolError, match="attempt_id"):
        requirement().to_payment_request(
            agent_id="x402-agent",
            mandate_id="x402-mandate",
            attempt_id=cast(str, attempt_id),
            observed_at=NOW,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("recipient", "DifferentRecipient"),
        ("amount", "0.02"),
        ("asset", "USD"),
        ("purpose", "Different purpose"),
        ("expires_at", "2026-07-25T10:02:00Z"),
    ],
)
def test_requirement_match_rejects_changed_canonical_fields(field: str, value: str) -> None:
    parsed = requirement()
    data = payment_request(parsed).to_dict()
    data[field] = value

    assert not parsed.matches(PaymentRequest.from_dict(data))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("asset_mint", "different"),
        ("network", "solana:different"),
        ("payment_protocol", "OTHER"),
        ("payment_required_digest", "sha256:different"),
        ("scheme", "upto"),
        ("settlement_mode", "MAINNET"),
        ("x402_version", 1),
    ],
)
def test_requirement_match_rejects_changed_binding_metadata(field: str, value: object) -> None:
    parsed = requirement()
    data = payment_request(parsed).to_dict()
    metadata = cast(dict[str, JsonValue], data["metadata"])
    metadata[field] = cast(JsonValue, value)

    assert not parsed.matches(PaymentRequest.from_dict(data))


@pytest.mark.parametrize("version", [None, 1, True, "2"])
def test_payment_required_rejects_non_v2_version(version: object) -> None:
    payload = requirement_payload()
    payload["x402Version"] = version

    with pytest.raises(X402ProtocolError, match="x402Version 2"):
        parse_payment_required_header(encode_header(payload))


def test_payment_required_requires_resource_object() -> None:
    payload = requirement_payload()
    payload["resource"] = "not-an-object"

    with pytest.raises(X402ProtocolError, match="resource must be an object"):
        parse_payment_required_header(encode_header(payload))


def test_payment_required_rejects_non_object_extensions() -> None:
    payload = requirement_payload()
    payload["extensions"] = "invalid"

    with pytest.raises(X402ProtocolError, match="extensions must be an object"):
        parse_payment_required_header(encode_header(payload))


@pytest.mark.parametrize(
    "url",
    [
        "http://api.example.test/resource",
        "https:///missing-host",
        "https://user:secret@api.example.test/resource",
        "https://api.example.test/resource#fragment",
    ],
)
def test_resource_url_requires_safe_https(url: str) -> None:
    payload = requirement_payload()
    cast(dict[str, Any], payload["resource"])["url"] = url

    with pytest.raises(X402ProtocolError, match="credential-free HTTPS"):
        parse_payment_required_header(encode_header(payload))


def test_resource_url_helpers_validate_and_remove_query() -> None:
    value = "https://api.example.test/path?token=secret"

    assert validate_resource_url(value) == value
    assert safe_resource_url(value) == "https://api.example.test/path"


@pytest.mark.parametrize("description", ["", " spaced ", "x" * 501, 42])
def test_payment_required_rejects_invalid_description(description: object) -> None:
    with pytest.raises(X402ProtocolError, match=r"resource\.description"):
        parse_payment_required_header(encode_header(requirement_payload(description=description)))


@pytest.mark.parametrize("accepts", [None, {}, [], "exact"])
def test_payment_required_requires_nonempty_accepts_array(accepts: object) -> None:
    payload = requirement_payload()
    payload["accepts"] = accepts

    with pytest.raises(X402ProtocolError, match="non-empty array"):
        parse_payment_required_header(encode_header(payload))


def test_payment_required_rejects_non_object_accept_entry() -> None:
    payload = requirement_payload()
    payload["accepts"] = ["exact"]

    with pytest.raises(X402ProtocolError, match="entries must be objects"):
        parse_payment_required_header(encode_header(payload))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("scheme", "upto"),
        ("network", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"),
        ("asset", "different-mint"),
    ],
)
def test_payment_required_rejects_unsupported_requirements(field: str, value: object) -> None:
    payload = requirement_payload()
    cast(dict[str, Any], payload["accepts"][0])[field] = value

    with pytest.raises(X402ProtocolError, match="no supported"):
        parse_payment_required_header(encode_header(payload))


def test_payment_required_rejects_ambiguous_supported_requirements() -> None:
    payload = requirement_payload()
    payload["accepts"].append(dict(payload["accepts"][0]))

    with pytest.raises(X402ProtocolError, match="ambiguous"):
        parse_payment_required_header(encode_header(payload))


@pytest.mark.parametrize(
    "amount",
    [0, "0", "-1", "1.5", chr(0xFF11) + chr(0xFF12), "x" * 65],
)
def test_payment_required_rejects_invalid_atomic_amount(amount: object) -> None:
    with pytest.raises(X402ProtocolError, match="amount"):
        parse_payment_required_header(encode_header(requirement_payload(amount=amount)))


@pytest.mark.parametrize("recipient", [None, "", " recipient ", "x" * 257])
def test_payment_required_rejects_invalid_recipient(recipient: object) -> None:
    payload = requirement_payload()
    cast(dict[str, Any], payload["accepts"][0])["payTo"] = recipient

    with pytest.raises(X402ProtocolError, match="payTo"):
        parse_payment_required_header(encode_header(payload))


@pytest.mark.parametrize("timeout", [None, True, 0, 301, "60"])
def test_payment_required_rejects_unsafe_timeout(timeout: object) -> None:
    payload = requirement_payload()
    cast(dict[str, Any], payload["accepts"][0])["maxTimeoutSeconds"] = timeout

    with pytest.raises(X402ProtocolError, match="maxTimeoutSeconds"):
        parse_payment_required_header(encode_header(payload))


def test_payment_required_rejects_non_object_extra() -> None:
    payload = requirement_payload()
    cast(dict[str, Any], payload["accepts"][0])["extra"] = "unsafe"

    with pytest.raises(X402ProtocolError, match="extra must be an object"):
        parse_payment_required_header(encode_header(payload))


@pytest.mark.parametrize(
    "header",
    ["", " value ", "not-base64!", pytest.param("A" * 65_537, id="oversized")],
)
def test_header_decoder_rejects_invalid_or_oversized_base64(header: str) -> None:
    with pytest.raises(X402ProtocolError):
        parse_payment_required_header(header)


def test_header_decoder_rejects_non_ascii_invalid_utf8_and_invalid_json() -> None:
    with pytest.raises(X402ProtocolError, match="ASCII"):
        parse_payment_required_header("é")
    with pytest.raises(X402ProtocolError, match="UTF-8"):
        parse_payment_required_header(base64.b64encode(b"\xff").decode())
    with pytest.raises(X402ProtocolError, match="valid JSON object"):
        parse_payment_required_header(base64.b64encode(b"not json").decode())
    with pytest.raises(X402ProtocolError, match="valid JSON object"):
        parse_payment_required_header(encode_header(["not", "an", "object"]))


def test_allowed_request_reaches_signer_and_returns_only_safe_simulated_evidence() -> None:
    parsed = requirement()
    request = payment_request(parsed)
    calls: list[str] = []

    def signer(selected: X402PaymentRequirement, candidate: PaymentRequest) -> str:
        calls.append(candidate.request_id)
        return signature_header(selected, candidate)

    settlement = X402DevnetSimulatedSettlement(
        requirement=parsed,
        signer=signer,
        authorization_guard=WalletAuthorizationGuard(clock=lambda: NOW),
    )
    gateway = PaymentGateway(
        policy=MandatePolicyEngine({request.agent_id: mandate(request)}),
        detection=BehaviourEngine(),
        settlement=settlement,
        clock=lambda: NOW,
    )

    outcome = gateway.process(request)

    assert outcome.result.decision is Decision.ALLOW
    assert calls == [request.request_id]
    assert outcome.settlement is not None
    evidence = outcome.settlement.to_dict()
    assert evidence["settlement_type"] == X402_DEVNET_SETTLEMENT_TYPE
    assert evidence["status"] == "PREPARED_SIMULATION"
    assert evidence["network"] == X402_SOLANA_DEVNET_NETWORK
    assert evidence["amount"] == "0.01"
    assert evidence["recipient"] == RECIPIENT
    assert evidence["payment_required_digest"] == parsed.payment_required_digest
    assert cast(str, evidence["payment_signature_digest"]).startswith("sha256:")
    assert cast(int, evidence["payment_signature_bytes"]) > 0
    assert cast(str, evidence["settlement_reference"]).startswith("x402:devnet:simulated:sha256:")
    assert "transaction" not in evidence


def test_policy_block_never_reaches_x402_signer() -> None:
    parsed = requirement(amount="1000000")
    request = payment_request(parsed)
    calls: list[str] = []

    def signer(selected: X402PaymentRequirement, candidate: PaymentRequest) -> str:
        del selected
        calls.append(candidate.request_id)
        return "must-not-run"

    gateway = PaymentGateway(
        policy=MandatePolicyEngine({request.agent_id: mandate(request, maximum="0.1")}),
        detection=BehaviourEngine(),
        settlement=X402DevnetSimulatedSettlement(
            requirement=parsed,
            signer=signer,
            authorization_guard=WalletAuthorizationGuard(clock=lambda: NOW),
        ),
        clock=lambda: NOW,
    )

    outcome = gateway.process(request)

    assert outcome.result.decision is Decision.BLOCK
    assert outcome.result.reason_codes == (ReasonCode.POLICY_AMOUNT_LIMIT,)
    assert outcome.result.authorization is None
    assert outcome.settlement is None
    assert calls == []


def test_settlement_rejects_request_not_bound_to_requirement_before_signing() -> None:
    parsed = requirement()
    request = payment_request(parsed)
    changed = PaymentRequest.from_dict({**request.to_dict(), "recipient": "DifferentRecipient"})
    calls: list[str] = []

    def recording_signer(selected: X402PaymentRequirement, candidate: PaymentRequest) -> str:
        del selected
        calls.append(candidate.request_id)
        return "unused"

    settlement = X402DevnetSimulatedSettlement(
        requirement=parsed,
        signer=recording_signer,
        authorization_guard=WalletAuthorizationGuard(clock=lambda: NOW),
    )

    with pytest.raises(AuthorizationRejected) as failure:
        settlement.settle(changed, authorization(changed))

    assert failure.value.reason_code is ReasonCode.AUTHORIZATION_MISMATCH
    assert calls == []


def test_settlement_requires_and_consumes_single_use_authorization() -> None:
    parsed = requirement()
    request = payment_request(parsed)
    settlement = X402DevnetSimulatedSettlement(
        requirement=parsed,
        signer=signature_header,
        authorization_guard=WalletAuthorizationGuard(clock=lambda: NOW),
    )

    with pytest.raises(AuthorizationRejected) as missing:
        settlement.settle(request, None)
    assert missing.value.reason_code is ReasonCode.AUTHORIZATION_MISSING

    valid = authorization(request)
    settlement.settle(request, valid)
    with pytest.raises(AuthorizationRejected) as replayed:
        settlement.settle(request, valid)
    assert replayed.value.reason_code is ReasonCode.AUTHORIZATION_REPLAYED


def test_default_authorization_guard_accepts_current_short_lived_authorization() -> None:
    now = datetime.now(UTC)
    parsed = requirement()
    request = parsed.to_payment_request(
        agent_id="agent",
        mandate_id="mandate",
        attempt_id="current",
        observed_at=now,
    )
    current_authorization = SigningAuthorization(
        authorization_id="current-auth",
        request_id=request.request_id,
        request_digest=request.digest,
        issued_at=now,
        expires_at=now + timedelta(minutes=1),
    )
    settlement = X402DevnetSimulatedSettlement(
        requirement=parsed,
        signer=signature_header,
    )

    assert settlement.settle(request, current_authorization).amount == Decimal("0.01")


@pytest.mark.parametrize(
    "signer",
    [
        lambda parsed, request: signature_header(parsed, request, version=1),
        lambda parsed, request: signature_header(parsed, request, accepted={"scheme": "upto"}),
        lambda parsed, request: signature_header(parsed, request, payload={}),
        lambda parsed, request: encode_header(
            {"x402Version": 2, "accepted": dict(parsed.accepted)}
        ),
        lambda parsed, request: encode_header(
            {"x402Version": 2, "accepted": "invalid", "payload": {"value": "x"}}
        ),
    ],
)
def test_invalid_payment_signature_envelope_fails_closed(
    signer: Any,
) -> None:
    parsed = requirement()
    request = payment_request(parsed)
    settlement = X402DevnetSimulatedSettlement(
        requirement=parsed,
        signer=signer,
        authorization_guard=WalletAuthorizationGuard(clock=lambda: NOW),
    )

    with pytest.raises(SettlementUnavailable) as failure:
        settlement.settle(request, authorization(request))

    assert failure.value.kind is SettlementFailureKind.INVALID_RESPONSE
    assert failure.value.settlement_type == X402_DEVNET_SETTLEMENT_TYPE


def test_signer_exception_fails_closed_at_gateway() -> None:
    parsed = requirement()
    request = payment_request(parsed)

    def broken_signer(selected: X402PaymentRequirement, candidate: PaymentRequest) -> str:
        del selected, candidate
        raise RuntimeError("signer unavailable")

    gateway = PaymentGateway(
        policy=MandatePolicyEngine({request.agent_id: mandate(request)}),
        detection=BehaviourEngine(),
        settlement=X402DevnetSimulatedSettlement(
            requirement=parsed,
            signer=broken_signer,
            authorization_guard=WalletAuthorizationGuard(clock=lambda: NOW),
        ),
        clock=lambda: NOW,
    )

    outcome = gateway.process(request)

    assert outcome.result.decision is Decision.BLOCK
    assert outcome.result.reason_codes == (ReasonCode.SYSTEM_FAILURE,)
    assert outcome.result.authorization is None
    assert outcome.settlement is None


def test_devnet_demo_proves_allowed_blocked_and_single_signer_call() -> None:
    report = run_x402_devnet_demo(clock=lambda: NOW)

    assert report["status"] == "VERIFIED"
    assert report["x402_version"] == 2
    assert report["network"] == X402_SOLANA_DEVNET_NETWORK
    assert report["settlement_mode"] == "SIMULATED_DEVNET"
    assert report["signer_calls"] == 1
    assert cast(dict[str, JsonValue], report["allowed"])["decision"] == "ALLOW"
    assert cast(dict[str, JsonValue], report["blocked"])["decision"] == "BLOCK"


def test_main_prints_verified_report_and_returns_success(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main([]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "VERIFIED"


def test_main_returns_failure_for_failed_report(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        x402_module,
        "run_x402_devnet_demo",
        lambda: {"status": "FAILED"},
    )

    assert main([]) == 2
    assert json.loads(capsys.readouterr().out) == {"status": "FAILED"}
