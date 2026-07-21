"""Tests for Pay.sh challenge conversion and sandbox settlement."""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from email.message import Message
from typing import Any, ClassVar, cast
from urllib.error import HTTPError, URLError

import pytest

import solguard.paysh as paysh_module
from solguard.contracts import (
    AgentMandate,
    Decision,
    PaymentRequest,
    ReasonCode,
    SigningAuthorization,
)
from solguard.detection import BehaviourEngine
from solguard.gateway import PaymentGateway
from solguard.paysh import (
    PAYSH_SANDBOX_ENDPOINT,
    PAYSH_SETTLEMENT_TYPE,
    SOLANA_USDC_MINT,
    HttpResult,
    PayCommandOutput,
    PayShChallengeProbe,
    PayShNetworkError,
    PayShPaymentRequirement,
    PayShProtocolError,
    PayShSandboxSettlement,
    attempt_sandbox_purchase,
    parse_payment_requirement,
    run_pay_command,
    safe_endpoint,
    validate_endpoint,
)
from solguard.policy import MandatePolicyEngine
from solguard.settlement import SettlementFailureKind, SettlementUnavailable
from tests.test_contracts import mandate_data, payment_data

NOW = datetime(2026, 7, 25, 10, 0, tzinfo=UTC)
ENDPOINT = "https://debugger.pay.sh/mpp/quote/AAPL?private=value"
RECIPIENT = "AwwJGdj7gkeZxEZ27qCPWd3y11VPy1AKGFkxQPSBhssB"


def challenge_header(
    *,
    payload_overrides: dict[str, Any] | None = None,
    parameter_overrides: dict[str, str] | None = None,
) -> str:
    payload: dict[str, Any] = {
        "amount": "10000",
        "currency": SOLANA_USDC_MINT,
        "methodDetails": {
            "decimals": 6,
            "feePayer": True,
            "network": "localnet",
        },
        "recipient": RECIPIENT,
    }
    if payload_overrides:
        payload.update(payload_overrides)
    encoded = (
        base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )
    parameters = {
        "id": "challenge-01",
        "method": "solana",
        "intent": "charge",
        "request": encoded,
        "description": "Stock quote: AAPL",
        "expires": "2026-07-25T10:05:00Z",
    }
    if parameter_overrides:
        parameters.update(parameter_overrides)
    return "Payment " + ", ".join(f"{key}={json.dumps(value)}" for key, value in parameters.items())


def requirement() -> PayShPaymentRequirement:
    return parse_payment_requirement(challenge_header(), endpoint=ENDPOINT)


def request() -> PaymentRequest:
    return requirement().to_payment_request(
        agent_id="paysh-demo-agent",
        mandate_id="paysh-demo-mandate",
        observed_at=NOW,
    )


def authorization(payment: PaymentRequest) -> SigningAuthorization:
    return SigningAuthorization(
        authorization_id="auth-paysh",
        request_id=payment.request_id,
        request_digest=payment.digest,
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )


def transport(endpoint: str, timeout_seconds: float) -> HttpResult:
    assert endpoint == PAYSH_SANDBOX_ENDPOINT
    assert timeout_seconds > 0
    return HttpResult(status=402, headers={"WWW-Authenticate": challenge_header()})


def successful_runner(arguments: object, timeout_seconds: float) -> PayCommandOutput:
    del arguments
    assert timeout_seconds > 0
    return PayCommandOutput(
        returncode=0,
        stdout='{"symbol":"AAPL","price":"219.00"}',
        stderr="ephemeral wallet created",
    )


def test_challenge_converts_exact_amount_and_safe_metadata_to_canonical_request() -> None:
    parsed = requirement()
    payment = request()

    assert parsed.amount == Decimal("0.01")
    assert parsed.network == "localnet"
    assert payment.amount == Decimal("0.01")
    assert payment.asset == "USDC"
    assert payment.recipient == RECIPIENT
    assert payment.nonce == "challenge-01"
    assert payment.purpose == "Stock quote: AAPL"
    assert payment.metadata == {
        "currency_mint": SOLANA_USDC_MINT,
        "endpoint": "https://debugger.pay.sh/mpp/quote/AAPL",
        "network": "localnet",
        "payment_protocol": "MPP",
        "settlement_mode": "SANDBOX",
    }


def test_empty_description_uses_canonical_fallback_purpose() -> None:
    parsed = requirement()
    parsed = PayShPaymentRequirement(
        challenge_id=parsed.challenge_id,
        endpoint=parsed.endpoint,
        recipient=parsed.recipient,
        amount=parsed.amount,
        currency_mint=parsed.currency_mint,
        description="",
        expires_at=parsed.expires_at,
        network=parsed.network,
    )

    payment = parsed.to_payment_request(
        agent_id="agent",
        mandate_id="mandate",
        observed_at=NOW,
    )

    assert payment.purpose == "Pay.sh sandbox API request"


def test_requirement_rejects_naive_or_expired_observation_time() -> None:
    parsed = requirement()

    with pytest.raises(PayShProtocolError, match="timezone"):
        parsed.to_payment_request(
            agent_id="agent",
            mandate_id="mandate",
            observed_at=datetime(2026, 7, 25, 10, 0),
        )
    with pytest.raises(PayShProtocolError, match="expired"):
        parsed.to_payment_request(
            agent_id="agent",
            mandate_id="mandate",
            observed_at=parsed.expires_at,
        )


def test_requirement_wraps_contract_validation_error() -> None:
    parsed = requirement()

    with pytest.raises(PayShProtocolError, match="canonical"):
        parsed.to_payment_request(
            agent_id=" agent ",
            mandate_id="mandate",
            observed_at=NOW,
        )


def test_probe_accepts_case_insensitive_authentication_header() -> None:
    probe = PayShChallengeProbe(
        lambda endpoint, timeout: HttpResult(
            status=402,
            headers={"wWw-AuThEnTiCaTe": challenge_header()},
        )
    )

    parsed = probe.probe(ENDPOINT)

    assert parsed.amount == Decimal("0.01")


def test_probe_rejects_invalid_timeout_status_and_missing_header() -> None:
    probe = PayShChallengeProbe(lambda endpoint, timeout: HttpResult(status=200, headers={}))

    with pytest.raises(ValueError, match="positive"):
        probe.probe(ENDPOINT, timeout_seconds=0)
    with pytest.raises(PayShProtocolError, match="HTTP 402"):
        probe.probe(ENDPOINT)

    missing = PayShChallengeProbe(
        lambda endpoint, timeout: HttpResult(status=402, headers={"content-type": "text/plain"})
    )
    with pytest.raises(PayShProtocolError, match="WWW-Authenticate"):
        missing.probe(ENDPOINT)


class FakeResponse:
    status = 200
    headers: ClassVar[dict[str, str]] = {"x-test": "value"}

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        del args


def test_default_http_probe_handles_normal_and_402_responses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(paysh_module, "urlopen", lambda request, timeout: FakeResponse())
    normal = paysh_module._http_probe(ENDPOINT, 1)
    assert normal.status == 200

    headers = Message()
    headers["WWW-Authenticate"] = challenge_header()

    def raise_402(request: object, timeout: float) -> object:
        del request, timeout
        raise HTTPError(ENDPOINT, 402, "Payment Required", headers, None)

    monkeypatch.setattr(paysh_module, "urlopen", raise_402)
    challenged = paysh_module._http_probe(ENDPOINT, 1)
    assert challenged.status == 402


def test_default_http_probe_distinguishes_network_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(request: object, timeout: float) -> object:
        del request, timeout
        raise URLError("offline")

    monkeypatch.setattr(paysh_module, "urlopen", fail)

    with pytest.raises(PayShNetworkError, match="probe failed"):
        paysh_module._http_probe(ENDPOINT, 1)


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://debugger.pay.sh/path",
        "https:///missing-host",
        "https://user@debugger.pay.sh/path",
        "https://user:password@debugger.pay.sh/path",
        "https://debugger.pay.sh/path#fragment",
    ],
)
def test_endpoint_validation_rejects_unsafe_urls(endpoint: str) -> None:
    with pytest.raises(PayShProtocolError, match="HTTPS"):
        validate_endpoint(endpoint)


def test_safe_endpoint_removes_query_values() -> None:
    assert safe_endpoint(ENDPOINT) == "https://debugger.pay.sh/mpp/quote/AAPL"


@pytest.mark.parametrize(
    "header",
    [
        "Basic value=one",
        "Payment",
        'Payment method="solana"',
        'Payment id="one", id="two"',
        'Payment id="one" unexpected',
        'Payment id="one" invalid method="solana"',
        'Payment id="unterminated',
    ],
)
def test_parser_rejects_malformed_or_incomplete_authentication_header(header: str) -> None:
    with pytest.raises(PayShProtocolError):
        parse_payment_requirement(header, endpoint=ENDPOINT)


@pytest.mark.parametrize(
    "overrides",
    [
        {"method": "ethereum"},
        {"intent": "subscription"},
    ],
)
def test_parser_rejects_unsupported_method_or_intent(overrides: dict[str, str]) -> None:
    with pytest.raises(PayShProtocolError, match="Solana MPP"):
        parse_payment_requirement(
            challenge_header(parameter_overrides=overrides),
            endpoint=ENDPOINT,
        )


@pytest.mark.parametrize(
    "payload",
    [
        {"amount": "-1"},
        {"amount": "one"},
        {"amount": "0"},
        {"currency": "different-mint"},
        {"methodDetails": "invalid"},
        {"methodDetails": {"decimals": True, "network": "localnet"}},
        {"methodDetails": {"decimals": -1, "network": "localnet"}},
        {"methodDetails": {"decimals": 19, "network": "localnet"}},
        {"methodDetails": {"decimals": 6, "network": "mainnet"}},
        {"recipient": ""},
    ],
)
def test_parser_rejects_invalid_payment_payload(payload: dict[str, Any]) -> None:
    with pytest.raises(PayShProtocolError):
        parse_payment_requirement(
            challenge_header(payload_overrides=payload),
            endpoint=ENDPOINT,
        )


@pytest.mark.parametrize(
    "request_value",
    [
        "%%not-base64%%",
        base64.urlsafe_b64encode(b"[]").decode().rstrip("="),
    ],
)
def test_parser_rejects_invalid_encoded_request(request_value: str) -> None:
    with pytest.raises(PayShProtocolError, match="payload"):
        parse_payment_requirement(
            challenge_header(parameter_overrides={"request": request_value}),
            endpoint=ENDPOINT,
        )


def test_parser_rejects_invalid_expiry_and_bounded_text() -> None:
    with pytest.raises(PayShProtocolError, match="expiry"):
        parse_payment_requirement(
            challenge_header(parameter_overrides={"expires": "not-a-time"}),
            endpoint=ENDPOINT,
        )
    with pytest.raises(PayShProtocolError, match="challenge id"):
        parse_payment_requirement(
            challenge_header(parameter_overrides={"id": " bad "}),
            endpoint=ENDPOINT,
        )
    with pytest.raises(PayShProtocolError, match="description"):
        parse_payment_requirement(
            challenge_header(parameter_overrides={"description": "x" * 501}),
            endpoint=ENDPOINT,
        )


def test_successful_settlement_runs_exact_sandbox_command_and_returns_safe_evidence() -> None:
    calls: list[tuple[tuple[str, ...], float]] = []

    def runner(arguments: object, timeout_seconds: float) -> PayCommandOutput:
        typed = tuple(cast(tuple[str, ...], arguments))
        calls.append((typed, timeout_seconds))
        return PayCommandOutput(0, '{"result":"ok"}', "secret diagnostic")

    adapter = PayShSandboxSettlement(
        endpoint=ENDPOINT,
        pay_executable="pay-test",
        timeout_seconds=12,
        runner=runner,
    )
    payment = request()

    result = adapter.settle(payment, authorization(payment))

    assert calls == [
        (
            (
                "pay-test",
                "--no-dna",
                "--sandbox",
                "fetch",
                ENDPOINT,
            ),
            12,
        )
    ]
    assert result.settlement_reference.startswith("paysh:sandbox:sha256:")
    assert result.response_digest.startswith("sha256:")
    assert result.to_dict()["settlement_type"] == PAYSH_SETTLEMENT_TYPE
    assert result.to_dict()["endpoint"] == "https://debugger.pay.sh/mpp/quote/AAPL"
    assert "secret diagnostic" not in str(result.to_dict())


@pytest.mark.parametrize(
    ("output", "expected_kind"),
    [
        (PayCommandOutput(1, "", "private failure"), SettlementFailureKind.COMMAND_FAILED),
        (PayCommandOutput(0, "", ""), SettlementFailureKind.INVALID_RESPONSE),
        (PayCommandOutput(0, "too-large", ""), SettlementFailureKind.INVALID_RESPONSE),
    ],
)
def test_settlement_maps_command_and_response_failures(
    output: PayCommandOutput,
    expected_kind: SettlementFailureKind,
) -> None:
    adapter = PayShSandboxSettlement(
        endpoint=ENDPOINT,
        max_response_bytes=3,
        runner=lambda arguments, timeout: output,
    )
    payment = request()

    with pytest.raises(SettlementUnavailable) as captured:
        adapter.settle(payment, authorization(payment))

    assert captured.value.kind is expected_kind
    assert captured.value.settlement_type == PAYSH_SETTLEMENT_TYPE
    assert "private failure" not in str(captured.value)


@pytest.mark.parametrize(
    ("failure", "kind"),
    [
        (subprocess.TimeoutExpired("pay", 1), SettlementFailureKind.TIMEOUT),
        (OSError("missing executable"), SettlementFailureKind.COMMAND_FAILED),
    ],
)
def test_settlement_maps_process_exceptions(
    failure: Exception,
    kind: SettlementFailureKind,
) -> None:
    def runner(arguments: object, timeout: float) -> PayCommandOutput:
        del arguments, timeout
        raise failure

    adapter = PayShSandboxSettlement(endpoint=ENDPOINT, runner=runner)
    payment = request()

    with pytest.raises(SettlementUnavailable) as captured:
        adapter.settle(payment, authorization(payment))

    assert captured.value.kind is kind


@pytest.mark.parametrize(
    "overrides",
    [
        {"pay_executable": " "},
        {"timeout_seconds": 0},
        {"max_response_bytes": 0},
    ],
)
def test_settlement_rejects_invalid_configuration(overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        PayShSandboxSettlement(endpoint=ENDPOINT, **overrides)  # type: ignore[arg-type]


def test_default_command_runner_captures_stdout_and_stderr() -> None:
    output = run_pay_command(
        [
            sys.executable,
            "-c",
            "import sys; print('body'); print('diagnostic', file=sys.stderr)",
        ],
        10,
    )

    assert output.returncode == 0
    assert output.stdout.strip() == "body"
    assert output.stderr.strip() == "diagnostic"


def test_attempt_sandbox_purchase_settles_real_adapter_path_with_injected_command() -> None:
    attempt = attempt_sandbox_purchase(
        transport=transport,
        runner=successful_runner,
        clock=lambda: NOW,
    )

    assert attempt.status == "SETTLED"
    assert attempt.outcome.result.decision is Decision.ALLOW
    assert attempt.outcome.settlement is not None
    assert attempt.to_dict()["status"] == "SETTLED"


def test_policy_block_prevents_pay_command_invocation() -> None:
    calls = 0

    def runner(arguments: object, timeout: float) -> PayCommandOutput:
        del arguments, timeout
        nonlocal calls
        calls += 1
        return successful_runner((), 1)

    attempt = attempt_sandbox_purchase(
        max_payment="0.001",
        transport=transport,
        runner=runner,
        clock=lambda: NOW,
    )

    assert attempt.status == "SECURITY_REJECTED"
    assert attempt.outcome.result.decision is Decision.BLOCK
    assert attempt.outcome.result.reason_codes == (ReasonCode.POLICY_AMOUNT_LIMIT,)
    assert calls == 0


def test_recipient_novelty_approval_prevents_pay_command_invocation() -> None:
    payment = request()
    engine = BehaviourEngine()
    engine.record_allowed(
        PaymentRequest.from_dict(
            payment_data(
                request_id="baseline",
                agent_id=payment.agent_id,
                mandate_id=payment.mandate_id,
                recipient="known-recipient",
                amount="0.01",
                nonce="baseline-nonce",
            )
        )
    )
    mandate = AgentMandate.from_dict(
        mandate_data(
            agent_id=payment.agent_id,
            mandate_id=payment.mandate_id,
            max_single_payment="1",
            allowed_recipients=[],
            blocked_recipients=[],
        )
    )
    calls = 0

    def runner(arguments: object, timeout: float) -> PayCommandOutput:
        del arguments, timeout
        nonlocal calls
        calls += 1
        return successful_runner((), 1)

    gateway = PaymentGateway(
        policy=MandatePolicyEngine({payment.agent_id: mandate}),
        detection=engine,
        settlement=PayShSandboxSettlement(endpoint=ENDPOINT, runner=runner),
        clock=lambda: NOW,
    )

    outcome = gateway.process(payment)

    assert outcome.result.decision is Decision.REQUIRE_APPROVAL
    assert outcome.result.reason_codes == (ReasonCode.DETECTION_RECIPIENT_NOVEL,)
    assert calls == 0


def test_external_failure_is_distinct_from_security_rejection() -> None:
    attempt = attempt_sandbox_purchase(
        transport=transport,
        runner=lambda arguments, timeout: PayCommandOutput(1, "", "network private detail"),
        clock=lambda: NOW,
    )

    assert attempt.status == "SETTLEMENT_UNAVAILABLE"
    assert attempt.outcome.result.decision is Decision.BLOCK
    assert attempt.outcome.result.reason_codes == (ReasonCode.SETTLEMENT_UNAVAILABLE,)
    assert attempt.outcome.result.evidence["security_decision"] == "ALLOW"
    assert attempt.outcome.result.evidence["stage"] == "EXTERNAL_SETTLEMENT"
    assert "network private detail" not in str(attempt.outcome.result.to_dict())


def test_positive_float_parser() -> None:
    assert paysh_module._positive_float("2.5") == 2.5
    with pytest.raises(argparse.ArgumentTypeError, match="positive"):
        paysh_module._positive_float("0")


def test_cli_prints_safe_settlement_summary(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    attempt = attempt_sandbox_purchase(
        transport=transport,
        runner=successful_runner,
        clock=lambda: NOW,
    )
    monkeypatch.setattr(paysh_module, "attempt_sandbox_purchase", lambda **kwargs: attempt)

    status = paysh_module.main([])
    output = json.loads(capsys.readouterr().out)

    assert status == 0
    assert output["status"] == "SETTLED"
    assert "ephemeral wallet created" not in str(output)


def test_cli_returns_distinct_security_and_probe_failure_codes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rejected = attempt_sandbox_purchase(
        max_payment="0.001",
        transport=transport,
        runner=successful_runner,
        clock=lambda: NOW,
    )
    monkeypatch.setattr(paysh_module, "attempt_sandbox_purchase", lambda **kwargs: rejected)
    assert paysh_module.main([]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "SECURITY_REJECTED"

    def network_failure(**kwargs: object) -> object:
        raise PayShNetworkError("private")

    monkeypatch.setattr(paysh_module, "attempt_sandbox_purchase", network_failure)
    assert paysh_module.main([]) == 3
    assert json.loads(capsys.readouterr().out) == {
        "stage": "CHALLENGE_PROBE",
        "status": "NETWORK_FAILURE",
    }

    def protocol_failure(**kwargs: object) -> object:
        raise PayShProtocolError("private")

    monkeypatch.setattr(paysh_module, "attempt_sandbox_purchase", protocol_failure)
    assert paysh_module.main([]) == 3
    assert json.loads(capsys.readouterr().out) == {
        "stage": "CHALLENGE_PROBE",
        "status": "PROTOCOL_FAILURE",
    }
