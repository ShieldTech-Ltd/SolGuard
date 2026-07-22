"""Tests for the opt-in real x402 Solana-devnet settlement boundary."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace
from typing import Any, cast

import pytest
from solders.keypair import Keypair

import solguard.x402_live as live_module
from solguard.authorization import AuthorizationRejected, WalletAuthorizationGuard
from solguard.contracts import Decision, PaymentRequest, ReasonCode, SigningAuthorization
from solguard.devnet_rpc import DevnetConfirmationError, DevnetConfirmationEvidence
from solguard.settlement import SettlementFailureKind, SettlementUnavailable
from solguard.x402 import (
    X402_SOLANA_DEVNET_NETWORK,
    X402_SOLANA_DEVNET_USDC_MINT,
    X402PaymentRequirement,
    X402ProtocolError,
    parse_payment_required_header,
)
from solguard.x402_live import (
    DEFAULT_X402_FACILITATOR_URL,
    FACILITATOR_ENV,
    PRIVATE_KEY_ENV,
    RECIPIENT_ENV,
    RPC_ENV,
    X402_DEVNET_LIVE_SETTLEMENT_TYPE,
    OfficialX402DevnetExecutor,
    X402DevnetLiveSettlement,
    X402LiveSettlementResult,
    build_live_requirement_header,
    main,
    run_live_devnet_demo,
)

NOW = datetime(2026, 7, 25, 10, 0, tzinfo=UTC)
FEE_PAYER = "CKPKJWNdJEqa81x7CkZ14BVPiY6y16Sxs7owznqtWYp5"


def private_key() -> str:
    return str(Keypair())


def recipient() -> str:
    return str(Keypair().pubkey())


def requirement(
    *, pay_to: str | None = None, amount_atomic: str = "1000"
) -> X402PaymentRequirement:
    return parse_payment_required_header(
        build_live_requirement_header(
            amount_atomic=amount_atomic,
            recipient=pay_to or recipient(),
            fee_payer=FEE_PAYER,
        )
    )


def payment(parsed: X402PaymentRequirement) -> PaymentRequest:
    return parsed.to_payment_request(
        agent_id="live-agent",
        mandate_id="live-mandate",
        attempt_id="live-attempt",
        observed_at=NOW,
        settlement_mode="LIVE_DEVNET",
    )


def authorization(request: PaymentRequest) -> SigningAuthorization:
    return SigningAuthorization(
        authorization_id="auth-live",
        request_id=request.request_id,
        request_digest=request.digest,
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )


class FakeExecutor:
    def __init__(
        self,
        *,
        payer: str = "payer-address",
        result_payer: str | None = None,
        result_network: str = X402_SOLANA_DEVNET_NETWORK,
        result_amount: Decimal | None = None,
        result_recipient: str | None = None,
        signature: str = "devnet-signature",
        confirmation_overrides: dict[str, object] | None = None,
    ) -> None:
        self._payer = payer
        self._result_payer = result_payer
        self._result_network = result_network
        self._result_amount = result_amount
        self._result_recipient = result_recipient
        self._signature = signature
        self._confirmation_overrides = confirmation_overrides or {}
        self._calls = 0

    @property
    def payer_address(self) -> str:
        return self._payer

    @property
    def calls(self) -> int:
        return self._calls

    def discover_fee_payer(self) -> str:
        return FEE_PAYER

    def execute(
        self,
        parsed: X402PaymentRequirement,
        request: PaymentRequest,
    ) -> X402LiveSettlementResult:
        self._calls += 1
        signature = self._signature
        return X402LiveSettlementResult(
            settlement_reference=f"solana:devnet:{signature}",
            transaction_signature=signature,
            explorer_url=f"https://explorer.solana.com/tx/{signature}?cluster=devnet",
            network=self._result_network,
            payer=self._result_payer or self._payer,
            recipient=self._result_recipient or request.recipient,
            amount=self._result_amount if self._result_amount is not None else parsed.amount,
            facilitator=DEFAULT_X402_FACILITATOR_URL,
            confirmation=replace(
                confirmation_evidence(
                    signature=signature,
                    payer=self._result_payer or self._payer,
                    recipient=self._result_recipient or request.recipient,
                    amount_atomic=parsed.amount_atomic,
                ),
                **cast(Any, self._confirmation_overrides),
            ),
        )


def confirmation_evidence(
    *,
    signature: str = "devnet-signature",
    payer: str = "payer-address",
    recipient: str = "recipient",
    amount_atomic: str = "1000",
) -> DevnetConfirmationEvidence:
    return DevnetConfirmationEvidence(
        transaction_signature=signature,
        confirmation_status="confirmed",
        slot=123,
        token_mint=X402_SOLANA_DEVNET_USDC_MINT,
        source_owner=payer,
        source_token_account="source-token-account",
        destination_owner=recipient,
        destination_token_account="destination-token-account",
        source_delta_atomic=f"-{amount_atomic}",
        destination_delta_atomic=amount_atomic,
    )


def test_live_result_contains_only_safe_confirmed_evidence() -> None:
    result = FakeExecutor().execute(requirement(pay_to="recipient"), payment(requirement()))

    payload = result.to_dict()

    assert payload["status"] == "CONFIRMED_DEVNET_RPC"
    assert cast(dict[str, object], payload["on_chain_confirmation"])["slot"] == 123
    assert payload["settlement_type"] == X402_DEVNET_LIVE_SETTLEMENT_TYPE
    assert payload["transaction_signature"] == "devnet-signature"
    assert PRIVATE_KEY_ENV not in str(payload)


def test_live_boundary_consumes_authorization_before_executor() -> None:
    parsed = requirement()
    request = payment(parsed)
    executor = FakeExecutor()
    settlement = X402DevnetLiveSettlement(
        requirement=parsed,
        executor=executor,
        authorization_guard=WalletAuthorizationGuard(clock=lambda: NOW),
    )

    result = settlement.settle(request, authorization(request))

    assert result.transaction_signature == "devnet-signature"
    assert executor.calls == 1
    with pytest.raises(AuthorizationRejected, match="AUTHORIZATION_REPLAYED"):
        settlement.settle(request, authorization(request))
    assert executor.calls == 1


def test_live_boundary_rejects_request_not_bound_to_requirement() -> None:
    parsed = requirement()
    original = payment(parsed)
    changed = PaymentRequest.from_dict({**original.to_dict(), "recipient": "changed-recipient"})
    executor = FakeExecutor()
    settlement = X402DevnetLiveSettlement(requirement=parsed, executor=executor)

    with pytest.raises(AuthorizationRejected, match="AUTHORIZATION_MISMATCH"):
        settlement.settle(changed, authorization(changed))

    assert executor.calls == 0


@pytest.mark.parametrize(
    "executor",
    [
        FakeExecutor(result_network="solana:wrong"),
        FakeExecutor(result_recipient="wrong-recipient"),
        FakeExecutor(result_amount=Decimal("2")),
        FakeExecutor(result_payer="wrong-payer"),
        FakeExecutor(signature=""),
        FakeExecutor(confirmation_overrides={"transaction_signature": "wrong"}),
        FakeExecutor(confirmation_overrides={"network": "solana:wrong"}),
        FakeExecutor(confirmation_overrides={"token_mint": "wrong"}),
        FakeExecutor(confirmation_overrides={"source_owner": "wrong"}),
        FakeExecutor(confirmation_overrides={"destination_owner": "wrong"}),
        FakeExecutor(confirmation_overrides={"destination_delta_atomic": "999"}),
        FakeExecutor(confirmation_overrides={"source_delta_atomic": "-999"}),
    ],
)
def test_live_boundary_rejects_inconsistent_facilitator_evidence(
    executor: FakeExecutor,
) -> None:
    parsed = requirement()
    request = payment(parsed)
    settlement = X402DevnetLiveSettlement(
        requirement=parsed,
        executor=executor,
        authorization_guard=WalletAuthorizationGuard(clock=lambda: NOW),
    )

    with pytest.raises(SettlementUnavailable) as caught:
        settlement.settle(request, authorization(request))

    assert caught.value.kind is SettlementFailureKind.INVALID_RESPONSE


def test_official_executor_validates_configuration_and_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = private_key()
    expected_address = str(Keypair.from_base58_string(key).pubkey())
    injected_confirmer = FakeConfirmer()
    executor = OfficialX402DevnetExecutor(private_key=key, confirmer=injected_confirmer)

    assert executor.payer_address == expected_address
    assert executor.calls == 0
    assert executor.facilitator_url == DEFAULT_X402_FACILITATOR_URL
    assert executor._confirmer is injected_confirmer

    monkeypatch.setenv(PRIVATE_KEY_ENV, key)
    monkeypatch.setenv(FACILITATOR_ENV, "https://facilitator.example.test/x402")
    monkeypatch.setenv(RPC_ENV, "https://rpc.example.test")
    configured = OfficialX402DevnetExecutor.from_environment()
    assert configured.facilitator_url == "https://facilitator.example.test/x402"


def test_official_executor_requires_environment_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(PRIVATE_KEY_ENV, raising=False)

    with pytest.raises(ValueError, match=PRIVATE_KEY_ENV):
        OfficialX402DevnetExecutor.from_environment()


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"private_key": ""}, PRIVATE_KEY_ENV),
        ({"private_key": " invalid "}, PRIVATE_KEY_ENV),
        ({"private_key": "not-a-key"}, PRIVATE_KEY_ENV),
        ({"private_key": "KEY", "facilitator_url": "http://example.test"}, "HTTPS"),
        ({"private_key": "KEY", "facilitator_url": "https://u:p@example.test"}, "HTTPS"),
        ({"private_key": "KEY", "facilitator_url": "https://example.test?a=1"}, "HTTPS"),
        ({"private_key": "KEY", "rpc_url": "https://example.test/#fragment"}, "HTTPS"),
    ],
)
def test_official_executor_rejects_unsafe_configuration(
    kwargs: dict[str, str], message: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    if kwargs["private_key"] == "KEY":
        monkeypatch.setattr(
            OfficialX402DevnetExecutor,
            "_derive_payer_address",
            staticmethod(lambda _key: "payer"),
        )
    with pytest.raises(ValueError, match=message):
        OfficialX402DevnetExecutor(**cast(Any, kwargs))


def test_https_origin_rejects_empty_or_oversized_value() -> None:
    with pytest.raises(ValueError, match="endpoint is invalid"):
        live_module._https_origin("", field_name="endpoint")
    with pytest.raises(ValueError, match="endpoint is invalid"):
        live_module._https_origin(f"https://example.test/{'x' * 2048}", field_name="endpoint")


def test_derive_payer_reports_missing_optional_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_import = __import__

    def missing_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "x402.mechanisms.svm":
            raise ImportError("missing")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", missing_import)
    with pytest.raises(RuntimeError, match=r"devnet.*dependencies"):
        OfficialX402DevnetExecutor._derive_payer_address("unused")


class FakeFacilitator:
    def __init__(
        self,
        *,
        supported: object | None = None,
        verification: object | None = None,
        settlement: object | None = None,
        error: Exception | None = None,
    ) -> None:
        self._supported = supported
        self._verification = verification
        self._settlement = settlement
        self._error = error
        self.closed = False

    def __enter__(self) -> FakeFacilitator:
        return self

    def __exit__(self, *_args: object) -> None:
        self.closed = True

    def get_supported(self) -> object:
        if self._error is not None:
            raise self._error
        return self._supported

    def verify(self, _payload: object, _accepted: object) -> object:
        if self._error is not None:
            raise self._error
        return self._verification

    def settle(self, _payload: object, _accepted: object) -> object:
        if self._error is not None:
            raise self._error
        return self._settlement


def supported_response(*kinds: object) -> object:
    return SimpleNamespace(kinds=list(kinds))


def supported_kind(**overrides: object) -> object:
    values: dict[str, object] = {
        "x402_version": 2,
        "scheme": "exact",
        "network": X402_SOLANA_DEVNET_NETWORK,
        "extra": {"feePayer": FEE_PAYER},
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_discover_fee_payer_selects_exact_v2_solana_kind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = OfficialX402DevnetExecutor(private_key=private_key())
    response = supported_response(
        supported_kind(x402_version=1),
        supported_kind(scheme="other"),
        supported_kind(network="solana:other"),
        supported_kind(extra=None),
        supported_kind(extra={"feePayer": 7}),
        supported_kind(),
    )
    monkeypatch.setattr(
        executor, "_official_facilitator", lambda: FakeFacilitator(supported=response)
    )

    assert executor.discover_fee_payer() == FEE_PAYER


def test_discover_fee_payer_fails_closed_for_missing_or_network_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = OfficialX402DevnetExecutor(private_key=private_key())
    monkeypatch.setattr(
        executor,
        "_official_facilitator",
        lambda: FakeFacilitator(supported=supported_response()),
    )
    with pytest.raises(SettlementUnavailable) as missing:
        executor.discover_fee_payer()
    assert missing.value.kind is SettlementFailureKind.INVALID_RESPONSE

    class ConnectFailure(Exception):
        pass

    monkeypatch.setattr(
        executor,
        "_official_facilitator",
        lambda: FakeFacilitator(error=ConnectFailure()),
    )
    with pytest.raises(SettlementUnavailable) as network:
        executor.discover_fee_payer()
    assert network.value.kind is SettlementFailureKind.NETWORK


class FakeClient:
    def __init__(self, *, payload: object | None = None, error: Exception | None = None) -> None:
        self._payload = payload
        self._error = error

    def create_payment_payload(self, _required: object) -> object:
        if self._error is not None:
            raise self._error
        return self._payload


def execute_fixture(
    executor: OfficialX402DevnetExecutor,
    parsed: X402PaymentRequirement,
    *,
    valid: bool = True,
    success: bool = True,
    transaction: str = "real-devnet-signature",
    amount: str | None = "1000",
    error: Exception | None = None,
    monkeypatch: pytest.MonkeyPatch,
) -> FakeFacilitator:
    required = executor._official_payment_required(parsed)
    payload = SimpleNamespace(accepted=required.accepts[0])
    facilitator = FakeFacilitator(
        verification=SimpleNamespace(is_valid=valid),
        settlement=SimpleNamespace(
            success=success,
            transaction=transaction,
            amount=amount,
            network=X402_SOLANA_DEVNET_NETWORK,
            payer=executor.payer_address,
        ),
        error=error,
    )
    monkeypatch.setattr(executor, "_official_client", lambda: FakeClient(payload=payload))
    monkeypatch.setattr(executor, "_official_facilitator", lambda: facilitator)
    monkeypatch.setattr(executor, "_confirmer", FakeConfirmer())
    return facilitator


class FakeConfirmer:
    def __init__(self, error: Exception | None = None) -> None:
        self._error = error
        self.calls = 0

    def confirm(
        self,
        *,
        transaction_signature: str,
        expected_mint: str,
        expected_source_owner: str,
        expected_destination_owner: str,
        expected_amount_atomic: str,
    ) -> DevnetConfirmationEvidence:
        self.calls += 1
        if self._error is not None:
            raise self._error
        return DevnetConfirmationEvidence(
            transaction_signature=transaction_signature,
            confirmation_status="confirmed",
            slot=123,
            token_mint=expected_mint,
            source_owner=expected_source_owner,
            source_token_account="source-token-account",
            destination_owner=expected_destination_owner,
            destination_token_account="destination-token-account",
            source_delta_atomic=f"-{expected_amount_atomic}",
            destination_delta_atomic=expected_amount_atomic,
        )


def test_official_executor_uses_sdk_verify_and_settle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = OfficialX402DevnetExecutor(private_key=private_key())
    parsed = requirement(amount_atomic="1000")
    request = payment(parsed)
    facilitator = execute_fixture(executor, parsed, monkeypatch=monkeypatch)

    result = executor.execute(parsed, request)

    assert result.amount == Decimal("0.001")
    assert result.transaction_signature == "real-devnet-signature"
    assert result.explorer_url.endswith("?cluster=devnet")
    assert executor.calls == 1
    assert facilitator.closed is True


@pytest.mark.parametrize(
    "options",
    [
        {"valid": False},
        {"success": False},
        {"transaction": ""},
        {"amount": None},
    ],
)
def test_official_executor_rejects_invalid_facilitator_outcomes(
    options: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    executor = OfficialX402DevnetExecutor(private_key=private_key())
    parsed = requirement()
    request = payment(parsed)
    execute_fixture(executor, parsed, monkeypatch=monkeypatch, **cast(Any, options))

    with pytest.raises(SettlementUnavailable) as caught:
        executor.execute(parsed, request)

    assert caught.value.kind is SettlementFailureKind.INVALID_RESPONSE


def test_official_executor_preserves_settlement_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = OfficialX402DevnetExecutor(private_key=private_key())
    parsed = requirement()
    unavailable = SettlementUnavailable(
        SettlementFailureKind.TIMEOUT,
        settlement_type=X402_DEVNET_LIVE_SETTLEMENT_TYPE,
    )
    monkeypatch.setattr(
        executor,
        "_official_payment_required",
        lambda _requirement: (_ for _ in ()).throw(unavailable),
    )

    with pytest.raises(SettlementUnavailable) as caught:
        executor.execute(parsed, payment(parsed))

    assert caught.value is unavailable


def test_official_executor_requires_independent_rpc_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = OfficialX402DevnetExecutor(private_key=private_key())
    parsed = requirement()
    execute_fixture(executor, parsed, monkeypatch=monkeypatch)
    monkeypatch.setattr(
        executor,
        "_confirmer",
        FakeConfirmer(DevnetConfirmationError("RPC unavailable")),
    )

    with pytest.raises(SettlementUnavailable) as caught:
        executor.execute(parsed, payment(parsed))

    assert caught.value.kind is SettlementFailureKind.INVALID_RESPONSE


def test_official_executor_builds_real_optional_sdk_objects() -> None:
    executor = OfficialX402DevnetExecutor(private_key=private_key())
    parsed = requirement()

    required = executor._official_payment_required(parsed)
    client = executor._official_client()
    facilitator = executor._official_facilitator()

    assert required.accepts[0].amount == "1000"
    assert type(client).__name__ == "x402ClientSync"
    assert type(facilitator).__name__ == "HTTPFacilitatorClientSync"
    facilitator.close()


@pytest.mark.parametrize(
    ("error", "kind"),
    [
        (type("OperationTimeout", (Exception,), {})(), SettlementFailureKind.TIMEOUT),
        (type("NetworkTransport", (Exception,), {})(), SettlementFailureKind.NETWORK),
        (ValueError("bad"), SettlementFailureKind.INVALID_RESPONSE),
        (RuntimeError("bad"), SettlementFailureKind.COMMAND_FAILED),
    ],
)
def test_official_failure_classification(error: Exception, kind: SettlementFailureKind) -> None:
    assert OfficialX402DevnetExecutor._unavailable(error).kind is kind


@pytest.mark.parametrize("value", ["not-a-number", "NaN", "0", "0.0000001"])
def test_live_amount_rejects_invalid_values(value: str) -> None:
    with pytest.raises(ValueError, match="amount"):
        live_module._atomic_amount(value)


def test_live_requirement_header_round_trips_through_strict_parser() -> None:
    pay_to = recipient()
    header = build_live_requirement_header(
        amount_atomic="1234",
        recipient=pay_to,
        fee_payer=FEE_PAYER,
    )

    parsed = parse_payment_required_header(header)

    assert parsed.amount == Decimal("0.001234")
    assert parsed.recipient == pay_to
    assert cast(dict[str, object], parsed.accepted["extra"])["feePayer"] == FEE_PAYER


def test_live_demo_blocks_before_executor_then_settles_once() -> None:
    executor = FakeExecutor()

    report = run_live_devnet_demo(
        executor=executor,
        recipient=recipient(),
        amount="0.001",
        clock=lambda: NOW,
    )

    assert report["status"] == "VERIFIED"
    assert cast(dict[str, object], report["blocked"])["decision"] == Decision.BLOCK.value
    assert cast(dict[str, object], report["allowed"])["decision"] == Decision.ALLOW.value
    assert executor.calls == 1


def test_live_demo_reports_failed_when_settlement_evidence_is_invalid() -> None:
    executor = FakeExecutor(result_payer="wrong")

    report = run_live_devnet_demo(
        executor=executor,
        recipient=recipient(),
        amount="0.001",
        clock=lambda: NOW,
    )

    assert report["status"] == "FAILED"
    assert cast(dict[str, object], report["allowed"])["reason_codes"] == [
        ReasonCode.SETTLEMENT_UNAVAILABLE.value
    ]


def test_live_demo_requires_timezone_aware_clock() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        run_live_devnet_demo(
            executor=FakeExecutor(),
            recipient=recipient(),
            amount="0.001",
            clock=lambda: datetime(2026, 7, 25, 10, 0),
        )


def test_environment_recipient_is_required_and_trimmed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(RECIPIENT_ENV, raising=False)
    with pytest.raises(ValueError, match=RECIPIENT_ENV):
        live_module._environment_recipient()
    monkeypatch.setenv(RECIPIENT_ENV, " invalid ")
    with pytest.raises(ValueError, match=RECIPIENT_ENV):
        live_module._environment_recipient()
    monkeypatch.setenv(RECIPIENT_ENV, "recipient")
    assert live_module._environment_recipient() == "recipient"


def test_main_can_show_public_wallet_without_settlement(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    executor = FakeExecutor(payer="public-wallet")
    monkeypatch.setattr(
        OfficialX402DevnetExecutor,
        "from_environment",
        classmethod(lambda _cls: executor),
    )

    assert main(["--show-wallet-address"]) == 0
    assert capsys.readouterr().out.strip() == "public-wallet"


def test_main_requires_explicit_devnet_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        OfficialX402DevnetExecutor,
        "from_environment",
        classmethod(lambda _cls: FakeExecutor()),
    )

    with pytest.raises(SystemExit) as caught:
        main([])

    assert caught.value.code == 2


@pytest.mark.parametrize(("status", "exit_code"), [("VERIFIED", 0), ("FAILED", 2)])
def test_main_runs_confirmed_demo_and_returns_status(
    status: str,
    exit_code: int,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    executor = FakeExecutor()
    monkeypatch.setenv(RECIPIENT_ENV, "recipient")
    monkeypatch.setattr(
        OfficialX402DevnetExecutor,
        "from_environment",
        classmethod(lambda _cls: executor),
    )
    monkeypatch.setattr(
        live_module,
        "run_live_devnet_demo",
        lambda **_kwargs: {"status": status},
    )

    assert main(["--confirm-devnet"]) == exit_code
    assert f'"status":"{status}"' in capsys.readouterr().out


def test_main_returns_sanitized_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        OfficialX402DevnetExecutor,
        "from_environment",
        classmethod(lambda _cls: (_ for _ in ()).throw(ValueError("secret detail"))),
    )

    assert main(["--confirm-devnet"]) == 2
    output = capsys.readouterr().out
    assert "ValueError" in output
    assert "secret detail" not in output


def test_main_returns_sanitized_protocol_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    executor = FakeExecutor()
    monkeypatch.setenv(RECIPIENT_ENV, "recipient")
    monkeypatch.setattr(
        OfficialX402DevnetExecutor,
        "from_environment",
        classmethod(lambda _cls: executor),
    )
    monkeypatch.setattr(
        live_module,
        "run_live_devnet_demo",
        lambda **_kwargs: (_ for _ in ()).throw(X402ProtocolError("private detail")),
    )

    assert main(["--confirm-devnet"]) == 2
    output = capsys.readouterr().out
    assert "X402ProtocolError" in output
    assert "private detail" not in output


def test_main_returns_sanitized_missing_dependency_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        OfficialX402DevnetExecutor,
        "from_environment",
        classmethod(lambda _cls: (_ for _ in ()).throw(RuntimeError("private detail"))),
    )

    assert main(["--confirm-devnet"]) == 2
    output = capsys.readouterr().out
    assert "RuntimeError" in output
    assert "private detail" not in output
