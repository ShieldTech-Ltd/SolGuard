"""Opt-in real x402 Solana-devnet settlement behind the SolGuard wallet boundary."""

from __future__ import annotations

import argparse
import base64
import json
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any, Protocol

from solguard.authorization import AuthorizationRejected, WalletAuthorizationGuard
from solguard.contracts import (
    AgentMandate,
    Decision,
    JsonObject,
    JsonValue,
    PaymentRequest,
    ReasonCode,
    SigningAuthorization,
    canonical_json,
    format_amount,
    format_timestamp,
)
from solguard.detection import BehaviourEngine
from solguard.gateway import PaymentGateway
from solguard.policy import MandatePolicyEngine
from solguard.settlement import SettlementFailureKind, SettlementResult, SettlementUnavailable
from solguard.x402 import (
    X402_SOLANA_DEVNET_NETWORK,
    X402_SOLANA_DEVNET_USDC_MINT,
    X402_VERSION,
    X402PaymentRequirement,
    X402ProtocolError,
    parse_payment_required_header,
)

X402_DEVNET_LIVE_SETTLEMENT_TYPE = "X402_DEVNET_LIVE"
DEFAULT_X402_FACILITATOR_URL = "https://x402.org/facilitator"
DEFAULT_SOLANA_DEVNET_RPC_URL = "https://api.devnet.solana.com"
SOLANA_DEVNET_EXPLORER_ROOT = "https://explorer.solana.com/tx"
PRIVATE_KEY_ENV = "SOLGUARD_SVM_PRIVATE_KEY"
RECIPIENT_ENV = "SOLGUARD_SVM_RECIPIENT"
FACILITATOR_ENV = "SOLGUARD_X402_FACILITATOR_URL"
RPC_ENV = "SOLGUARD_SOLANA_RPC_URL"
_USDC_ATOMIC_FACTOR = Decimal("1000000")


@dataclass(frozen=True, slots=True)
class X402LiveSettlementResult(SettlementResult):
    """Safe evidence returned after confirmed facilitator settlement."""

    settlement_reference: str
    transaction_signature: str
    explorer_url: str
    network: str
    payer: str
    recipient: str
    amount: Decimal
    facilitator: str

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "amount": format_amount(self.amount),
            "asset": "USDC",
            "explorer_url": self.explorer_url,
            "facilitator": self.facilitator,
            "network": self.network,
            "payer": self.payer,
            "recipient": self.recipient,
            "settlement_reference": self.settlement_reference,
            "settlement_type": X402_DEVNET_LIVE_SETTLEMENT_TYPE,
            "status": "CONFIRMED_DEVNET",
            "transaction_signature": self.transaction_signature,
        }


class X402LiveExecutor(Protocol):
    """Trusted optional boundary that signs and settles one allowed requirement."""

    @property
    def payer_address(self) -> str: ...

    def execute(
        self,
        requirement: X402PaymentRequirement,
        request: PaymentRequest,
    ) -> X402LiveSettlementResult: ...


class X402LiveDemoExecutor(X402LiveExecutor, Protocol):
    """Additional operations required by the explicit live demonstration command."""

    @property
    def calls(self) -> int: ...

    def discover_fee_payer(self) -> str: ...


class X402DevnetLiveSettlement:
    """Consume exact-request authorization before invoking a live devnet executor."""

    def __init__(
        self,
        *,
        requirement: X402PaymentRequirement,
        executor: X402LiveExecutor,
        authorization_guard: WalletAuthorizationGuard | None = None,
    ) -> None:
        self._requirement = requirement
        self._executor = executor
        self._authorization_guard = (
            authorization_guard if authorization_guard is not None else WalletAuthorizationGuard()
        )

    def settle(
        self,
        request: PaymentRequest,
        authorization: SigningAuthorization | None,
    ) -> X402LiveSettlementResult:
        """Settle only the requirement that was evaluated and authorized by SolGuard."""

        if not self._requirement.matches(request, settlement_mode="LIVE_DEVNET"):
            raise AuthorizationRejected(ReasonCode.AUTHORIZATION_MISMATCH)
        self._authorization_guard.authorize(request, authorization)
        result = self._executor.execute(self._requirement, request)
        if (
            result.network != self._requirement.network
            or result.recipient != request.recipient
            or result.amount != request.amount
            or result.payer != self._executor.payer_address
            or not result.transaction_signature
        ):
            raise SettlementUnavailable(
                SettlementFailureKind.INVALID_RESPONSE,
                settlement_type=X402_DEVNET_LIVE_SETTLEMENT_TYPE,
            )
        return result


class OfficialX402DevnetExecutor:
    """Use the optional official x402 Python SDK for SVM signing and settlement."""

    def __init__(
        self,
        *,
        private_key: str,
        facilitator_url: str = DEFAULT_X402_FACILITATOR_URL,
        rpc_url: str = DEFAULT_SOLANA_DEVNET_RPC_URL,
    ) -> None:
        if not private_key or private_key != private_key.strip():
            raise ValueError(f"{PRIVATE_KEY_ENV} must be a non-empty trimmed value")
        self._facilitator_url = _https_origin(facilitator_url, field_name="facilitator_url")
        self._rpc_url = _https_origin(rpc_url, field_name="rpc_url")
        self._private_key = private_key
        self._payer_address = self._derive_payer_address(private_key)
        self._calls = 0

    @classmethod
    def from_environment(cls) -> OfficialX402DevnetExecutor:
        """Load a devnet-only key from the process environment without logging it."""

        private_key = os.environ.get(PRIVATE_KEY_ENV)
        if private_key is None:
            raise ValueError(f"{PRIVATE_KEY_ENV} is required for live devnet settlement")
        return cls(
            private_key=private_key,
            facilitator_url=os.environ.get(FACILITATOR_ENV, DEFAULT_X402_FACILITATOR_URL),
            rpc_url=os.environ.get(RPC_ENV, DEFAULT_SOLANA_DEVNET_RPC_URL),
        )

    @property
    def payer_address(self) -> str:
        return self._payer_address

    @property
    def calls(self) -> int:
        return self._calls

    @property
    def facilitator_url(self) -> str:
        return self._facilitator_url

    def discover_fee_payer(self) -> str:
        """Return the facilitator's current fee payer for x402 v2 Solana devnet."""

        try:
            supported = self._official_facilitator().get_supported()
            for kind in supported.kinds:
                if (
                    kind.x402_version == X402_VERSION
                    and kind.scheme == "exact"
                    and kind.network == X402_SOLANA_DEVNET_NETWORK
                    and kind.extra is not None
                ):
                    candidate = kind.extra.get("feePayer")
                    if isinstance(candidate, str) and candidate:
                        return candidate
        except Exception as exc:
            raise self._unavailable(exc) from None
        raise SettlementUnavailable(
            SettlementFailureKind.INVALID_RESPONSE,
            settlement_type=X402_DEVNET_LIVE_SETTLEMENT_TYPE,
        )

    def execute(
        self,
        requirement: X402PaymentRequirement,
        request: PaymentRequest,
    ) -> X402LiveSettlementResult:
        """Sign, verify, and settle the exact requirement through the test facilitator."""

        self._calls += 1
        try:
            payment_required = self._official_payment_required(requirement)
            client = self._official_client()
            payload = client.create_payment_payload(payment_required)
            accepted = payload.accepted
            with self._official_facilitator() as facilitator:
                verification = facilitator.verify(payload, accepted)
                if not verification.is_valid:
                    raise ValueError("facilitator rejected payment payload")
                settlement = facilitator.settle(payload, accepted)
            if not settlement.success or not settlement.transaction or settlement.amount is None:
                raise ValueError("facilitator did not confirm settlement")
            settled_amount = Decimal(settlement.amount) / _USDC_ATOMIC_FACTOR
            return X402LiveSettlementResult(
                settlement_reference=f"solana:devnet:{settlement.transaction}",
                transaction_signature=settlement.transaction,
                explorer_url=(
                    f"{SOLANA_DEVNET_EXPLORER_ROOT}/{settlement.transaction}?cluster=devnet"
                ),
                network=str(settlement.network),
                payer=settlement.payer or self._payer_address,
                recipient=request.recipient,
                amount=settled_amount,
                facilitator=self._facilitator_url,
            )
        except SettlementUnavailable:
            raise
        except Exception as exc:
            raise self._unavailable(exc) from None

    def _official_payment_required(self, requirement: X402PaymentRequirement) -> Any:
        from x402.schemas import PaymentRequired, ResourceInfo

        return PaymentRequired.model_validate(
            {
                "x402Version": X402_VERSION,
                "accepts": [dict(requirement.accepted)],
                "extensions": {},
                "resource": ResourceInfo(
                    url=requirement.resource_url,
                    description=requirement.description,
                    mime_type="application/json",
                    service_name="SolGuard devnet demonstration",
                    tags=["security", "agent-payments"],
                ),
            }
        )

    def _official_client(self) -> Any:
        from x402 import x402ClientSync
        from x402.mechanisms.svm import KeypairSigner
        from x402.mechanisms.svm.exact.register import (
            register_exact_svm_client,
        )

        client = x402ClientSync()
        signer = KeypairSigner.from_base58(self._private_key)
        return register_exact_svm_client(
            client,
            signer,
            networks=X402_SOLANA_DEVNET_NETWORK,
            rpc_url=self._rpc_url,
        )

    def _official_facilitator(self) -> Any:
        from x402.http import (
            FacilitatorConfig,
            HTTPFacilitatorClientSync,
        )

        return HTTPFacilitatorClientSync(FacilitatorConfig(url=self._facilitator_url, timeout=30.0))

    @staticmethod
    def _derive_payer_address(private_key: str) -> str:
        try:
            from x402.mechanisms.svm import KeypairSigner

            return KeypairSigner.from_base58(private_key).address
        except ImportError as exc:
            raise RuntimeError(
                'live devnet dependencies are missing; install the "devnet" extra'
            ) from exc
        except Exception as exc:
            raise ValueError(f"{PRIVATE_KEY_ENV} is not a valid Solana keypair") from exc

    @staticmethod
    def _unavailable(error: Exception) -> SettlementUnavailable:
        error_name = type(error).__name__.lower()
        if "timeout" in error_name:
            kind = SettlementFailureKind.TIMEOUT
        elif any(token in error_name for token in ("connect", "network", "transport")):
            kind = SettlementFailureKind.NETWORK
        elif isinstance(error, (ValueError, InvalidOperation)):
            kind = SettlementFailureKind.INVALID_RESPONSE
        else:
            kind = SettlementFailureKind.COMMAND_FAILED
        return SettlementUnavailable(kind, settlement_type=X402_DEVNET_LIVE_SETTLEMENT_TYPE)


def _https_origin(value: str, *, field_name: str) -> str:
    from urllib.parse import urlsplit

    if not value or value != value.strip() or len(value) > 2048:
        raise ValueError(f"{field_name} is invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{field_name} must be a credential-free HTTPS URL")
    return value.rstrip("/")


def _atomic_amount(value: str) -> tuple[Decimal, str]:
    try:
        amount = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError("amount must be a decimal USDC value") from exc
    atomic = amount * _USDC_ATOMIC_FACTOR
    if not amount.is_finite() or amount <= 0 or atomic != atomic.to_integral_value():
        raise ValueError("amount must be positive with at most six decimal places")
    return amount, str(int(atomic))


def build_live_requirement_header(
    *,
    amount_atomic: str,
    recipient: str,
    fee_payer: str,
) -> str:
    """Build the exact requirement used for a direct facilitator-backed devnet demo."""

    payload: JsonObject = {
        "accepts": [
            {
                "amount": amount_atomic,
                "asset": X402_SOLANA_DEVNET_USDC_MINT,
                "extra": {"feePayer": fee_payer, "memo": "solguard-live-demo"},
                "maxTimeoutSeconds": 60,
                "network": X402_SOLANA_DEVNET_NETWORK,
                "payTo": recipient,
                "scheme": "exact",
            }
        ],
        "extensions": {},
        "resource": {
            "description": "SolGuard protected autonomous API purchase",
            "mimeType": "application/json",
            "url": "https://demo.solguard.invalid/protected-resource",
        },
        "x402Version": X402_VERSION,
    }
    return base64.b64encode(canonical_json(payload).encode()).decode("ascii")


def run_live_devnet_demo(
    *,
    executor: X402LiveDemoExecutor,
    recipient: str,
    amount: str,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, JsonValue]:
    """Run one blocked proof followed by one real allowed devnet settlement."""

    amount_value, amount_atomic = _atomic_amount(amount)
    fee_payer = executor.discover_fee_payer()
    header = build_live_requirement_header(
        amount_atomic=amount_atomic,
        recipient=recipient,
        fee_payer=fee_payer,
    )
    requirement = parse_payment_required_header(header)
    now = (clock or (lambda: datetime.now(UTC)))()
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("clock must return a timezone-aware datetime")
    mandate = AgentMandate.from_dict(
        {
            "agent_id": "x402-live-agent",
            "allowed_recipients": [recipient],
            "asset": "USDC",
            "blocked_recipients": [],
            "expires_at": format_timestamp(now + timedelta(minutes=10)),
            "mandate_id": "x402-live-mandate",
            "max_single_payment": format_amount(amount_value),
            "purpose": "SolGuard protected autonomous API purchase",
            "valid_from": format_timestamp(now - timedelta(minutes=1)),
        }
    )
    settlement = X402DevnetLiveSettlement(
        requirement=requirement,
        executor=executor,
        authorization_guard=WalletAuthorizationGuard(clock=lambda: now),
    )
    gateway = PaymentGateway(
        policy=MandatePolicyEngine({mandate.agent_id: mandate}),
        detection=BehaviourEngine(),
        settlement=settlement,
        clock=lambda: now,
    )
    blocked_request = PaymentRequest.from_dict(
        {
            **requirement.to_payment_request(
                agent_id=mandate.agent_id,
                mandate_id=mandate.mandate_id,
                attempt_id="blocked-proof",
                observed_at=now,
                settlement_mode="LIVE_DEVNET",
            ).to_dict(),
            "amount": format_amount(amount_value * Decimal("2")),
            "nonce": "x402-live-blocked-proof",
            "request_id": "x402-live-blocked-proof",
        }
    )
    blocked = gateway.process(blocked_request)
    calls_before_allowed = executor.calls
    allowed_request = requirement.to_payment_request(
        agent_id=mandate.agent_id,
        mandate_id=mandate.mandate_id,
        attempt_id="allowed-live-settlement",
        observed_at=now,
        settlement_mode="LIVE_DEVNET",
    )
    allowed = gateway.process(allowed_request)
    verified = (
        blocked.result.decision is Decision.BLOCK
        and blocked.settlement is None
        and calls_before_allowed == 0
        and allowed.result.decision is Decision.ALLOW
        and allowed.settlement is not None
        and executor.calls == 1
    )
    return {
        "allowed": allowed.result.to_dict(),
        "blocked": blocked.result.to_dict(),
        "executor_calls": executor.calls,
        "network": X402_SOLANA_DEVNET_NETWORK,
        "payer": executor.payer_address,
        "settlement": (allowed.settlement.to_dict() if allowed.settlement is not None else None),
        "status": "VERIFIED" if verified else "FAILED",
    }


def _environment_recipient() -> str:
    recipient = os.environ.get(RECIPIENT_ENV)
    if recipient is None or not recipient or recipient != recipient.strip():
        raise ValueError(f"{RECIPIENT_ENV} is required for live devnet settlement")
    return recipient


def main(arguments: Sequence[str] | None = None) -> int:
    """Run an explicitly confirmed real Solana-devnet USDC settlement."""

    parser = argparse.ArgumentParser(
        description="Run SolGuard with a real x402 Solana-devnet USDC settlement"
    )
    parser.add_argument("--amount", default="0.001", help="USDC amount, maximum six decimals")
    parser.add_argument(
        "--confirm-devnet",
        action="store_true",
        help="confirm that one real devnet USDC settlement may be submitted",
    )
    parser.add_argument(
        "--show-wallet-address",
        action="store_true",
        help="print only the public payer address without submitting a payment",
    )
    args = parser.parse_args(arguments)
    try:
        executor = OfficialX402DevnetExecutor.from_environment()
        if args.show_wallet_address:
            print(executor.payer_address)
            return 0
        if not args.confirm_devnet:
            parser.error("--confirm-devnet is required to submit a real devnet payment")
        report = run_live_devnet_demo(
            executor=executor,
            recipient=_environment_recipient(),
            amount=args.amount,
        )
    except (RuntimeError, SettlementUnavailable, X402ProtocolError, ValueError) as exc:
        print(
            json.dumps(
                {"error_type": type(exc).__name__, "status": "FAILED"},
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0 if report["status"] == "VERIFIED" else 2


if __name__ == "__main__":  # pragma: no cover - exercised through console entry point
    raise SystemExit(main())
