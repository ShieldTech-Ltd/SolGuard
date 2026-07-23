"""Problem-first autonomous attack and protected-wallet security proof."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from http import HTTPStatus
from typing import cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from solguard.agent_auth import (
    AgentIdentityRegistry,
    RegisteredAgent,
    public_key_base64,
    sign_agent_request,
)
from solguard.autonomous_api import AutonomousDecisionService
from solguard.autonomous_runner import DeterministicPaidResourceClient
from solguard.contracts import (
    AgentMandate,
    Decision,
    JsonObject,
    JsonValue,
    PaymentRequest,
    ReasonCode,
    SigningAuthorization,
    format_amount,
    format_timestamp,
)
from solguard.detection import BehaviourEngine
from solguard.devnet_rpc import DevnetConfirmationError, SolanaDevnetConfirmer
from solguard.gateway import PaymentGateway
from solguard.policy import MandatePolicyEngine, PolicyResult
from solguard.settlement import SettlementFailureKind, SettlementResult, SettlementUnavailable
from solguard.wallet_signer import (
    CanonicalTransactionCodec,
    DeterministicEd25519WalletBackend,
    IsolatedSolanaWalletSigner,
    SignedWalletAuthorization,
    SolanaTransactionFields,
    SolGuardAuthorizationIssuer,
    SolGuardAuthorizationVerifier,
    WalletSigningReceipt,
    WalletSigningRejected,
)
from solguard.x402 import parse_payment_required_response
from solguard_demo_reference import UnsafeReferenceWallet

PROOF_AGENT_ID = "proof-agent"
PROOF_KEY_ID = "proof-agent-key-v1"
PROOF_MANDATE_ID = "proof-mandate-v1"
POLICY_VERSION = "agent-financial-mandate-v1"
INITIAL_SIMULATED_BALANCE = Decimal("1000000")
KNOWN_RECIPIENT = "ProofKnownMerchant1111111111111111111111111"
NOVEL_RECIPIENT = "ProofNovelMerchant1111111111111111111111111"
ATTACKER_RECIPIENT = "ProofAttackerWallet111111111111111111111111"
PROOF_TIME = datetime(2026, 7, 25, 10, 0, tzinfo=UTC)


class ProofInvariantError(RuntimeError):
    """Raised when computed proof evidence does not satisfy a required invariant."""


@dataclass(frozen=True, slots=True)
class ProofScenario:
    """One shared canonical request and its expected protected decision."""

    name: str
    request: PaymentRequest
    expected_decision: Decision
    expected_reason: ReasonCode | None
    adversarial: bool


@dataclass(frozen=True, slots=True)
class RequestEvidence:
    """Computed per-request evidence shared by CLI and passive visual observers."""

    scenario: str
    mode: str
    request: PaymentRequest
    decision: str
    reason_codes: tuple[str, ...]
    authorization_id: str | None
    wallet_signer_invoked: bool
    signing_state: str
    offline_wallet_signature: str | None
    solana_transaction_signature: str | None
    rpc_confirmation_status: str
    audit_receipt_digest: str | None
    balance_before: Decimal
    balance_after: Decimal

    def to_dict(self) -> JsonObject:
        return {
            "agent_id": self.request.agent_id,
            "audit_receipt_digest": self.audit_receipt_digest,
            "authorization_id": self.authorization_id,
            "balance_after": format_amount(self.balance_after),
            "balance_before": format_amount(self.balance_before),
            "canonical_request": self.request.to_dict(),
            "decision": self.decision,
            "mandate_id": self.request.mandate_id,
            "mode": self.mode,
            "offline_wallet_signature": self.offline_wallet_signature,
            "policy_version": POLICY_VERSION,
            "reason_codes": list(self.reason_codes),
            "request_digest": self.request.digest,
            "rpc_confirmation_status": self.rpc_confirmation_status,
            "scenario": self.scenario,
            "signing_state": self.signing_state,
            "solana_transaction_signature": self.solana_transaction_signature,
            "wallet_signer_invoked": self.wallet_signer_invoked,
        }


@dataclass(frozen=True, slots=True)
class _ProtectedSigningResult:
    receipt: WalletSigningReceipt
    balance_before: Decimal
    balance_after: Decimal
    authorization: SignedWalletAuthorization
    serialized_transaction: bytes


class _MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class _ForbiddenDecisionSettlement:
    def settle(
        self,
        request: PaymentRequest,
        authorization: SigningAuthorization | None,
    ) -> SettlementResult:
        del request, authorization
        raise RuntimeError("decision API cannot settle proof payments")


class _ProtectedOfflineBoundary:
    """Issue signed intent, invoke isolated wallet, then update a simulated ledger."""

    def __init__(
        self,
        *,
        issuer: SolGuardAuthorizationIssuer,
        signer: IsolatedSolanaWalletSigner,
        backend: DeterministicEd25519WalletBackend,
        codec: CanonicalTransactionCodec,
        balance: Decimal,
    ) -> None:
        self._issuer = issuer
        self._signer = signer
        self._backend = backend
        self._codec = codec
        self._balance = balance
        self.artifacts: dict[str, _ProtectedSigningResult] = {}

    @property
    def balance(self) -> Decimal:
        return self._balance

    @property
    def signer_calls(self) -> int:
        return self._backend.calls

    def settle(
        self,
        request: PaymentRequest,
        authorization: SigningAuthorization,
    ) -> _ProtectedSigningResult:
        if request.amount > self._balance:
            raise ProofInvariantError("protected simulated balance is insufficient")
        signed = self._issuer.issue(
            request=request,
            authorization=authorization,
            wallet_address=self._backend.wallet_address,
        )
        serialized = self._codec.serialize(signed.transaction)
        receipt = self._signer.sign(serialized, signed)
        balance_before = self._balance
        balance_after = balance_before - request.amount
        self._balance = balance_after
        result = _ProtectedSigningResult(
            receipt=receipt,
            balance_before=balance_before,
            balance_after=balance_after,
            authorization=signed,
            serialized_transaction=serialized,
        )
        self.artifacts[request.request_id] = result
        return result


@dataclass(slots=True)
class _ProtectedContext:
    service: AutonomousDecisionService
    agent_signer: Ed25519PrivateKey
    detection: BehaviourEngine
    boundary: _ProtectedOfflineBoundary
    clock: _MutableClock


def build_proof_scenarios() -> tuple[ProofScenario, ...]:
    """Create the immutable canonical sequence used by both comparison paths."""

    requirements = {
        "https://proof.invalid/normal": ("10", KNOWN_RECIPIENT),
        "https://proof.invalid/novel": ("10", NOVEL_RECIPIENT),
        "https://proof.invalid/anomaly": ("80", KNOWN_RECIPIENT),
        "https://proof.invalid/compound": ("20", ATTACKER_RECIPIENT),
        "https://proof.invalid/limit": ("150", KNOWN_RECIPIENT),
    }
    client = DeterministicPaidResourceClient(requirements)

    def request(resource_url: str, attempt_id: str, observed_at: datetime) -> PaymentRequest:
        response = client.request(resource_url)
        requirement = parse_payment_required_response(
            status=response.status,
            headers=response.headers,
        )
        return requirement.to_payment_request(
            agent_id=PROOF_AGENT_ID,
            mandate_id=PROOF_MANDATE_ID,
            attempt_id=attempt_id,
            observed_at=observed_at,
        )

    normal_1 = request("https://proof.invalid/normal", "normal-1", PROOF_TIME)
    return (
        ProofScenario("normal-1", normal_1, Decision.ALLOW, None, False),
        ProofScenario(
            "normal-2",
            request("https://proof.invalid/normal", "normal-2", PROOF_TIME),
            Decision.ALLOW,
            None,
            False,
        ),
        ProofScenario(
            "normal-3",
            request("https://proof.invalid/normal", "normal-3", PROOF_TIME),
            Decision.ALLOW,
            None,
            False,
        ),
        ProofScenario(
            "first-seen-recipient",
            request("https://proof.invalid/novel", "first-seen", PROOF_TIME),
            Decision.REQUIRE_APPROVAL,
            ReasonCode.DETECTION_RECIPIENT_NOVEL,
            True,
        ),
        ProofScenario(
            "velocity-only",
            request("https://proof.invalid/normal", "velocity", PROOF_TIME),
            Decision.REQUIRE_APPROVAL,
            ReasonCode.DETECTION_VELOCITY,
            True,
        ),
        ProofScenario(
            "exact-8x-amount-anomaly",
            request("https://proof.invalid/anomaly", "exact-8x", PROOF_TIME),
            Decision.BLOCK,
            ReasonCode.DETECTION_AMOUNT_ANOMALY,
            True,
        ),
        ProofScenario(
            "exact-2x-compound-drain",
            request("https://proof.invalid/compound", "exact-2x", PROOF_TIME),
            Decision.BLOCK,
            ReasonCode.DETECTION_COMPOUND_DRAIN,
            True,
        ),
        ProofScenario(
            "hard-spending-limit",
            request("https://proof.invalid/limit", "limit", PROOF_TIME),
            Decision.BLOCK,
            ReasonCode.POLICY_AMOUNT_LIMIT,
            True,
        ),
        ProofScenario(
            "replayed-request",
            normal_1,
            Decision.BLOCK,
            ReasonCode.REQUEST_REPLAYED,
            True,
        ),
        ProofScenario(
            "safe-recovery",
            request(
                "https://proof.invalid/normal",
                "safe-recovery",
                PROOF_TIME + timedelta(seconds=11),
            ),
            Decision.ALLOW,
            None,
            False,
        ),
    )


def _build_protected_context() -> _ProtectedContext:
    agent_signer = Ed25519PrivateKey.generate()
    issuer_key = Ed25519PrivateKey.generate()
    wallet_backend = DeterministicEd25519WalletBackend(Ed25519PrivateKey.generate())
    clock = _MutableClock(PROOF_TIME)
    mandate = AgentMandate.from_dict(
        {
            "agent_id": PROOF_AGENT_ID,
            "allowed_recipients": [
                KNOWN_RECIPIENT,
                NOVEL_RECIPIENT,
                ATTACKER_RECIPIENT,
            ],
            "asset": "USDC",
            "blocked_recipients": [],
            "expires_at": format_timestamp(PROOF_TIME + timedelta(hours=1)),
            "mandate_id": PROOF_MANDATE_ID,
            "max_single_payment": "100",
            "purpose": "Autonomous attack resistance proof",
            "valid_from": format_timestamp(PROOF_TIME - timedelta(minutes=1)),
        }
    )
    detection = BehaviourEngine()
    service = AutonomousDecisionService(
        gateway=PaymentGateway(
            policy=MandatePolicyEngine({PROOF_AGENT_ID: mandate}),
            detection=detection,
            settlement=_ForbiddenDecisionSettlement(),
            clock=clock,
        ),
        identities=AgentIdentityRegistry(
            {
                PROOF_KEY_ID: RegisteredAgent.from_base64(
                    agent_id=PROOF_AGENT_ID,
                    public_key=public_key_base64(agent_signer),
                )
            }
        ),
        mandates={PROOF_AGENT_ID: mandate},
    )
    issuer = SolGuardAuthorizationIssuer(key_id="proof-issuer-v1", private_key=issuer_key)
    codec = CanonicalTransactionCodec()
    signer = IsolatedSolanaWalletSigner(
        verifier=SolGuardAuthorizationVerifier({"proof-issuer-v1": issuer.public_key}),
        inspector=codec,
        backend=wallet_backend,
        clock=clock,
    )
    return _ProtectedContext(
        service=service,
        agent_signer=agent_signer,
        detection=detection,
        boundary=_ProtectedOfflineBoundary(
            issuer=issuer,
            signer=signer,
            backend=wallet_backend,
            codec=codec,
            balance=INITIAL_SIMULATED_BALANCE,
        ),
        clock=clock,
    )


def _run_unsafe(scenarios: Sequence[ProofScenario]) -> tuple[RequestEvidence, ...]:
    wallet = UnsafeReferenceWallet(
        private_key=Ed25519PrivateKey.generate(),
        balance=INITIAL_SIMULATED_BALANCE,
    )
    evidence: list[RequestEvidence] = []
    for scenario in scenarios:
        result = wallet.execute(scenario.request)
        evidence.append(
            RequestEvidence(
                scenario=scenario.name,
                mode="UNSAFE_OFFLINE_REFERENCE_SIMULATION",
                request=scenario.request,
                decision="UNPROTECTED",
                reason_codes=(),
                authorization_id=None,
                wallet_signer_invoked=True,
                signing_state="SIGNED_WITHOUT_FINANCIAL_AUTHORIZATION",
                offline_wallet_signature=result.signature,
                solana_transaction_signature=None,
                rpc_confirmation_status="NOT_SUBMITTED_SIMULATION",
                audit_receipt_digest=None,
                balance_before=result.balance_before,
                balance_after=result.balance_after,
            )
        )
    return tuple(evidence)


def _run_protected(
    scenarios: Sequence[ProofScenario],
) -> tuple[tuple[RequestEvidence, ...], _ProtectedContext]:
    context = _build_protected_context()
    evidence: list[RequestEvidence] = []
    for scenario in scenarios:
        context.clock.value = scenario.request.created_at
        balance_before = context.boundary.balance
        calls_before = context.boundary.signer_calls
        signature = sign_agent_request(
            scenario.request,
            key_id=PROOF_KEY_ID,
            private_key=context.agent_signer,
        )
        result = context.service.evaluate(
            cast(Mapping[str, object], scenario.request.to_dict()),
            key_id=PROOF_KEY_ID,
            signature=signature,
        )
        if result.status is not HTTPStatus.OK:
            raise ProofInvariantError("authenticated decision API returned failure")
        decision_value = result.payload.get("decision")
        if not isinstance(decision_value, str):
            raise ProofInvariantError("decision API response is invalid")
        try:
            decision = Decision(decision_value)
        except ValueError as exc:
            raise ProofInvariantError("decision API response is invalid") from exc
        reasons_value = result.payload.get("reason_codes")
        if not isinstance(reasons_value, list) or any(
            not isinstance(reason, str) for reason in reasons_value
        ):
            raise ProofInvariantError("decision reason codes are invalid")
        reasons = tuple(cast(str, reason) for reason in reasons_value)
        if decision is not scenario.expected_decision or (
            scenario.expected_reason is not None and scenario.expected_reason.value not in reasons
        ):
            raise ProofInvariantError(f"unexpected protected decision: {scenario.name}")
        raw_authorization = result.payload.get("authorization")
        authorization: SigningAuthorization | None = None
        signing_result: _ProtectedSigningResult | None = None
        if raw_authorization is not None:
            if not isinstance(raw_authorization, dict):
                raise ProofInvariantError("decision authorization is invalid")
            authorization = SigningAuthorization.from_dict(
                cast(Mapping[str, object], raw_authorization)
            )
        if decision is Decision.ALLOW:
            if authorization is None:
                raise ProofInvariantError("ALLOW omitted authorization")
            signing_result = context.boundary.settle(scenario.request, authorization)
            context.detection.record_allowed(scenario.request)
        elif authorization is not None:
            raise ProofInvariantError("non-ALLOW included authorization")
        signer_invoked = context.boundary.signer_calls > calls_before
        balance_after = context.boundary.balance
        if decision is not Decision.ALLOW and (signer_invoked or balance_after != balance_before):
            raise ProofInvariantError("blocked or quarantined request reached wallet")
        evidence.append(
            RequestEvidence(
                scenario=scenario.name,
                mode="SOLGUARD_PROTECTED_OFFLINE_CRYPTOGRAPHIC_SIMULATION",
                request=scenario.request,
                decision=decision.value,
                reason_codes=reasons,
                authorization_id=(
                    authorization.authorization_id if authorization is not None else None
                ),
                wallet_signer_invoked=signer_invoked,
                signing_state=(
                    signing_result.receipt.signing_outcome
                    if signing_result is not None
                    else "NOT_SIGNED"
                ),
                offline_wallet_signature=(
                    signing_result.receipt.transaction_signature
                    if signing_result is not None
                    else None
                ),
                solana_transaction_signature=None,
                rpc_confirmation_status="NOT_SUBMITTED_SIMULATION",
                audit_receipt_digest=cast(str | None, result.payload.get("audit_receipt_digest")),
                balance_before=balance_before,
                balance_after=balance_after,
            )
        )
    return tuple(evidence), context


def _wallet_adversarial_probes(context: _ProtectedContext) -> list[JsonObject]:
    first = next(iter(context.boundary.artifacts.values()))
    signer = context.boundary._signer
    codec = context.boundary._codec
    mutated_fields = SolanaTransactionFields.from_dict(
        cast(
            Mapping[str, object],
            {**first.authorization.transaction.to_dict(), "amount_atomic": "10000001"},
        )
    )
    probes: list[JsonObject] = []
    calls_before = context.boundary.signer_calls
    for name, serialized, authorization, expected in (
        (
            "transaction-mutation-after-authorization",
            codec.serialize(mutated_fields),
            first.authorization,
            ReasonCode.AUTHORIZATION_MISMATCH,
        ),
        (
            "single-use-authorization-replay",
            first.serialized_transaction,
            first.authorization,
            ReasonCode.AUTHORIZATION_REPLAYED,
        ),
        (
            "direct-wallet-call-without-authorization",
            first.serialized_transaction,
            None,
            ReasonCode.AUTHORIZATION_MISSING,
        ),
    ):
        try:
            signer.sign(serialized, authorization)
        except WalletSigningRejected as exc:
            observed = exc.reason_code
        else:
            raise ProofInvariantError(f"wallet probe unexpectedly signed: {name}")
        if observed is not expected:
            raise ProofInvariantError(f"wallet probe returned wrong reason: {name}")
        probes.append(
            {
                "authorization_result": observed.value,
                "name": name,
                "signer_invoked": context.boundary.signer_calls > calls_before,
                "status": "PASS",
                "transaction_signature": None,
            }
        )
    return probes


class _FailingPolicy:
    def evaluate(self, request: PaymentRequest) -> PolicyResult:
        del request
        raise RuntimeError("injected decision failure")


class _FailingSettlement:
    def settle(
        self,
        request: PaymentRequest,
        authorization: SigningAuthorization | None,
    ) -> SettlementResult:
        del request, authorization
        raise SettlementUnavailable(
            SettlementFailureKind.NETWORK,
            settlement_type="INJECTED_FACILITATOR",
        )


class _FailingSignerBackend:
    def __init__(self, wallet_address: str) -> None:
        self._wallet_address = wallet_address

    @property
    def wallet_address(self) -> str:
        return self._wallet_address

    def sign(self, serialized_transaction: bytes) -> str:
        del serialized_transaction
        raise OSError("injected signer failure")


class _FailingRpcTransport:
    def call(self, method: str, params: Sequence[JsonValue]) -> JsonValue:
        del method, params
        raise DevnetConfirmationError("injected RPC failure")


def _failure_probes(scenario: ProofScenario) -> list[JsonObject]:
    request = scenario.request
    clean_detection = BehaviourEngine()
    decision_failure = PaymentGateway(
        policy=_FailingPolicy(),
        detection=clean_detection,
        settlement=_ForbiddenDecisionSettlement(),
        clock=lambda: request.created_at,
    ).evaluate(request)
    if (
        decision_failure.result.decision is not Decision.BLOCK
        or ReasonCode.SYSTEM_FAILURE not in decision_failure.result.reason_codes
    ):
        raise ProofInvariantError("decision failure did not fail closed")

    mandate = AgentMandate.from_dict(
        {
            "agent_id": request.agent_id,
            "allowed_recipients": [request.recipient],
            "asset": request.asset,
            "blocked_recipients": [],
            "expires_at": format_timestamp(request.expires_at + timedelta(minutes=1)),
            "mandate_id": request.mandate_id,
            "max_single_payment": "100",
            "purpose": "Failure injection",
            "valid_from": format_timestamp(request.created_at - timedelta(minutes=1)),
        }
    )
    facilitator = PaymentGateway(
        policy=MandatePolicyEngine({request.agent_id: mandate}),
        detection=BehaviourEngine(),
        settlement=_FailingSettlement(),
        clock=lambda: request.created_at,
    ).process(request)
    if (
        facilitator.result.decision is not Decision.BLOCK
        or ReasonCode.SETTLEMENT_UNAVAILABLE not in facilitator.result.reason_codes
    ):
        raise ProofInvariantError("facilitator failure did not fail closed")

    issuer_key = Ed25519PrivateKey.generate()
    issuer = SolGuardAuthorizationIssuer(key_id="failure-issuer", private_key=issuer_key)
    healthy_backend = DeterministicEd25519WalletBackend(Ed25519PrivateKey.generate())
    failing_backend = _FailingSignerBackend(healthy_backend.wallet_address)
    codec = CanonicalTransactionCodec()
    authorization = SigningAuthorization(
        authorization_id="failure-auth",
        request_id=request.request_id,
        request_digest=request.digest,
        issued_at=request.created_at,
        expires_at=request.created_at + timedelta(seconds=30),
    )
    signed = issuer.issue(
        request=request,
        authorization=authorization,
        wallet_address=failing_backend.wallet_address,
    )
    failing_signer = IsolatedSolanaWalletSigner(
        verifier=SolGuardAuthorizationVerifier({"failure-issuer": issuer.public_key}),
        inspector=codec,
        backend=failing_backend,
        clock=lambda: request.created_at,
    )
    try:
        failing_signer.sign(codec.serialize(signed.transaction), signed)
    except WalletSigningRejected as exc:
        if exc.reason_code is not ReasonCode.SYSTEM_FAILURE:
            raise ProofInvariantError("signer failure returned wrong reason") from exc
    else:
        raise ProofInvariantError("signer failure unexpectedly returned a signature")

    try:
        SolanaDevnetConfirmer(_FailingRpcTransport()).confirm(
            transaction_signature="injected-signature",
            expected_mint=cast(str, request.metadata["asset_mint"]),
            expected_source_owner="source",
            expected_destination_owner=request.recipient,
            expected_amount_atomic="10000000",
        )
    except DevnetConfirmationError:
        pass
    else:
        raise ProofInvariantError("RPC failure unexpectedly returned confirmation")

    return [
        _failure_probe("decision-api-security-path", ReasonCode.SYSTEM_FAILURE),
        _failure_probe("isolated-wallet-signer", ReasonCode.SYSTEM_FAILURE),
        _failure_probe("x402-facilitator", ReasonCode.SETTLEMENT_UNAVAILABLE),
        _failure_probe("solana-rpc-confirmation", ReasonCode.SETTLEMENT_UNAVAILABLE),
    ]


def _failure_probe(name: str, reason: ReasonCode) -> JsonObject:
    return {
        "authorization_result": reason.value,
        "name": name,
        "signer_invoked": False,
        "status": "PASS",
        "transaction_signature": None,
    }


def run_security_proof() -> JsonObject:
    """Run unsafe and protected acts, then enforce every offline proof invariant."""

    scenarios = build_proof_scenarios()
    unsafe = _run_unsafe(scenarios)
    protected, context = _run_protected(scenarios)
    by_name_unsafe = {item.scenario: item for item in unsafe}
    by_name_protected = {item.scenario: item for item in protected}
    primary = "exact-2x-compound-drain"
    unsafe_attack = by_name_unsafe[primary]
    protected_attack = by_name_protected[primary]
    if unsafe_attack.request.digest != protected_attack.request.digest:
        raise ProofInvariantError("comparison paths did not use the same attack request")
    if (
        unsafe_attack.offline_wallet_signature is None
        or unsafe_attack.balance_after >= unsafe_attack.balance_before
        or protected_attack.decision != Decision.BLOCK.value
        or protected_attack.authorization_id is not None
        or protected_attack.wallet_signer_invoked
        or protected_attack.offline_wallet_signature is not None
        or protected_attack.balance_after != protected_attack.balance_before
    ):
        raise ProofInvariantError("problem-first comparison invariant failed")
    for scenario in scenarios:
        item = by_name_protected[scenario.name]
        if scenario.expected_decision is not Decision.ALLOW and (
            item.authorization_id is not None
            or item.wallet_signer_invoked
            or item.offline_wallet_signature is not None
            or item.balance_after != item.balance_before
        ):
            raise ProofInvariantError(f"unsafe protected evidence: {scenario.name}")
    recovery = by_name_protected["safe-recovery"]
    if (
        recovery.decision != Decision.ALLOW.value
        or not recovery.wallet_signer_invoked
        or recovery.offline_wallet_signature is None
    ):
        raise ProofInvariantError("safe recovery did not complete")
    probes = _wallet_adversarial_probes(context) + _failure_probes(scenarios[0])
    return {
        "comparison": {
            "attack_request_digest": unsafe_attack.request.digest,
            "protected_balance_unchanged": (
                protected_attack.balance_before == protected_attack.balance_after
            ),
            "protected_signer_invoked": protected_attack.wallet_signer_invoked,
            "same_canonical_attack_fixture": True,
            "unsafe_balance_decreased": unsafe_attack.balance_after < unsafe_attack.balance_before,
            "unsafe_reference_signed": unsafe_attack.offline_wallet_signature is not None,
        },
        "failure_and_wallet_probes": cast(JsonValue, probes),
        "mode": "OFFLINE_CRYPTOGRAPHIC_AND_LEDGER_SIMULATION",
        "protected_act": [item.to_dict() for item in protected],
        "real_devnet_evidence": "NOT_EXECUTED_CREDENTIALS_REQUIRED",
        "security_invariants": "PASS",
        "threat_boundary": (
            "Direct theft of an independently usable wallet private key is outside this proof; "
            "the protected agent never possesses or directly invokes that key."
        ),
        "unsafe_problem_act": [item.to_dict() for item in unsafe],
    }


def main(argv: Sequence[str] | None = None) -> int:
    """Run the authoritative machine-readable offline security proof."""

    parser = argparse.ArgumentParser(description="Run the SolGuard autonomous attack proof")
    parser.parse_args(argv)
    try:
        report = run_security_proof()
    except Exception as exc:
        print(
            json.dumps(
                {"error_type": type(exc).__name__, "security_invariants": "FAIL"},
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - module execution boundary
    raise SystemExit(main())
