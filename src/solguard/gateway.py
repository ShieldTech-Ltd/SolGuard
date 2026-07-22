"""Fail-closed orchestration immediately before a payment signer."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from time import perf_counter_ns
from typing import Protocol

from solguard.authorization import AuthorizationRejected, WalletAuthorizationGuard
from solguard.contracts import (
    AgentMandate,
    ContractValidationError,
    Decision,
    DecisionResult,
    PaymentRequest,
    ReasonCode,
    SigningAuthorization,
    format_amount,
)
from solguard.detection import BehaviourEngine, DetectionResult, DetectionSignal
from solguard.integrity import IntegrityResult, RequestIntegrityGuard
from solguard.policy import MandatePolicyEngine, PolicyResult
from solguard.settlement import SettlementResult, SettlementUnavailable
from solguard.simulation import (
    InsufficientSimulatedFunds,
    SimulatedSettlement,
)


class PolicyEvaluator(Protocol):
    """Policy interface used by the gateway."""

    def evaluate(self, request: PaymentRequest) -> PolicyResult: ...


class DetectionEvaluator(Protocol):
    """Behaviour interface used by the gateway."""

    def evaluate(self, request: PaymentRequest, *, observed_at: datetime) -> DetectionResult: ...

    def record_allowed(self, request: PaymentRequest) -> None: ...


class IntegrityEvaluator(Protocol):
    """Basic request freshness and replay interface used by the gateway."""

    def evaluate(self, request: PaymentRequest, *, observed_at: datetime) -> IntegrityResult: ...


class SettlementAdapter(Protocol):
    """Minimal settlement boundary used by the Phase 1 gateway."""

    def settle(
        self, request: PaymentRequest, authorization: SigningAuthorization | None
    ) -> SettlementResult: ...


@dataclass(frozen=True, slots=True)
class GatewayOutcome:
    """Gateway decision and optional successful simulated settlement."""

    result: DecisionResult
    settlement: SettlementResult | None


class PaymentGateway:
    """Combine policy and behaviour controls without allowing unsafe bypass."""

    AUTHORIZATION_LIFETIME = timedelta(seconds=30)

    def __init__(
        self,
        *,
        policy: PolicyEvaluator,
        detection: DetectionEvaluator,
        settlement: SettlementAdapter,
        integrity: IntegrityEvaluator | None = None,
        clock: Callable[[], datetime] | None = None,
        timer_ns: Callable[[], int] | None = None,
    ) -> None:
        self._policy = policy
        self._detection = detection
        self._settlement = settlement
        self._integrity = integrity if integrity is not None else RequestIntegrityGuard()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._timer_ns = timer_ns or perf_counter_ns

    def process(self, payload: PaymentRequest | Mapping[str, object]) -> GatewayOutcome:
        """Evaluate one request and settle only a clean, policy-compliant payment."""

        return self._process(payload, settle=True)

    def evaluate(self, payload: PaymentRequest | Mapping[str, object]) -> GatewayOutcome:
        """Evaluate and authorize without calling the settlement boundary."""

        return self._process(payload, settle=False)

    def _process(
        self,
        payload: PaymentRequest | Mapping[str, object],
        *,
        settle: bool,
    ) -> GatewayOutcome:
        """Run the shared fail-closed path with an explicit settlement boundary."""

        started_ns = self._timer_ns()
        if isinstance(payload, PaymentRequest):
            request = payload
        else:
            try:
                request = PaymentRequest.from_dict(payload)
            except (ContractValidationError, KeyError, TypeError, ValueError) as exc:
                return self._blocked_invalid(payload, exc, started_ns=started_ns)

        try:
            observed_at = self._clock()
            integrity_result = self._integrity.evaluate(request, observed_at=observed_at)
            if integrity_result.decision is Decision.BLOCK:
                return self._blocked_integrity(
                    request,
                    integrity=integrity_result,
                    started_ns=started_ns,
                )
            policy_result = self._policy.evaluate(request)
            detection_result = self._detection.evaluate(request, observed_at=observed_at)
            if (
                policy_result.decision is Decision.BLOCK
                or detection_result.signal is DetectionSignal.BLOCK
            ):
                return self._outcome(
                    request=request,
                    decision=Decision.BLOCK,
                    integrity=integrity_result,
                    policy=policy_result,
                    detection=detection_result,
                    settlement=None,
                    authorization=None,
                    started_ns=started_ns,
                )
            if detection_result.signal is DetectionSignal.FLAG:
                return self._outcome(
                    request=request,
                    decision=Decision.REQUIRE_APPROVAL,
                    integrity=integrity_result,
                    policy=policy_result,
                    detection=detection_result,
                    settlement=None,
                    authorization=None,
                    started_ns=started_ns,
                )

            authorization = self._authorization(request, observed_at=observed_at)
            if not settle:
                return self._outcome(
                    request=request,
                    decision=Decision.ALLOW,
                    integrity=integrity_result,
                    policy=policy_result,
                    detection=detection_result,
                    settlement=None,
                    authorization=authorization,
                    started_ns=started_ns,
                )
            try:
                settlement_result = self._settlement.settle(request, authorization)
            except AuthorizationRejected as exc:
                return self._blocked_authorization(
                    request,
                    rejection=exc,
                    integrity=integrity_result,
                    policy=policy_result,
                    detection=detection_result,
                    started_ns=started_ns,
                )
            except SettlementUnavailable as exc:
                return self._blocked_unavailable(
                    request,
                    failure=exc,
                    integrity=integrity_result,
                    policy=policy_result,
                    detection=detection_result,
                    started_ns=started_ns,
                )
            except InsufficientSimulatedFunds:
                return self._blocked_settlement(
                    request,
                    integrity=integrity_result,
                    policy=policy_result,
                    detection=detection_result,
                    started_ns=started_ns,
                )
            self._detection.record_allowed(request)
            return self._outcome(
                request=request,
                decision=Decision.ALLOW,
                integrity=integrity_result,
                policy=policy_result,
                detection=detection_result,
                settlement=settlement_result,
                authorization=authorization,
                started_ns=started_ns,
            )
        except Exception as exc:
            return self._blocked_system(request, exc, started_ns=started_ns)

    def _authorization(
        self, request: PaymentRequest, *, observed_at: datetime
    ) -> SigningAuthorization:
        material = f"{request.digest}|{observed_at.isoformat()}".encode()
        identifier = hashlib.sha256(material).hexdigest()[:32]
        return SigningAuthorization(
            authorization_id=f"auth_{identifier}",
            request_id=request.request_id,
            request_digest=request.digest,
            issued_at=observed_at,
            expires_at=observed_at + self.AUTHORIZATION_LIFETIME,
        )

    def _outcome(
        self,
        *,
        request: PaymentRequest,
        decision: Decision,
        integrity: IntegrityResult,
        policy: PolicyResult,
        detection: DetectionResult,
        settlement: SettlementResult | None,
        authorization: SigningAuthorization | None,
        started_ns: int,
    ) -> GatewayOutcome:
        evidence: dict[str, object] = {
            "detection": dict(detection.evidence),
            "integrity": dict(integrity.evidence),
            "latency_ms": self._elapsed_ms(started_ns),
            "policy": dict(policy.evidence),
            "settlement": settlement.to_dict() if settlement is not None else None,
        }
        reasons = policy.reason_codes + detection.reason_codes
        result = DecisionResult.create(
            request_id=request.request_id,
            decision=decision,
            reason_codes=reasons,
            request_digest=request.digest,
            evidence=evidence,
            authorization=authorization,
        )
        return GatewayOutcome(result=result, settlement=settlement)

    def _blocked_settlement(
        self,
        request: PaymentRequest,
        *,
        integrity: IntegrityResult,
        policy: PolicyResult,
        detection: DetectionResult,
        started_ns: int,
    ) -> GatewayOutcome:
        evidence: dict[str, object] = {
            "detection": dict(detection.evidence),
            "integrity": dict(integrity.evidence),
            "latency_ms": self._elapsed_ms(started_ns),
            "policy": dict(policy.evidence),
            "settlement": {
                "amount": format_amount(request.amount),
                "settlement_type": "SIMULATED",
                "status": "INSUFFICIENT_FUNDS",
            },
        }
        result = DecisionResult.create(
            request_id=request.request_id,
            decision=Decision.BLOCK,
            reason_codes=(ReasonCode.SETTLEMENT_INSUFFICIENT_FUNDS,),
            request_digest=request.digest,
            evidence=evidence,
        )
        return GatewayOutcome(result=result, settlement=None)

    def _blocked_authorization(
        self,
        request: PaymentRequest,
        *,
        rejection: AuthorizationRejected,
        integrity: IntegrityResult,
        policy: PolicyResult,
        detection: DetectionResult,
        started_ns: int,
    ) -> GatewayOutcome:
        result = DecisionResult.create(
            request_id=request.request_id,
            decision=Decision.BLOCK,
            reason_codes=(rejection.reason_code,),
            request_digest=request.digest,
            evidence={
                "detection": dict(detection.evidence),
                "integrity": dict(integrity.evidence),
                "latency_ms": self._elapsed_ms(started_ns),
                "policy": dict(policy.evidence),
                "settlement": None,
                "stage": "WALLET_AUTHORIZATION",
            },
        )
        return GatewayOutcome(result=result, settlement=None)

    def _blocked_unavailable(
        self,
        request: PaymentRequest,
        *,
        failure: SettlementUnavailable,
        integrity: IntegrityResult,
        policy: PolicyResult,
        detection: DetectionResult,
        started_ns: int,
    ) -> GatewayOutcome:
        evidence: dict[str, object] = {
            "detection": dict(detection.evidence),
            "integrity": dict(integrity.evidence),
            "latency_ms": self._elapsed_ms(started_ns),
            "policy": dict(policy.evidence),
            "security_decision": Decision.ALLOW.value,
            "settlement": {
                "failure_kind": failure.kind.value,
                "settlement_type": failure.settlement_type,
                "status": "UNAVAILABLE",
            },
            "stage": "EXTERNAL_SETTLEMENT",
        }
        result = DecisionResult.create(
            request_id=request.request_id,
            decision=Decision.BLOCK,
            reason_codes=(ReasonCode.SETTLEMENT_UNAVAILABLE,),
            request_digest=request.digest,
            evidence=evidence,
        )
        return GatewayOutcome(result=result, settlement=None)

    def _blocked_integrity(
        self,
        request: PaymentRequest,
        *,
        integrity: IntegrityResult,
        started_ns: int,
    ) -> GatewayOutcome:
        result = DecisionResult.create(
            request_id=request.request_id,
            decision=Decision.BLOCK,
            reason_codes=integrity.reason_codes,
            request_digest=request.digest,
            evidence={
                "integrity": dict(integrity.evidence),
                "latency_ms": self._elapsed_ms(started_ns),
                "stage": "REQUEST_INTEGRITY",
            },
        )
        return GatewayOutcome(result=result, settlement=None)

    def _blocked_invalid(
        self,
        payload: Mapping[str, object],
        error: Exception,
        *,
        started_ns: int,
    ) -> GatewayOutcome:
        request_id = "unparsed"
        candidate = payload.get("request_id")
        if isinstance(candidate, str) and candidate.strip():
            request_id = candidate.strip()[:128]
        result = DecisionResult.create(
            request_id=request_id,
            decision=Decision.BLOCK,
            reason_codes=(ReasonCode.REQUEST_INVALID,),
            request_digest=self._untrusted_digest(payload),
            evidence={
                "error": str(error),
                "latency_ms": self._elapsed_ms(started_ns),
                "stage": "CONTRACT_VALIDATION",
            },
        )
        return GatewayOutcome(result=result, settlement=None)

    def _blocked_system(
        self, request: PaymentRequest, error: Exception, *, started_ns: int
    ) -> GatewayOutcome:
        result = DecisionResult.create(
            request_id=request.request_id,
            decision=Decision.BLOCK,
            reason_codes=(ReasonCode.SYSTEM_FAILURE,),
            request_digest=request.digest,
            evidence={
                "error_type": type(error).__name__,
                "latency_ms": self._elapsed_ms(started_ns),
                "stage": "SECURITY_PATH",
            },
        )
        return GatewayOutcome(result=result, settlement=None)

    def _elapsed_ms(self, started_ns: int) -> str:
        elapsed_ns = max(0, self._timer_ns() - started_ns)
        return format_amount(Decimal(elapsed_ns) / Decimal("1000000"))

    @staticmethod
    def _untrusted_digest(payload: object) -> str:
        try:
            encoded = json.dumps(
                payload,
                default=lambda value: f"<{type(value).__name__}>",
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        except (TypeError, ValueError):
            encoded = type(payload).__name__.encode()
        return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def build_simulated_gateway(
    *,
    mandates: Mapping[str, AgentMandate],
    balances: Mapping[str, Decimal],
    clock: Callable[[], datetime] | None = None,
    timer_ns: Callable[[], int] | None = None,
) -> PaymentGateway:
    """Build the local fallback gateway from already validated mandate objects."""

    if any(not isinstance(mandate, AgentMandate) for mandate in mandates.values()):
        raise ValueError("all mandates must be validated AgentMandate instances")
    active_clock = clock or (lambda: datetime.now(UTC))
    return PaymentGateway(
        policy=MandatePolicyEngine(mandates),
        detection=BehaviourEngine(),
        settlement=SimulatedSettlement(
            balances,
            authorization_guard=WalletAuthorizationGuard(clock=active_clock),
        ),
        clock=active_clock,
        timer_ns=timer_ns,
    )
