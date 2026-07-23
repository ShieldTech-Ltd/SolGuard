"""Deterministic headless runner for autonomous x402 payment security."""

from __future__ import annotations

import argparse
import base64
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from http import HTTPStatus
from typing import Protocol, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from solguard.agent_auth import (
    AgentIdentityRegistry,
    RegisteredAgent,
    public_key_base64,
    sign_agent_request,
)
from solguard.authorization import WalletAuthorizationGuard
from solguard.autonomous_api import AutonomousApiResult, AutonomousDecisionService
from solguard.contracts import (
    AgentMandate,
    ContractValidationError,
    Decision,
    JsonObject,
    JsonValue,
    PaymentRequest,
    ReasonCode,
    SigningAuthorization,
    canonical_json,
    format_timestamp,
)
from solguard.detection import BehaviourEngine
from solguard.gateway import PaymentGateway
from solguard.policy import MandatePolicyEngine
from solguard.settlement import SettlementResult
from solguard.simulation import SimulatedSettlement
from solguard.x402 import (
    X402_PAYMENT_REQUIRED_HEADER,
    X402_SOLANA_DEVNET_NETWORK,
    X402_SOLANA_DEVNET_USDC_MINT,
    parse_payment_required_response,
)

DEMO_AGENT_ID = "autonomous-demo-agent"
DEMO_KEY_ID = "autonomous-demo-key-v1"
DEMO_MANDATE_ID = "autonomous-demo-mandate"
KNOWN_RECIPIENT = "KnownMerchant11111111111111111111111111111"
NOVEL_RECIPIENT = "NovelMerchant11111111111111111111111111111"
ATTACKER_RECIPIENT = "AttackerWallet111111111111111111111111111"


class AutonomousRunError(RuntimeError):
    """Raised when a protocol failure or security invariant stops the runner."""


@dataclass(frozen=True, slots=True)
class ResourceResponse:
    """Minimal paid-resource HTTP response consumed by the runner."""

    status: int
    headers: Mapping[str, str]


class PaidResourceClient(Protocol):
    """Network boundary used to request one x402-protected resource."""

    def request(self, resource_url: str) -> ResourceResponse: ...


class DecisionApiClient(Protocol):
    """Authenticated SolGuard decision API boundary."""

    def evaluate(
        self,
        request: PaymentRequest,
        *,
        key_id: str,
        signature: str,
    ) -> AutonomousApiResult: ...


class SettlementBoundary(Protocol):
    """Wallet boundary reachable only after an ALLOW authorization."""

    def settle(
        self,
        request: PaymentRequest,
        authorization: SigningAuthorization | None,
    ) -> SettlementResult: ...


class AllowedPaymentRecorder(Protocol):
    """Trusted callback used only after confirmed settlement."""

    def record_allowed(self, request: PaymentRequest) -> None: ...


@dataclass(frozen=True, slots=True)
class Scenario:
    """One immutable expected decision in the deterministic demonstration."""

    name: str
    resource_url: str
    attempt_id: str
    expected_decision: Decision
    expected_reason: ReasonCode | None = None
    replay_of: str | None = None


@dataclass(frozen=True, slots=True)
class RuntimeEvent:
    """Machine-readable transition derived from the executing runner."""

    sequence: int
    scenario: str
    event_type: str
    payload: Mapping[str, JsonValue]

    def to_dict(self) -> JsonObject:
        return {
            "event_type": self.event_type,
            "payload": cast(JsonValue, dict(self.payload)),
            "scenario": self.scenario,
            "sequence": self.sequence,
        }


@dataclass(frozen=True, slots=True)
class AutonomousRunReport:
    """Complete deterministic outcome suitable for CLI and passive observers."""

    events: tuple[RuntimeEvent, ...]
    settlement_attempts: int
    settlement_count: int
    quarantined_count: int
    blocked_count: int

    def to_dict(self) -> JsonObject:
        return {
            "blocked_count": self.blocked_count,
            "events": [event.to_dict() for event in self.events],
            "mode": "DETERMINISTIC_SIMULATION",
            "quarantined_count": self.quarantined_count,
            "security_invariants": "PASS",
            "settlement_attempts": self.settlement_attempts,
            "settlement_count": self.settlement_count,
        }


class InProcessDecisionApiClient:
    """Call the same authenticated service used by the HTTP API without a socket."""

    def __init__(self, service: AutonomousDecisionService) -> None:
        self._service = service

    def evaluate(
        self,
        request: PaymentRequest,
        *,
        key_id: str,
        signature: str,
    ) -> AutonomousApiResult:
        return self._service.evaluate(
            cast(Mapping[str, object], request.to_dict()),
            key_id=key_id,
            signature=signature,
        )


class DeterministicPaidResourceClient:
    """Return explicit simulated HTTP 402 fixtures without external availability risk."""

    def __init__(self, requirements: Mapping[str, tuple[str, str]]) -> None:
        self._requirements = dict(requirements)

    def request(self, resource_url: str) -> ResourceResponse:
        requirement = self._requirements.get(resource_url)
        if requirement is None:
            raise AutonomousRunError("paid resource is not configured")
        amount, recipient = requirement
        return ResourceResponse(
            status=HTTPStatus.PAYMENT_REQUIRED,
            headers={
                X402_PAYMENT_REQUIRED_HEADER: _payment_required_header(
                    resource_url=resource_url,
                    amount=amount,
                    recipient=recipient,
                )
            },
        )


class AutonomousPaymentRunner:
    """Execute signed x402 intents without direct access to any wallet signer."""

    def __init__(
        self,
        *,
        resource_client: PaidResourceClient,
        decision_client: DecisionApiClient,
        settlement: SettlementBoundary,
        recorder: AllowedPaymentRecorder,
        private_key: Ed25519PrivateKey,
        key_id: str,
        clock: Callable[[], datetime],
        observer: Callable[[RuntimeEvent], None] | None = None,
    ) -> None:
        self._resource_client = resource_client
        self._decision_client = decision_client
        self._settlement = settlement
        self._recorder = recorder
        self._private_key = private_key
        self._key_id = key_id
        self._clock = clock
        self._observer = observer
        self._events: list[RuntimeEvent] = []

    def run(self, scenarios: Sequence[Scenario]) -> AutonomousRunReport:
        """Run every declared scenario and fail if observed decisions differ."""

        self._events = []
        requests: dict[str, PaymentRequest] = {}
        settled = quarantined = blocked = 0
        settlement_attempts = 0
        names = [scenario.name for scenario in scenarios]
        if not scenarios or len(names) != len(set(names)):
            raise AutonomousRunError("scenarios must be non-empty with unique names")

        for scenario in scenarios:
            self._emit(scenario.name, "RESOURCE_REQUESTED", {"url": scenario.resource_url})
            if scenario.replay_of is None:
                try:
                    response = self._resource_client.request(scenario.resource_url)
                    requirement = parse_payment_required_response(
                        status=response.status,
                        headers=response.headers,
                    )
                    request = requirement.to_payment_request(
                        agent_id=DEMO_AGENT_ID,
                        mandate_id=DEMO_MANDATE_ID,
                        attempt_id=scenario.attempt_id,
                        observed_at=self._clock(),
                    )
                except Exception as exc:
                    raise AutonomousRunError("paid resource protocol failed") from exc
            else:
                try:
                    request = requests[scenario.replay_of]
                except KeyError as exc:
                    raise AutonomousRunError("replay target must precede the replay") from exc
            requests[scenario.name] = request
            signature = sign_agent_request(
                request,
                key_id=self._key_id,
                private_key=self._private_key,
            )
            try:
                result = self._decision_client.evaluate(
                    request,
                    key_id=self._key_id,
                    signature=signature,
                )
            except Exception as exc:
                raise AutonomousRunError("decision API failed") from exc
            decision = _validated_decision(result, request=request)
            reasons = _reason_codes(result.payload)
            self._emit(
                scenario.name,
                "DECISION_RECEIVED",
                {
                    "audit_receipt_digest": result.payload.get("audit_receipt_digest"),
                    "decision": decision.value,
                    "reason_codes": [reason.value for reason in reasons],
                    "request_digest": request.digest,
                },
            )
            if decision is not scenario.expected_decision or (
                scenario.expected_reason is not None and scenario.expected_reason not in reasons
            ):
                raise AutonomousRunError(f"unexpected decision for scenario {scenario.name}")

            authorization = _authorization(result.payload)
            if decision is Decision.ALLOW:
                if authorization is None:
                    raise AutonomousRunError("ALLOW response omitted authorization")
                settlement_attempts += 1
                try:
                    settlement_result = self._settlement.settle(request, authorization)
                except Exception as exc:
                    raise AutonomousRunError("settlement boundary failed") from exc
                self._recorder.record_allowed(request)
                settled += 1
                self._emit(
                    scenario.name,
                    "SETTLED",
                    cast(Mapping[str, JsonValue], settlement_result.to_dict()),
                )
            elif authorization is not None:
                raise AutonomousRunError("non-ALLOW response exposed an authorization")
            elif decision is Decision.REQUIRE_APPROVAL:
                quarantined += 1
                self._emit(scenario.name, "QUARANTINED", {"signer_called": False})
            else:
                blocked += 1
                self._emit(scenario.name, "BLOCKED", {"signer_called": False})

        return AutonomousRunReport(
            events=tuple(self._events),
            settlement_attempts=settlement_attempts,
            settlement_count=settled,
            quarantined_count=quarantined,
            blocked_count=blocked,
        )

    def _emit(
        self,
        scenario: str,
        event_type: str,
        payload: Mapping[str, JsonValue],
    ) -> None:
        event = RuntimeEvent(
            sequence=len(self._events) + 1,
            scenario=scenario,
            event_type=event_type,
            payload=dict(payload),
        )
        self._events.append(event)
        if self._observer is not None:
            self._observer(event)


def deterministic_scenarios() -> tuple[Scenario, ...]:
    """Return the immutable normal, novelty, replay, and drain sequence."""

    return (
        Scenario("normal-1", "https://merchant.invalid/data/1", "normal-1", Decision.ALLOW),
        Scenario("normal-2", "https://merchant.invalid/data/2", "normal-2", Decision.ALLOW),
        Scenario("normal-3", "https://merchant.invalid/data/3", "normal-3", Decision.ALLOW),
        Scenario(
            "first-seen-recipient",
            "https://novel.invalid/data",
            "first-seen",
            Decision.REQUIRE_APPROVAL,
            ReasonCode.DETECTION_RECIPIENT_NOVEL,
        ),
        Scenario(
            "replay-attack",
            "https://novel.invalid/data",
            "unused-replay-id",
            Decision.BLOCK,
            ReasonCode.REQUEST_REPLAYED,
            replay_of="first-seen-recipient",
        ),
        Scenario(
            "compound-drain",
            "https://attacker.invalid/drain",
            "compound-drain",
            Decision.BLOCK,
            ReasonCode.DETECTION_COMPOUND_DRAIN,
        ),
    )


def build_deterministic_runner(
    *,
    now: datetime | None = None,
    observer: Callable[[RuntimeEvent], None] | None = None,
) -> tuple[AutonomousPaymentRunner, SimulatedSettlement]:
    """Build the dependency-free demonstration with an explicitly simulated wallet."""

    observed_at = now or datetime.now(UTC)
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        raise ValueError("now must include a timezone")
    private_key = Ed25519PrivateKey.generate()
    mandate = AgentMandate.from_dict(
        {
            "agent_id": DEMO_AGENT_ID,
            "allowed_recipients": [KNOWN_RECIPIENT, NOVEL_RECIPIENT, ATTACKER_RECIPIENT],
            "asset": "USDC",
            "blocked_recipients": [],
            "expires_at": format_timestamp(observed_at + timedelta(hours=1)),
            "mandate_id": DEMO_MANDATE_ID,
            "max_single_payment": "100",
            "purpose": "Deterministic autonomous payment security demonstration",
            "valid_from": format_timestamp(observed_at - timedelta(minutes=1)),
        }
    )
    identities = AgentIdentityRegistry(
        {
            DEMO_KEY_ID: RegisteredAgent.from_base64(
                agent_id=DEMO_AGENT_ID,
                public_key=public_key_base64(private_key),
            )
        }
    )
    detection = BehaviourEngine()
    gateway = PaymentGateway(
        policy=MandatePolicyEngine({DEMO_AGENT_ID: mandate}),
        detection=detection,
        settlement=_ForbiddenRunnerSettlement(),
        clock=lambda: observed_at,
    )
    service = AutonomousDecisionService(
        gateway=gateway,
        identities=identities,
        mandates={DEMO_AGENT_ID: mandate},
    )
    settlement = SimulatedSettlement(
        {DEMO_AGENT_ID: Decimal("1000000")},
        authorization_guard=WalletAuthorizationGuard(clock=lambda: observed_at),
    )
    requirements = {
        "https://merchant.invalid/data/1": ("10", KNOWN_RECIPIENT),
        "https://merchant.invalid/data/2": ("10", KNOWN_RECIPIENT),
        "https://merchant.invalid/data/3": ("10", KNOWN_RECIPIENT),
        "https://novel.invalid/data": ("10", NOVEL_RECIPIENT),
        "https://attacker.invalid/drain": ("20", ATTACKER_RECIPIENT),
    }
    return (
        AutonomousPaymentRunner(
            resource_client=DeterministicPaidResourceClient(requirements),
            decision_client=InProcessDecisionApiClient(service),
            settlement=settlement,
            recorder=detection,
            private_key=private_key,
            key_id=DEMO_KEY_ID,
            clock=lambda: observed_at,
            observer=observer,
        ),
        settlement,
    )


class _ForbiddenRunnerSettlement:
    def settle(
        self,
        request: PaymentRequest,
        authorization: SigningAuthorization | None,
    ) -> SettlementResult:
        del request, authorization
        raise RuntimeError("the decision service cannot settle runner payments")


def _payment_required_header(*, resource_url: str, amount: str, recipient: str) -> str:
    atomic_amount = str(Decimal(amount) * Decimal("1000000"))
    payload: JsonObject = {
        "accepts": [
            {
                "amount": atomic_amount,
                "asset": X402_SOLANA_DEVNET_USDC_MINT,
                "extra": {"feePayer": "DemoFeePayer111111111111111111111111111111"},
                "maxTimeoutSeconds": 60,
                "network": X402_SOLANA_DEVNET_NETWORK,
                "payTo": recipient,
                "scheme": "exact",
            }
        ],
        "extensions": {},
        "resource": {
            "description": "Autonomous x402 resource",
            "mimeType": "application/json",
            "url": resource_url,
        },
        "x402Version": 2,
    }
    return base64.b64encode(canonical_json(payload).encode("utf-8")).decode("ascii")


def _validated_decision(result: AutonomousApiResult, *, request: PaymentRequest) -> Decision:
    if result.status is not HTTPStatus.OK:
        raise AutonomousRunError("decision API returned a non-success status")
    if result.payload.get("request_id") != request.request_id:
        raise AutonomousRunError("decision response request_id mismatch")
    if result.payload.get("request_digest") != request.digest:
        raise AutonomousRunError("decision response digest mismatch")
    value = result.payload.get("decision")
    if not isinstance(value, str):
        raise AutonomousRunError("decision response is invalid")
    try:
        return Decision(value)
    except ValueError as exc:
        raise AutonomousRunError("decision response is invalid") from exc


def _reason_codes(payload: Mapping[str, JsonValue]) -> tuple[ReasonCode, ...]:
    values = payload.get("reason_codes")
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
        raise AutonomousRunError("decision response reason_codes are invalid")
    try:
        return tuple(ReasonCode(cast(str, value)) for value in values)
    except ValueError as exc:
        raise AutonomousRunError("decision response contains an unknown reason code") from exc


def _authorization(payload: Mapping[str, JsonValue]) -> SigningAuthorization | None:
    value = payload.get("authorization")
    if value is None:
        return None
    if not isinstance(value, dict):
        raise AutonomousRunError("decision response authorization is invalid")
    try:
        return SigningAuthorization.from_dict(cast(Mapping[str, object], value))
    except ContractValidationError as exc:
        raise AutonomousRunError("decision response authorization is invalid") from exc


def run_deterministic_demo(*, now: datetime | None = None) -> AutonomousRunReport:
    """Execute the complete safe local demonstration."""

    runner, settlement = build_deterministic_runner(now=now)
    report = runner.run(deterministic_scenarios())
    if report.settlement_attempts != settlement.attempt_count:
        raise AutonomousRunError("settlement evidence does not match runner events")
    return report


def main(argv: Sequence[str] | None = None) -> int:
    """Run the headless demonstration and print one machine-readable report."""

    parser = argparse.ArgumentParser(description="Run the SolGuard autonomous security demo")
    parser.parse_args(argv)
    try:
        report = run_deterministic_demo()
    except (AutonomousRunError, ContractValidationError, ValueError) as exc:
        print(json.dumps({"error": str(exc), "security_invariants": "FAIL"}, sort_keys=True))
        return 1
    print(json.dumps(report.to_dict(), separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - module execution boundary
    raise SystemExit(main())
