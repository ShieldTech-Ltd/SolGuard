"""Tests for the deterministic autonomous x402 security runner."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from http import HTTPStatus
from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import solguard.autonomous_runner as runner_module
from solguard.authorization import WalletAuthorizationGuard
from solguard.autonomous_api import AutonomousApiResult
from solguard.autonomous_runner import (
    ATTACKER_RECIPIENT,
    DEMO_AGENT_ID,
    DEMO_KEY_ID,
    AutonomousPaymentRunner,
    AutonomousRunError,
    AutonomousRunReport,
    DeterministicPaidResourceClient,
    RuntimeEvent,
    Scenario,
    build_deterministic_runner,
    deterministic_scenarios,
    main,
    run_deterministic_demo,
)
from solguard.contracts import (
    ContractValidationError,
    Decision,
    JsonValue,
    PaymentRequest,
    ReasonCode,
    SigningAuthorization,
)
from solguard.settlement import SettlementResult
from solguard.simulation import SimulatedSettlement
from solguard.x402 import parse_payment_required_response

NOW = datetime(2026, 7, 25, 10, 0, tzinfo=UTC)
RESOURCE_URL = "https://attacker.invalid/drain"


def test_complete_demo_is_headless_deterministic_and_fail_closed() -> None:
    observed: list[RuntimeEvent] = []
    runner, settlement = build_deterministic_runner(now=NOW, observer=observed.append)

    report = runner.run(deterministic_scenarios())

    assert report.settlement_count == 3
    assert report.settlement_attempts == 3
    assert report.quarantined_count == 1
    assert report.blocked_count == 2
    assert settlement.attempt_count == 3
    assert settlement.balances[DEMO_AGENT_ID] == Decimal("999970")
    assert observed == list(report.events)
    assert [event.sequence for event in report.events] == list(range(1, 19))
    assert [
        (event.scenario, event.event_type, event.payload.get("signer_called"))
        for event in report.events
        if event.event_type in {"QUARANTINED", "BLOCKED"}
    ] == [
        ("first-seen-recipient", "QUARANTINED", False),
        ("replay-attack", "BLOCKED", False),
        ("compound-drain", "BLOCKED", False),
    ]
    assert report.to_dict()["security_invariants"] == "PASS"
    assert report.to_dict()["mode"] == "DETERMINISTIC_SIMULATION"


def test_convenience_demo_verifies_settlement_evidence() -> None:
    report = run_deterministic_demo(now=NOW)

    assert report.settlement_attempts == 3


def test_runner_rejects_empty_or_duplicate_scenarios() -> None:
    runner, _ = build_deterministic_runner(now=NOW)
    duplicate = Scenario("same", RESOURCE_URL, "one", Decision.BLOCK)

    with pytest.raises(AutonomousRunError, match="unique names"):
        runner.run(())
    with pytest.raises(AutonomousRunError, match="unique names"):
        runner.run((duplicate, duplicate))


def test_runner_rejects_replay_before_original() -> None:
    runner, _ = build_deterministic_runner(now=NOW)
    scenario = Scenario(
        "replay",
        RESOURCE_URL,
        "replay",
        Decision.BLOCK,
        replay_of="missing",
    )

    with pytest.raises(AutonomousRunError, match="replay target"):
        runner.run((scenario,))


def test_paid_resource_client_rejects_unknown_resource() -> None:
    client = DeterministicPaidResourceClient({})

    with pytest.raises(AutonomousRunError, match="not configured"):
        client.request(RESOURCE_URL)


@pytest.mark.parametrize("failure", [OSError("offline"), RuntimeError("bad protocol")])
def test_resource_or_protocol_failure_stops_safely(failure: Exception) -> None:
    class FailingResource:
        def request(self, resource_url: str) -> runner_module.ResourceResponse:
            del resource_url
            raise failure

    runner = _single_scenario_runner(resource_client=FailingResource())

    with pytest.raises(AutonomousRunError, match="paid resource protocol failed"):
        runner.run((_single_scenario(),))


def test_decision_api_failure_stops_safely() -> None:
    class FailingDecision:
        def evaluate(
            self,
            request: PaymentRequest,
            *,
            key_id: str,
            signature: str,
        ) -> AutonomousApiResult:
            del request, key_id, signature
            raise OSError("offline")

    runner = _single_scenario_runner(decision_client=FailingDecision())

    with pytest.raises(AutonomousRunError, match="decision API failed"):
        runner.run((_single_scenario(),))


def test_settlement_failure_stops_without_recording_clean_baseline() -> None:
    class FailingSettlement:
        def settle(
            self,
            request: PaymentRequest,
            authorization: SigningAuthorization | None,
        ) -> SettlementResult:
            del request, authorization
            raise OSError("wallet offline")

    recorder = RecordingBaseline()
    runner = _single_scenario_runner(
        decision_client=ResponseClient(Decision.ALLOW, include_authorization=True),
        settlement=FailingSettlement(),
        recorder=recorder,
    )

    with pytest.raises(AutonomousRunError, match="settlement boundary failed"):
        runner.run((_single_scenario(expected=Decision.ALLOW),))
    assert recorder.requests == []


def test_unexpected_decision_or_reason_fails_the_run() -> None:
    runner = _single_scenario_runner(decision_client=ResponseClient(Decision.BLOCK))

    with pytest.raises(AutonomousRunError, match="unexpected decision"):
        runner.run((_single_scenario(expected=Decision.ALLOW),))

    runner = _single_scenario_runner(
        decision_client=ResponseClient(
            Decision.BLOCK,
            reasons=(ReasonCode.POLICY_AMOUNT_LIMIT,),
        )
    )
    scenario = _single_scenario(
        expected=Decision.BLOCK,
        expected_reason=ReasonCode.DETECTION_COMPOUND_DRAIN,
    )
    with pytest.raises(AutonomousRunError, match="unexpected decision"):
        runner.run((scenario,))


def test_allow_requires_authorization_and_non_allow_must_not_have_one() -> None:
    missing = _single_scenario_runner(decision_client=ResponseClient(Decision.ALLOW))
    with pytest.raises(AutonomousRunError, match="omitted authorization"):
        missing.run((_single_scenario(expected=Decision.ALLOW),))

    exposed = _single_scenario_runner(
        decision_client=ResponseClient(Decision.BLOCK, include_authorization=True)
    )
    with pytest.raises(AutonomousRunError, match="exposed an authorization"):
        exposed.run((_single_scenario(expected=Decision.BLOCK),))


def test_decision_response_must_be_bound_and_well_formed() -> None:
    request = _request_for_validation()
    valid = _payload(request, Decision.BLOCK)

    with pytest.raises(AutonomousRunError, match="non-success"):
        runner_module._validated_decision(
            AutonomousApiResult(HTTPStatus.UNAUTHORIZED, valid), request=request
        )
    with pytest.raises(AutonomousRunError, match="request_id mismatch"):
        runner_module._validated_decision(
            AutonomousApiResult(HTTPStatus.OK, {**valid, "request_id": "other"}),
            request=request,
        )
    with pytest.raises(AutonomousRunError, match="digest mismatch"):
        runner_module._validated_decision(
            AutonomousApiResult(HTTPStatus.OK, {**valid, "request_digest": "sha256:other"}),
            request=request,
        )
    for value in (7, "UNKNOWN"):
        with pytest.raises(AutonomousRunError, match="decision response is invalid"):
            runner_module._validated_decision(
                AutonomousApiResult(HTTPStatus.OK, {**valid, "decision": value}),
                request=request,
            )


def test_reason_code_response_validation_is_strict() -> None:
    with pytest.raises(AutonomousRunError, match="reason_codes are invalid"):
        runner_module._reason_codes({"reason_codes": "BLOCK"})
    with pytest.raises(AutonomousRunError, match="reason_codes are invalid"):
        runner_module._reason_codes({"reason_codes": [3]})
    with pytest.raises(AutonomousRunError, match="unknown reason code"):
        runner_module._reason_codes({"reason_codes": ["UNKNOWN"]})


def test_authorization_response_validation_is_strict() -> None:
    assert runner_module._authorization({"authorization": None}) is None
    with pytest.raises(AutonomousRunError, match="authorization is invalid"):
        runner_module._authorization({"authorization": "invalid"})
    with pytest.raises(AutonomousRunError, match="authorization is invalid"):
        runner_module._authorization({"authorization": {"authorization_id": "partial"}})


def test_signing_authorization_round_trip_and_expiry_order_validation() -> None:
    authorization = _authorization_for(_request_for_validation())

    assert (
        SigningAuthorization.from_dict(cast(Mapping[str, object], authorization.to_dict()))
        == authorization
    )
    invalid = authorization.to_dict()
    invalid["expires_at"] = invalid["issued_at"]
    with pytest.raises(ContractValidationError, match="must be later"):
        SigningAuthorization.from_dict(cast(Mapping[str, object], invalid))


def test_build_runner_rejects_naive_time() -> None:
    with pytest.raises(ValueError, match="timezone"):
        build_deterministic_runner(now=datetime(2026, 7, 25, 10, 0))


def test_forbidden_decision_settlement_is_never_a_wallet_path() -> None:
    with pytest.raises(RuntimeError, match="cannot settle"):
        runner_module._ForbiddenRunnerSettlement().settle(_request_for_validation(), None)


def test_run_demo_detects_evidence_count_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeRunner:
        def run(self, scenarios: object) -> AutonomousRunReport:
            del scenarios
            return AutonomousRunReport((), 1, 1, 0, 0)

    class Evidence:
        attempt_count = 0

    monkeypatch.setattr(
        runner_module,
        "build_deterministic_runner",
        lambda now=None: (FakeRunner(), Evidence()),
    )

    with pytest.raises(AutonomousRunError, match="evidence does not match"):
        run_deterministic_demo(now=NOW)


def test_cli_outputs_json_and_returns_nonzero_on_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        runner_module,
        "run_deterministic_demo",
        lambda: AutonomousRunReport((), 0, 0, 0, 0),
    )
    assert main([]) == 0
    assert '"security_invariants":"PASS"' in capsys.readouterr().out

    def fail() -> AutonomousRunReport:
        raise AutonomousRunError("stopped safely")

    monkeypatch.setattr(runner_module, "run_deterministic_demo", fail)
    assert main([]) == 1
    assert '"security_invariants": "FAIL"' in capsys.readouterr().out


class RecordingBaseline:
    def __init__(self) -> None:
        self.requests: list[PaymentRequest] = []

    def record_allowed(self, request: PaymentRequest) -> None:
        self.requests.append(request)


class ResponseClient:
    def __init__(
        self,
        decision: Decision,
        *,
        reasons: tuple[ReasonCode, ...] = (),
        include_authorization: bool = False,
    ) -> None:
        self._decision = decision
        self._reasons = reasons
        self._include_authorization = include_authorization

    def evaluate(
        self,
        request: PaymentRequest,
        *,
        key_id: str,
        signature: str,
    ) -> AutonomousApiResult:
        assert key_id == DEMO_KEY_ID
        assert signature
        payload = _payload(request, self._decision, reasons=self._reasons)
        if self._include_authorization:
            payload["authorization"] = _authorization_for(request).to_dict()
        return AutonomousApiResult(HTTPStatus.OK, payload)


def _single_scenario_runner(
    *,
    resource_client: object | None = None,
    decision_client: object | None = None,
    settlement: object | None = None,
    recorder: RecordingBaseline | None = None,
) -> AutonomousPaymentRunner:
    resource = resource_client or DeterministicPaidResourceClient(
        {RESOURCE_URL: ("20", ATTACKER_RECIPIENT)}
    )
    boundary = settlement or SimulatedSettlement(
        {DEMO_AGENT_ID: Decimal("100")},
        authorization_guard=WalletAuthorizationGuard(clock=lambda: NOW),
    )
    return AutonomousPaymentRunner(
        resource_client=cast(runner_module.PaidResourceClient, resource),
        decision_client=cast(
            runner_module.DecisionApiClient,
            decision_client or ResponseClient(Decision.BLOCK),
        ),
        settlement=cast(runner_module.SettlementBoundary, boundary),
        recorder=recorder or RecordingBaseline(),
        private_key=Ed25519PrivateKey.generate(),
        key_id=DEMO_KEY_ID,
        clock=lambda: NOW,
    )


def _single_scenario(
    *,
    expected: Decision = Decision.BLOCK,
    expected_reason: ReasonCode | None = None,
) -> Scenario:
    return Scenario(
        "single",
        RESOURCE_URL,
        "single",
        expected,
        expected_reason,
    )


def _request_for_validation() -> PaymentRequest:
    resource = DeterministicPaidResourceClient({RESOURCE_URL: ("20", ATTACKER_RECIPIENT)})
    response = resource.request(RESOURCE_URL)
    requirement = parse_payment_required_response(
        status=response.status,
        headers=response.headers,
    )
    return requirement.to_payment_request(
        agent_id=DEMO_AGENT_ID,
        mandate_id=runner_module.DEMO_MANDATE_ID,
        attempt_id="validation",
        observed_at=NOW,
    )


def _authorization_for(request: PaymentRequest) -> SigningAuthorization:
    return SigningAuthorization(
        authorization_id="auth_test",
        request_id=request.request_id,
        request_digest=request.digest,
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )


def _payload(
    request: PaymentRequest,
    decision: Decision,
    *,
    reasons: tuple[ReasonCode, ...] = (),
) -> dict[str, JsonValue]:
    return {
        "api_version": "1",
        "audit_receipt_digest": None,
        "authorization": None,
        "decision": decision.value,
        "evidence": {},
        "execution_state": "BLOCKED",
        "reason_codes": [reason.value for reason in reasons],
        "request_digest": request.digest,
        "request_id": request.request_id,
    }
