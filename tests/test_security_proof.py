"""Tests for the problem-first autonomous attack resistance proof."""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import replace
from decimal import Decimal
from http import HTTPStatus
from types import MappingProxyType
from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import solguard.security_proof as proof_module
from solguard.agent_auth import sign_agent_request
from solguard.autonomous_api import AutonomousApiResult, AutonomousDecisionService
from solguard.contracts import Decision, JsonValue, ReasonCode, SigningAuthorization
from solguard.devnet_rpc import SolanaDevnetConfirmer
from solguard.policy import PolicyResult
from solguard.security_proof import (
    INITIAL_SIMULATED_BALANCE,
    ProofInvariantError,
    build_proof_scenarios,
    main,
    run_security_proof,
)
from solguard.wallet_signer import (
    IsolatedSolanaWalletSigner,
    WalletSigningReceipt,
    WalletSigningRejected,
)
from solguard_demo_reference import UnsafeReferenceWallet
from solguard_demo_reference.unsafe_wallet import UnsafeReferenceFailure


def test_complete_problem_first_proof_uses_identical_attack_fixture() -> None:
    report = run_security_proof()
    comparison = cast(dict[str, JsonValue], report["comparison"])
    protected = _items(report, "protected_act")
    unsafe = _items(report, "unsafe_problem_act")
    probes = _items(report, "failure_and_wallet_probes")

    assert report["security_invariants"] == "PASS"
    assert report["mode"] == "OFFLINE_CRYPTOGRAPHIC_AND_LEDGER_SIMULATION"
    assert report["real_devnet_evidence"] == "NOT_EXECUTED_CREDENTIALS_REQUIRED"
    assert comparison == {
        "attack_request_digest": _scenario(protected, "exact-2x-compound-drain")["request_digest"],
        "protected_balance_unchanged": True,
        "protected_signer_invoked": False,
        "same_canonical_attack_fixture": True,
        "unsafe_balance_decreased": True,
        "unsafe_reference_signed": True,
    }
    assert (
        _scenario(unsafe, "exact-2x-compound-drain")["request_digest"]
        == comparison["attack_request_digest"]
    )
    assert _scenario(protected, "first-seen-recipient")["decision"] == "REQUIRE_APPROVAL"
    assert _scenario(protected, "velocity-only")["reason_codes"] == [
        ReasonCode.DETECTION_VELOCITY.value
    ]
    assert ReasonCode.DETECTION_AMOUNT_ANOMALY.value in cast(
        list[str], _scenario(protected, "exact-8x-amount-anomaly")["reason_codes"]
    )
    assert ReasonCode.DETECTION_COMPOUND_DRAIN.value in cast(
        list[str], _scenario(protected, "exact-2x-compound-drain")["reason_codes"]
    )
    assert _scenario(protected, "safe-recovery")["decision"] == Decision.ALLOW.value
    assert _scenario(protected, "safe-recovery")["wallet_signer_invoked"] is True
    assert all(probe["status"] == "PASS" for probe in probes)
    assert all(probe["transaction_signature"] is None for probe in probes)


def test_fixture_boundaries_are_exact_and_replay_is_same_object() -> None:
    scenarios = build_proof_scenarios()
    by_name = {scenario.name: scenario for scenario in scenarios}

    assert by_name["exact-8x-amount-anomaly"].request.amount == Decimal("80")
    assert by_name["exact-2x-compound-drain"].request.amount == Decimal("20")
    assert by_name["replayed-request"].request is by_name["normal-1"].request
    assert by_name["safe-recovery"].request.created_at > by_name["normal-1"].request.created_at


def test_cli_succeeds_and_reports_safe_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        proof_module,
        "run_security_proof",
        lambda: {"security_invariants": "PASS"},
    )
    assert main([]) == 0
    assert json.loads(capsys.readouterr().out)["security_invariants"] == "PASS"

    def fail() -> dict[str, JsonValue]:
        raise ProofInvariantError("private detail not emitted")

    monkeypatch.setattr(proof_module, "run_security_proof", fail)
    assert main([]) == 1
    failure = json.loads(capsys.readouterr().out)
    assert failure == {
        "error_type": "ProofInvariantError",
        "security_invariants": "FAIL",
    }


def test_three_consecutive_clean_processes_observe_expected_decisions() -> None:
    for _ in range(3):
        completed = subprocess.run(
            [sys.executable, "-m", "solguard.security_proof"],
            check=True,
            capture_output=True,
            text=True,
        )
        report = json.loads(completed.stdout)
        protected = _items(cast(dict[str, JsonValue], report), "protected_act")
        assert report["security_invariants"] == "PASS"
        assert _scenario(protected, "velocity-only")["decision"] == "REQUIRE_APPROVAL"
        assert _scenario(protected, "exact-8x-amount-anomaly")["decision"] == "BLOCK"
        assert _scenario(protected, "safe-recovery")["decision"] == "ALLOW"


def test_unsafe_reference_wallet_is_cryptographic_but_financially_unprotected() -> None:
    request = build_proof_scenarios()[6].request
    wallet = UnsafeReferenceWallet(
        private_key=Ed25519PrivateKey.generate(),
        balance=INITIAL_SIMULATED_BALANCE,
    )

    result = wallet.execute(request)

    assert result.signature
    assert result.request_digest == request.digest
    assert result.balance_after == INITIAL_SIMULATED_BALANCE - request.amount
    assert result.to_dict()["mode"] == "UNSAFE_OFFLINE_REFERENCE_SIMULATION"
    assert wallet.calls == 1
    assert wallet.balance == result.balance_after


def test_unsafe_reference_wallet_validates_configuration_and_balance() -> None:
    with pytest.raises(TypeError, match="private_key"):
        UnsafeReferenceWallet(
            private_key=cast(Ed25519PrivateKey, object()),
            balance=Decimal("1"),
        )
    with pytest.raises(ValueError, match="balance"):
        UnsafeReferenceWallet(
            private_key=Ed25519PrivateKey.generate(),
            balance=Decimal("-1"),
        )
    wallet = UnsafeReferenceWallet(
        private_key=Ed25519PrivateKey.generate(),
        balance=Decimal("1"),
    )
    with pytest.raises(UnsafeReferenceFailure, match="insufficient"):
        wallet.execute(build_proof_scenarios()[6].request)


def test_forbidden_decision_settlement_and_protected_balance_guard() -> None:
    scenario = build_proof_scenarios()[0]
    with pytest.raises(RuntimeError, match="cannot settle"):
        proof_module._ForbiddenDecisionSettlement().settle(scenario.request, None)

    context = proof_module._build_protected_context()
    context.clock.value = scenario.request.created_at
    response = context.service.evaluate(
        scenario.request.to_dict(),
        key_id=proof_module.PROOF_KEY_ID,
        signature=sign_agent_request(
            scenario.request,
            key_id=proof_module.PROOF_KEY_ID,
            private_key=context.agent_signer,
        ),
    )
    raw = response.payload["authorization"]
    assert isinstance(raw, dict)
    authorization = SigningAuthorization.from_dict(cast(dict[str, object], raw))
    context.boundary._balance = Decimal("0")
    with pytest.raises(ProofInvariantError, match="balance is insufficient"):
        context.boundary.settle(scenario.request, authorization)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"status": HTTPStatus.UNAUTHORIZED}, "authenticated decision API"),
        ({"decision": 7}, "decision API response"),
        ({"decision": "UNKNOWN"}, "decision API response"),
        ({"reason_codes": "bad"}, "decision reason codes"),
        ({"authorization": "bad"}, "decision authorization"),
        ({"authorization": None}, "ALLOW omitted authorization"),
    ],
)
def test_protected_runner_rejects_malformed_api_evidence(
    mutation: dict[str, object], message: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    scenario = build_proof_scenarios()[0]
    context = proof_module._build_protected_context()
    original = context.service

    class MutatingService:
        def evaluate(self, *args: object, **kwargs: object) -> AutonomousApiResult:
            result = original.evaluate(*args, **kwargs)  # type: ignore[arg-type]
            status = cast(HTTPStatus, mutation.get("status", result.status))
            payload = dict(result.payload)
            payload.update(cast(dict[str, JsonValue], mutation))
            payload.pop("status", None)
            return AutonomousApiResult(status, payload)

    context.service = cast(AutonomousDecisionService, MutatingService())
    monkeypatch.setattr(proof_module, "_build_protected_context", lambda: context)

    with pytest.raises(ProofInvariantError, match=message):
        proof_module._run_protected((scenario,))


def test_protected_runner_rejects_unexpected_decision_and_nonallow_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = build_proof_scenarios()[0]
    unexpected = replace(scenario, expected_decision=Decision.BLOCK)
    with pytest.raises(ProofInvariantError, match="unexpected protected decision"):
        proof_module._run_protected((unexpected,))

    context = proof_module._build_protected_context()
    original = context.service

    class BlockWithAuthorization:
        def evaluate(self, *args: object, **kwargs: object) -> AutonomousApiResult:
            result = original.evaluate(*args, **kwargs)  # type: ignore[arg-type]
            return AutonomousApiResult(
                result.status,
                {**result.payload, "decision": "BLOCK"},
            )

    context.service = cast(
        AutonomousDecisionService,
        BlockWithAuthorization(),
    )
    monkeypatch.setattr(proof_module, "_build_protected_context", lambda: context)
    expected_block = replace(scenario, expected_decision=Decision.BLOCK)
    with pytest.raises(ProofInvariantError, match="non-ALLOW included authorization"):
        proof_module._run_protected((expected_block,))


def test_protected_runner_detects_wallet_side_effect_on_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = replace(build_proof_scenarios()[0], expected_decision=Decision.BLOCK)
    context = proof_module._build_protected_context()
    original = context.service

    class MutatingBlockedService:
        def evaluate(self, *args: object, **kwargs: object) -> AutonomousApiResult:
            result = original.evaluate(*args, **kwargs)  # type: ignore[arg-type]
            context.boundary._balance -= Decimal("1")
            return AutonomousApiResult(
                result.status,
                {**result.payload, "authorization": None, "decision": "BLOCK"},
            )

    context.service = cast(
        AutonomousDecisionService,
        MutatingBlockedService(),
    )
    monkeypatch.setattr(proof_module, "_build_protected_context", lambda: context)

    with pytest.raises(ProofInvariantError, match="reached wallet"):
        proof_module._run_protected((scenario,))


def test_wallet_probe_detects_unexpected_success_or_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, context = proof_module._run_protected((build_proof_scenarios()[0],))
    monkeypatch.setattr(
        context.boundary._signer,
        "sign",
        lambda *_args: WalletSigningReceipt("w", "d", "a", "s"),
    )
    with pytest.raises(ProofInvariantError, match="unexpectedly signed"):
        proof_module._wallet_adversarial_probes(context)

    _, context = proof_module._run_protected((build_proof_scenarios()[0],))

    def wrong_reason(*_args: object) -> WalletSigningReceipt:
        raise WalletSigningRejected(ReasonCode.SYSTEM_FAILURE)

    monkeypatch.setattr(context.boundary._signer, "sign", wrong_reason)
    with pytest.raises(ProofInvariantError, match="wrong reason"):
        proof_module._wallet_adversarial_probes(context)


def test_failure_probe_self_checks_detect_broken_injections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = build_proof_scenarios()[0]
    monkeypatch.setattr(
        proof_module._FailingPolicy,
        "evaluate",
        lambda *_args: PolicyResult(Decision.ALLOW, (), MappingProxyType({})),
    )
    with pytest.raises(ProofInvariantError, match="decision failure"):
        proof_module._failure_probes(scenario)

    monkeypatch.undo()

    class DummySettlementResult:
        settlement_reference = "unexpected"

        def to_dict(self) -> dict[str, JsonValue]:
            return {"status": "unexpected"}

    monkeypatch.setattr(
        proof_module._FailingSettlement,
        "settle",
        lambda *_args: DummySettlementResult(),
    )
    with pytest.raises(ProofInvariantError, match="facilitator failure"):
        proof_module._failure_probes(scenario)


def test_failure_probe_detects_wrong_signer_and_rpc_outcomes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = build_proof_scenarios()[0]

    def wrong_signer(*_args: object, **_kwargs: object) -> WalletSigningReceipt:
        raise WalletSigningRejected(ReasonCode.AUTHORIZATION_MISMATCH)

    monkeypatch.setattr(IsolatedSolanaWalletSigner, "sign", wrong_signer)
    with pytest.raises(ProofInvariantError, match="signer failure returned wrong reason"):
        proof_module._failure_probes(scenario)

    monkeypatch.undo()
    monkeypatch.setattr(
        IsolatedSolanaWalletSigner,
        "sign",
        lambda *_args, **_kwargs: WalletSigningReceipt("w", "d", "a", "s"),
    )
    with pytest.raises(ProofInvariantError, match="unexpectedly returned a signature"):
        proof_module._failure_probes(scenario)

    monkeypatch.undo()
    monkeypatch.setattr(
        SolanaDevnetConfirmer,
        "confirm",
        lambda *_args, **_kwargs: cast(object, None),
    )
    with pytest.raises(ProofInvariantError, match="RPC failure unexpectedly"):
        proof_module._failure_probes(scenario)


@pytest.mark.parametrize(
    "failure_kind",
    ["digest", "primary", "blocked", "recovery"],
)
def test_top_level_proof_rejects_inconsistent_evidence(
    failure_kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    scenarios = build_proof_scenarios()
    unsafe = list(proof_module._run_unsafe(scenarios))
    protected_values, context = proof_module._run_protected(scenarios)
    protected = list(protected_values)
    primary = next(
        index for index, item in enumerate(unsafe) if item.scenario == "exact-2x-compound-drain"
    )
    if failure_kind == "digest":
        unsafe[primary] = replace(unsafe[primary], request=scenarios[0].request)
        message = "same attack request"
    elif failure_kind == "primary":
        unsafe[primary] = replace(unsafe[primary], offline_wallet_signature=None)
        message = "problem-first comparison"
    elif failure_kind == "blocked":
        index = next(
            index for index, item in enumerate(protected) if item.scenario == "velocity-only"
        )
        protected[index] = replace(protected[index], authorization_id="unexpected")
        message = "unsafe protected evidence"
    else:
        index = next(
            index for index, item in enumerate(protected) if item.scenario == "safe-recovery"
        )
        protected[index] = replace(protected[index], wallet_signer_invoked=False)
        message = "safe recovery"
    monkeypatch.setattr(proof_module, "_run_unsafe", lambda _scenarios: tuple(unsafe))
    monkeypatch.setattr(
        proof_module,
        "_run_protected",
        lambda _scenarios: (tuple(protected), context),
    )

    with pytest.raises(ProofInvariantError, match=message):
        run_security_proof()


def _items(report: dict[str, JsonValue], key: str) -> list[dict[str, JsonValue]]:
    return cast(list[dict[str, JsonValue]], report[key])


def _scenario(items: list[dict[str, JsonValue]], name: str) -> dict[str, JsonValue]:
    return next(item for item in items if item["scenario"] == name)
