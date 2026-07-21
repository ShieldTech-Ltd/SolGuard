"""Tests for the one-command deterministic SolGuard demonstration."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from decimal import Decimal
from typing import cast

import pytest

import solguard.demo as demo_module
from solguard.contracts import JsonValue
from solguard.dashboard import DemoRuntime
from solguard.demo import DemoReport, DemoValidationError, run_demo
from solguard.paysh import HttpResult, PayCommandOutput, PayShNetworkError
from tests.test_paysh import challenge_header

NOW = datetime(2026, 7, 25, 10, 0, tzinfo=UTC)


def checkpoints() -> dict[str, JsonValue]:
    return DemoRuntime(start_time=NOW).run_demo_sequence()


def successful_transport(endpoint: str, timeout: float) -> HttpResult:
    del endpoint, timeout
    return HttpResult(status=402, headers={"WWW-Authenticate": challenge_header()})


def successful_runner(arguments: object, timeout: float) -> PayCommandOutput:
    del arguments, timeout
    return PayCommandOutput(0, '{"symbol":"AAPL","price":"219.00"}', "private diagnostic")


def test_runtime_sequence_proves_attack_enforcement_and_recovery() -> None:
    result = checkpoints()
    baseline = cast(dict[str, JsonValue], result["baseline"])
    attack = cast(dict[str, JsonValue], result["attack"])
    recovery = cast(dict[str, JsonValue], result["recovery"])
    attack_events = cast(list[JsonValue], attack["events"])
    latest = cast(dict[str, JsonValue], attack_events[0])

    assert baseline["wallet_balance"] == attack["wallet_balance"]
    assert latest["decision"] == "BLOCK"
    assert latest["signing_state"] == "NOT_SIGNED"
    assert latest["settlement_reference"] is None
    assert recovery["decision_counts"] == {
        "allowed": 1,
        "blocked": 0,
        "require_approval": 0,
        "total": 1,
    }


def test_skip_external_demo_returns_runtime_derived_concise_report() -> None:
    ticks = iter((1_000_000, 6_000_000))

    report = run_demo(
        skip_paysh=True,
        start_time=NOW,
        timer_ns=lambda: next(ticks),
    )
    rendered = report.to_dict()
    local = cast(dict[str, JsonValue], rendered["local"])
    attack = cast(dict[str, JsonValue], local["attack"])

    assert rendered["status"] == "VERIFIED"
    assert rendered["duration_ms"] == "5"
    assert rendered["external"] == {
        "settlement_type": "PAYSH_SANDBOX",
        "status": "SKIPPED",
    }
    assert local["settlement_type"] == "SIMULATED"
    assert local["baseline_wallet_balance"] == local["attack_wallet_balance"]
    assert attack["decision"] == "BLOCK"
    assert attack["signing_state"] == "NOT_SIGNED"
    assert attack["settlement_reference"] is None
    assert "dashboard-demo-secret" not in json.dumps(rendered)


def test_external_demo_includes_real_adapter_settlement_summary() -> None:
    report = run_demo(
        start_time=NOW,
        transport=successful_transport,
        runner=successful_runner,
    )
    external = cast(dict[str, JsonValue], report.to_dict()["external"])

    assert external["status"] == "SETTLED"
    assert external["decision"] == "ALLOW"
    assert external["settlement_type"] == "PAYSH_SANDBOX"
    assert "private diagnostic" not in json.dumps(external)
    assert Decimal(report.duration_ms) < Decimal("120000")


def test_external_settlement_failure_preserves_verified_local_fallback() -> None:
    report = run_demo(
        start_time=NOW,
        transport=successful_transport,
        runner=lambda arguments, timeout: PayCommandOutput(1, "", "private failure"),
    )
    rendered = report.to_dict()
    external = cast(dict[str, JsonValue], rendered["external"])

    assert rendered["status"] == "VERIFIED"
    assert external["status"] == "SETTLEMENT_UNAVAILABLE"
    assert external["reason_codes"] == ["SETTLEMENT_UNAVAILABLE"]
    assert "private failure" not in json.dumps(rendered)


def test_external_probe_network_and_protocol_failures_are_labelled() -> None:
    def unavailable(endpoint: str, timeout: float) -> HttpResult:
        del endpoint, timeout
        raise PayShNetworkError("private network detail")

    network = run_demo(start_time=NOW, transport=unavailable)
    protocol = run_demo(
        start_time=NOW,
        transport=lambda endpoint, timeout: HttpResult(status=200, headers={}),
    )

    assert network.external == {
        "settlement_type": "PAYSH_SANDBOX",
        "stage": "CHALLENGE_PROBE",
        "status": "NETWORK_FAILURE",
    }
    assert protocol.external == {
        "settlement_type": "PAYSH_SANDBOX",
        "stage": "CHALLENGE_PROBE",
        "status": "PROTOCOL_FAILURE",
    }


def test_negative_timer_delta_is_clamped_to_zero() -> None:
    ticks = iter((2_000_000, 1_000_000))

    report = run_demo(skip_paysh=True, start_time=NOW, timer_ns=lambda: next(ticks))

    assert report.duration_ms == "0"


def test_validation_rejects_incomplete_checkpoints() -> None:
    with pytest.raises(DemoValidationError, match="incomplete"):
        demo_module._validate_and_summarize({})


def test_validation_rejects_non_object_checkpoint() -> None:
    data = checkpoints()
    data["initial"] = "invalid"

    with pytest.raises(DemoValidationError, match="incomplete"):
        demo_module._validate_and_summarize(data)


@pytest.mark.parametrize("invalid", ["invalid", {"allowed": True}])
def test_validation_rejects_invalid_decision_counts(invalid: JsonValue) -> None:
    data = checkpoints()
    baseline = cast(dict[str, JsonValue], data["baseline"])
    baseline["decision_counts"] = invalid

    with pytest.raises(DemoValidationError, match="incomplete"):
        demo_module._validate_and_summarize(data)


def test_validation_rejects_invalid_event_collection_or_item() -> None:
    data = checkpoints()
    attack = cast(dict[str, JsonValue], data["attack"])
    attack["events"] = "invalid"
    with pytest.raises(DemoValidationError, match="incomplete"):
        demo_module._validate_and_summarize(data)

    data = checkpoints()
    attack = cast(dict[str, JsonValue], data["attack"])
    attack["events"] = ["invalid"]
    with pytest.raises(DemoValidationError, match="incomplete"):
        demo_module._validate_and_summarize(data)


def test_validation_rejects_non_clean_baseline() -> None:
    data = checkpoints()
    baseline = cast(dict[str, JsonValue], data["baseline"])
    counts = cast(dict[str, JsonValue], baseline["decision_counts"])
    counts["allowed"] = 0

    with pytest.raises(DemoValidationError, match="baseline"):
        demo_module._validate_and_summarize(data)


def test_validation_requires_attack_block_and_additional_attempts() -> None:
    data = checkpoints()
    attack = cast(dict[str, JsonValue], data["attack"])
    counts = cast(dict[str, JsonValue], attack["decision_counts"])
    counts["blocked"] = 0
    with pytest.raises(DemoValidationError, match="block"):
        demo_module._validate_and_summarize(data)

    data = checkpoints()
    baseline = cast(dict[str, JsonValue], data["baseline"])
    attack = cast(dict[str, JsonValue], data["attack"])
    attack["decision_counts"] = copy.deepcopy(baseline["decision_counts"])
    attack_counts = cast(dict[str, JsonValue], attack["decision_counts"])
    attack_counts["blocked"] = 1
    with pytest.raises(DemoValidationError, match="additional"):
        demo_module._validate_and_summarize(data)


def test_validation_requires_unchanged_attack_balance_and_no_signature() -> None:
    data = checkpoints()
    attack = cast(dict[str, JsonValue], data["attack"])
    attack["wallet_balance"] = "0"
    with pytest.raises(DemoValidationError, match="wallet balance"):
        demo_module._validate_and_summarize(data)

    data = checkpoints()
    attack = cast(dict[str, JsonValue], data["attack"])
    events = cast(list[JsonValue], attack["events"])
    latest = cast(dict[str, JsonValue], events[0])
    latest["signing_state"] = "SIGNED_SIMULATED"
    with pytest.raises(DemoValidationError, match="before signing"):
        demo_module._validate_and_summarize(data)


def test_validation_requires_clean_recovery() -> None:
    data = checkpoints()
    recovery = cast(dict[str, JsonValue], data["recovery"])
    counts = cast(dict[str, JsonValue], recovery["decision_counts"])
    counts["allowed"] = 0

    with pytest.raises(DemoValidationError, match="recovery"):
        demo_module._validate_and_summarize(data)


def test_cli_prints_verified_report(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = DemoReport(
        duration_ms="1",
        external={"status": "SKIPPED"},
        local={"settlement_type": "SIMULATED"},
    )
    monkeypatch.setattr(demo_module, "run_demo", lambda **kwargs: report)

    assert demo_module.main(["--skip-paysh"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "VERIFIED"


def test_cli_reports_local_validation_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(**kwargs: object) -> DemoReport:
        raise DemoValidationError("failed")

    monkeypatch.setattr(demo_module, "run_demo", fail)

    assert demo_module.main([]) == 2
    assert json.loads(capsys.readouterr().out) == {"status": "LOCAL_DEMO_FAILED"}
