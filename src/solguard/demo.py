"""One-command deterministic security demonstration with optional Pay.sh settlement."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from time import perf_counter_ns
from typing import cast

from solguard.contracts import JsonValue, format_amount
from solguard.dashboard import DemoRuntime
from solguard.paysh import (
    PAYSH_SANDBOX_ENDPOINT,
    ChallengeTransport,
    PayCommandRunner,
    PayShNetworkError,
    PayShProtocolError,
    attempt_sandbox_purchase,
)


class DemoValidationError(RuntimeError):
    """Raised when a deterministic demo invariant is not actually observed."""


@dataclass(frozen=True, slots=True)
class DemoReport:
    """Safe runtime-derived report for one complete demonstration."""

    duration_ms: str
    external: Mapping[str, JsonValue]
    local: Mapping[str, JsonValue]

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "duration_ms": self.duration_ms,
            "external": dict(self.external),
            "local": dict(self.local),
            "status": "VERIFIED",
        }


def run_demo(
    *,
    endpoint: str = PAYSH_SANDBOX_ENDPOINT,
    pay_executable: str = "pay",
    skip_paysh: bool = False,
    start_time: datetime | None = None,
    timer_ns: Callable[[], int] | None = None,
    transport: ChallengeTransport | None = None,
    runner: PayCommandRunner | None = None,
) -> DemoReport:
    """Run optional external commerce followed by the reliable local security story."""

    timer = timer_ns if timer_ns is not None else perf_counter_ns
    started_ns = timer()
    external = _run_external(
        endpoint=endpoint,
        pay_executable=pay_executable,
        skip=skip_paysh,
        transport=transport,
        runner=runner,
    )
    runtime = DemoRuntime(start_time=start_time)
    checkpoints = runtime.run_demo_sequence()
    local = _validate_and_summarize(checkpoints)
    elapsed_ns = max(0, timer() - started_ns)
    return DemoReport(
        duration_ms=format_amount(Decimal(elapsed_ns) / Decimal("1000000")),
        external=external,
        local=local,
    )


def _run_external(
    *,
    endpoint: str,
    pay_executable: str,
    skip: bool,
    transport: ChallengeTransport | None,
    runner: PayCommandRunner | None,
) -> dict[str, JsonValue]:
    if skip:
        return {"settlement_type": "PAYSH_SANDBOX", "status": "SKIPPED"}
    try:
        attempt = attempt_sandbox_purchase(
            endpoint=endpoint,
            pay_executable=pay_executable,
            transport=transport,
            runner=runner,
        )
    except PayShNetworkError:
        return {
            "settlement_type": "PAYSH_SANDBOX",
            "stage": "CHALLENGE_PROBE",
            "status": "NETWORK_FAILURE",
        }
    except PayShProtocolError:
        return {
            "settlement_type": "PAYSH_SANDBOX",
            "stage": "CHALLENGE_PROBE",
            "status": "PROTOCOL_FAILURE",
        }
    return {"settlement_type": "PAYSH_SANDBOX", **attempt.to_dict()}


def _validate_and_summarize(checkpoints: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    try:
        initial = _snapshot(checkpoints, "initial")
        baseline = _snapshot(checkpoints, "baseline")
        attack = _snapshot(checkpoints, "attack")
        recovery = _snapshot(checkpoints, "recovery")
        baseline_counts = _counts(baseline)
        attack_counts = _counts(attack)
        recovery_counts = _counts(recovery)
        latest_attack = _event(_events(attack)[0])
    except (IndexError, KeyError, TypeError, ValueError) as exc:
        raise DemoValidationError("demo checkpoints are incomplete") from exc

    if baseline_counts["total"] < 1 or baseline_counts["allowed"] != baseline_counts["total"]:
        raise DemoValidationError("baseline did not contain only allowed payments")
    if attack_counts["blocked"] < 1:
        raise DemoValidationError("attack did not produce a block")
    if attack_counts["total"] <= baseline_counts["total"]:
        raise DemoValidationError("attack produced no additional requests")
    if baseline["wallet_balance"] != attack["wallet_balance"]:
        raise DemoValidationError("blocked attack changed the wallet balance")
    if (
        latest_attack.get("decision") != "BLOCK"
        or latest_attack.get("signing_state") != "NOT_SIGNED"
        or latest_attack.get("settlement_reference") is not None
    ):
        raise DemoValidationError("latest attack was not stopped before signing")
    expected_recovery = {"allowed": 1, "blocked": 0, "require_approval": 0, "total": 1}
    if recovery_counts != expected_recovery:
        raise DemoValidationError("recovery payment did not complete cleanly")

    return {
        "attack": {
            "decision": latest_attack["decision"],
            "reason_codes": latest_attack["reason_codes"],
            "settlement_reference": latest_attack["settlement_reference"],
            "signing_state": latest_attack["signing_state"],
        },
        "attack_attempts": attack_counts["total"] - baseline_counts["total"],
        "attack_decisions": cast(JsonValue, attack_counts),
        "attack_wallet_balance": attack["wallet_balance"],
        "baseline_decisions": cast(JsonValue, baseline_counts),
        "baseline_wallet_balance": baseline["wallet_balance"],
        "initial_wallet_balance": initial["wallet_balance"],
        "recovery_decisions": cast(JsonValue, recovery_counts),
        "recovery_wallet_balance": recovery["wallet_balance"],
        "settlement_type": "SIMULATED",
        "value_protected": attack["value_protected"],
    }


def _snapshot(checkpoints: Mapping[str, JsonValue], name: str) -> dict[str, JsonValue]:
    value = checkpoints[name]
    if not isinstance(value, dict):
        raise TypeError("checkpoint must be an object")
    return value


def _counts(snapshot: Mapping[str, JsonValue]) -> dict[str, int]:
    value = snapshot["decision_counts"]
    if not isinstance(value, dict) or any(
        not isinstance(item, int) or isinstance(item, bool) for item in value.values()
    ):
        raise TypeError("decision counts must contain integers")
    return cast(dict[str, int], value)


def _events(snapshot: Mapping[str, JsonValue]) -> list[JsonValue]:
    value = snapshot["events"]
    if not isinstance(value, list):
        raise TypeError("events must be an array")
    return value


def _event(value: JsonValue) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise TypeError("event must be an object")
    return value


def main(arguments: Sequence[str] | None = None) -> int:
    """Run the complete concise demo and emit one JSON evidence object."""

    parser = argparse.ArgumentParser(description="Run the complete SolGuard security demo")
    parser.add_argument("--endpoint", default=PAYSH_SANDBOX_ENDPOINT)
    parser.add_argument(
        "--pay-executable",
        default=os.environ.get("SOLGUARD_PAY_EXECUTABLE", "pay"),
    )
    parser.add_argument("--skip-paysh", action="store_true")
    parsed = parser.parse_args(arguments)
    try:
        report = run_demo(
            endpoint=parsed.endpoint,
            pay_executable=parsed.pay_executable,
            skip_paysh=parsed.skip_paysh,
        )
    except DemoValidationError:
        print(json.dumps({"status": "LOCAL_DEMO_FAILED"}))
        return 2
    print(json.dumps(report.to_dict(), separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through the console entry point
    raise SystemExit(main())
