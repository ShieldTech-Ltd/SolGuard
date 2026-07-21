"""Explainable behavioural detection for autonomous-agent payments."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from types import MappingProxyType

from solguard.contracts import JsonValue, PaymentRequest, ReasonCode, format_amount


class DetectionSignal(StrEnum):
    """Internal detection severity before gateway decision mapping."""

    CLEAN = "CLEAN"
    FLAG = "FLAG"
    BLOCK = "BLOCK"


@dataclass(frozen=True, slots=True)
class DetectionResult:
    """Explainable output from all four behavioural rules."""

    signal: DetectionSignal
    reason_codes: tuple[ReasonCode, ...]
    evidence: Mapping[str, JsonValue]


@dataclass(slots=True)
class _CleanBaseline:
    amounts: list[Decimal]
    recipients: set[str]


class BehaviourEngine:
    """Run the four fixed SolGuard detection rules against each payment attempt."""

    VELOCITY_THRESHOLD = 5
    VELOCITY_WINDOW = timedelta(seconds=10)
    AMOUNT_WARMUP = 3
    AMOUNT_BLOCK_MULTIPLIER = Decimal("8")
    DRAIN_AMOUNT_MULTIPLIER = Decimal("2")

    def __init__(self) -> None:
        self._attempts: dict[str, deque[datetime]] = defaultdict(deque)
        self._baselines: dict[str, _CleanBaseline] = {}

    def evaluate(self, request: PaymentRequest, *, observed_at: datetime) -> DetectionResult:
        """Record one attempt and evaluate velocity, amount, novelty, and drain rules."""

        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")

        velocity_count = self._record_attempt(request.agent_id, observed_at)
        high_velocity = velocity_count >= self.VELOCITY_THRESHOLD
        baseline = self._baselines.get(request.agent_id)
        baseline_count = len(baseline.amounts) if baseline is not None else 0
        average = self._average(baseline.amounts) if baseline is not None else None

        if baseline is None or not baseline.recipients:
            recipient_state = "NO_HISTORY"
            new_recipient = False
        elif request.recipient in baseline.recipients:
            recipient_state = "KNOWN"
            new_recipient = False
        else:
            recipient_state = "FIRST_SEEN"
            new_recipient = True

        amount_multiple = request.amount / average if average is not None else None
        amount_anomaly = (
            baseline_count >= self.AMOUNT_WARMUP
            and amount_multiple is not None
            and amount_multiple > self.AMOUNT_BLOCK_MULTIPLIER
        )
        drain_pattern = (
            new_recipient
            and high_velocity
            and amount_multiple is not None
            and amount_multiple > self.DRAIN_AMOUNT_MULTIPLIER
        )

        reasons: list[ReasonCode] = []
        triggered_rules: list[JsonValue] = []
        if high_velocity:
            reasons.append(ReasonCode.DETECTION_VELOCITY)
            triggered_rules.append("VELOCITY")
        if amount_anomaly:
            reasons.append(ReasonCode.DETECTION_AMOUNT_ANOMALY)
            triggered_rules.append("AMOUNT_ANOMALY")
        if new_recipient:
            reasons.append(ReasonCode.DETECTION_RECIPIENT_NOVEL)
            triggered_rules.append("RECIPIENT_NOVELTY")
        if drain_pattern:
            reasons.append(ReasonCode.DETECTION_COMPOUND_DRAIN)
            triggered_rules.append("DRAIN_COMBINATION")

        if amount_anomaly or drain_pattern:
            signal = DetectionSignal.BLOCK
        elif high_velocity or new_recipient:
            signal = DetectionSignal.FLAG
        else:
            signal = DetectionSignal.CLEAN

        evidence: dict[str, JsonValue] = {
            "amount_multiple": (
                format_amount(amount_multiple) if amount_multiple is not None else None
            ),
            "baseline_average": format_amount(average) if average is not None else None,
            "baseline_count": baseline_count,
            "recipient_state": recipient_state,
            "triggered_rules": triggered_rules,
            "velocity_count": velocity_count,
            "velocity_window_seconds": int(self.VELOCITY_WINDOW.total_seconds()),
        }
        return DetectionResult(
            signal=signal,
            reason_codes=tuple(reasons),
            evidence=MappingProxyType(evidence),
        )

    def record_allowed(self, request: PaymentRequest) -> None:
        """Update clean state only after the gateway has allowed a payment."""

        baseline = self._baselines.setdefault(
            request.agent_id, _CleanBaseline(amounts=[], recipients=set())
        )
        baseline.amounts.append(request.amount)
        baseline.recipients.add(request.recipient)

    def _record_attempt(self, agent_id: str, observed_at: datetime) -> int:
        attempts = self._attempts[agent_id]
        cutoff = observed_at - self.VELOCITY_WINDOW
        while attempts and attempts[0] < cutoff:
            attempts.popleft()
        attempts.append(observed_at)
        return len(attempts)

    @staticmethod
    def _average(amounts: list[Decimal]) -> Decimal:
        return sum(amounts, start=Decimal("0")) / len(amounts)
