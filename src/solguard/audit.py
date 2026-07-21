"""Tamper-evident audit receipts and a bounded local event stream."""

from __future__ import annotations

import hashlib
import json
import threading
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from decimal import Decimal
from types import MappingProxyType
from typing import cast

from solguard.contracts import (
    AgentMandate,
    Decision,
    JsonObject,
    JsonValue,
    PaymentRequest,
    canonical_json,
    format_amount,
    format_timestamp,
    parse_timestamp,
)
from solguard.gateway import GatewayOutcome
from solguard.privacy import SanitizedMetadata

AUDIT_SCHEMA_VERSION = "1.0"
AuditSubscriber = Callable[["AuditEvent"], None]
_AUDIT_PAYLOAD_FIELDS = frozenset(
    {
        "agent_id",
        "amount",
        "asset",
        "decision",
        "decision_evidence",
        "latency_ms",
        "observed_at",
        "policy_version",
        "reason_codes",
        "recipient",
        "request_digest",
        "request_id",
        "sanitized_metadata",
        "schema_version",
        "sequence",
        "settlement_reference",
        "signing_state",
        "traffic_type",
    }
)


def policy_digest(mandate: AgentMandate) -> str:
    """Return a deterministic version identifier for the active policy."""

    digest = hashlib.sha256(canonical_json(mandate.to_dict()).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def compute_receipt_digest(
    payload: Mapping[str, JsonValue], previous_receipt_digest: str | None
) -> str:
    """Compute the chained digest for one canonical audit payload."""

    material: dict[str, JsonValue] = {
        "payload": dict(payload),
        "previous_receipt_digest": previous_receipt_digest,
    }
    digest = hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Immutable canonical event with a chained tamper-evident digest."""

    _payload_json: str
    previous_receipt_digest: str | None
    receipt_digest: str

    @classmethod
    def create(
        cls,
        payload: Mapping[str, JsonValue],
        *,
        previous_receipt_digest: str | None,
    ) -> AuditEvent:
        """Create an immutable receipt from a validated event payload."""

        payload_json = canonical_json(dict(payload))
        stable_payload = cast(JsonObject, json.loads(payload_json))
        digest = compute_receipt_digest(stable_payload, previous_receipt_digest)
        return cls(
            _payload_json=payload_json,
            previous_receipt_digest=previous_receipt_digest,
            receipt_digest=digest,
        )

    @property
    def payload(self) -> Mapping[str, JsonValue]:
        """Return a fresh read-only top-level copy of the canonical payload."""

        return MappingProxyType(cast(JsonObject, json.loads(self._payload_json)))

    @property
    def sequence(self) -> int:
        return cast(int, self.payload["sequence"])

    @property
    def decision(self) -> Decision:
        return Decision(cast(str, self.payload["decision"]))

    @property
    def amount(self) -> Decimal:
        return Decimal(cast(str, self.payload["amount"]))

    @property
    def latency_ms(self) -> str:
        return cast(str, self.payload["latency_ms"])

    def to_dict(self) -> dict[str, JsonValue]:
        """Return the complete portable receipt."""

        return {
            **self.payload,
            "previous_receipt_digest": self.previous_receipt_digest,
            "receipt_digest": self.receipt_digest,
        }

    def dashboard_dict(self) -> dict[str, JsonValue]:
        """Return the safe event fields consumed by the browser dashboard."""

        payload = self.payload
        return {
            "agent_id": payload["agent_id"],
            "amount": payload["amount"],
            "asset": payload["asset"],
            "decision": payload["decision"],
            "latency_ms": payload["latency_ms"],
            "observed_at": payload["observed_at"],
            "reason_codes": payload["reason_codes"],
            "recipient": payload["recipient"],
            "receipt_digest": self.receipt_digest,
            "request_id": payload["request_id"],
            "sanitized_metadata": payload["sanitized_metadata"],
            "sequence": payload["sequence"],
            "settlement_reference": payload["settlement_reference"],
            "signing_state": payload["signing_state"],
            "traffic_type": payload["traffic_type"],
        }


class AuditEventStream:
    """Thread-safe ephemeral stream with bounded replay and receipt chaining."""

    def __init__(self, *, max_events: int = 50) -> None:
        if max_events < 1:
            raise ValueError("max_events must be positive")
        self._events: deque[AuditEvent] = deque(maxlen=max_events)
        self._subscribers: dict[int, AuditSubscriber] = {}
        self._next_subscriber_id = 0
        self._sequence = 0
        self._last_receipt_digest: str | None = None
        self._lock = threading.RLock()

    def publish(
        self,
        *,
        request: PaymentRequest,
        outcome: GatewayOutcome,
        mandate: AgentMandate,
        sanitized_metadata: SanitizedMetadata,
    ) -> AuditEvent:
        """Publish one sanitized event created exclusively from runtime results."""

        with self._lock:
            self._sequence += 1
            payload = self._payload(
                sequence=self._sequence,
                request=request,
                outcome=outcome,
                mandate=mandate,
                sanitized_metadata=sanitized_metadata,
            )
            event = AuditEvent.create(
                payload,
                previous_receipt_digest=self._last_receipt_digest,
            )
            self._last_receipt_digest = event.receipt_digest
            self._events.append(event)
            subscribers = tuple(self._subscribers.values())

        for subscriber in subscribers:
            try:
                subscriber(event)
            except Exception:
                # Observability consumers cannot change an already-made security decision.
                continue
        return event

    def subscribe(self, subscriber: AuditSubscriber, *, replay: bool = True) -> Callable[[], None]:
        """Subscribe to ordered events and return an idempotent unsubscribe callback."""

        with self._lock:
            subscriber_id = self._next_subscriber_id
            self._next_subscriber_id += 1
            self._subscribers[subscriber_id] = subscriber
            existing = tuple(self._events) if replay else ()
        for event in existing:
            try:
                subscriber(event)
            except Exception:
                continue

        def unsubscribe() -> None:
            with self._lock:
                self._subscribers.pop(subscriber_id, None)

        return unsubscribe

    def snapshot(self) -> tuple[AuditEvent, ...]:
        """Return retained events in publication order for local reconnects."""

        with self._lock:
            return tuple(self._events)

    @staticmethod
    def verify_receipt(event: AuditEvent) -> bool:
        """Verify one receipt against its immutable canonical payload."""

        expected = compute_receipt_digest(event.payload, event.previous_receipt_digest)
        return expected == event.receipt_digest

    @classmethod
    def verify_chain(cls, events: tuple[AuditEvent, ...]) -> bool:
        """Verify receipt integrity, ordering, and retained chain links."""

        for index, event in enumerate(events):
            if not cls.verify_receipt(event):
                return False
            if index > 0:
                previous = events[index - 1]
                if event.previous_receipt_digest != previous.receipt_digest:
                    return False
                if event.sequence != previous.sequence + 1:
                    return False
        return True

    @staticmethod
    def _payload(
        *,
        sequence: int,
        request: PaymentRequest,
        outcome: GatewayOutcome,
        mandate: AgentMandate,
        sanitized_metadata: SanitizedMetadata,
    ) -> dict[str, JsonValue]:
        settlement_reference = (
            outcome.settlement.settlement_reference if outcome.settlement is not None else None
        )
        return {
            "agent_id": request.agent_id,
            "amount": format_amount(request.amount),
            "asset": request.asset,
            "decision": outcome.result.decision.value,
            "decision_evidence": dict(outcome.result.evidence),
            "latency_ms": cast(str, outcome.result.evidence["latency_ms"]),
            "observed_at": format_timestamp(request.created_at),
            "policy_version": policy_digest(mandate),
            "reason_codes": [reason.value for reason in outcome.result.reason_codes],
            "recipient": request.recipient,
            "request_digest": request.digest,
            "request_id": request.request_id,
            "sanitized_metadata": sanitized_metadata.to_dict(),
            "schema_version": AUDIT_SCHEMA_VERSION,
            "sequence": sequence,
            "settlement_reference": settlement_reference,
            "signing_state": (
                "SIGNED_SIMULATED" if outcome.settlement is not None else "NOT_SIGNED"
            ),
            "traffic_type": "SIMULATED",
        }


def receipt_from_dict(value: Mapping[str, JsonValue]) -> AuditEvent:
    """Reconstruct and validate a portable receipt from untrusted JSON data."""

    expected = _AUDIT_PAYLOAD_FIELDS | {
        "previous_receipt_digest",
        "receipt_digest",
    }
    if set(value) != expected:
        raise ValueError("receipt fields do not match the audit schema")
    previous = value["previous_receipt_digest"]
    digest = value["receipt_digest"]
    if previous is not None and not isinstance(previous, str):
        raise ValueError("previous_receipt_digest must be a string or null")
    if not isinstance(digest, str):
        raise ValueError("receipt_digest must be a string")
    if previous is not None:
        _validate_digest(previous, field_name="previous_receipt_digest")
    _validate_digest(digest, field_name="receipt_digest")
    payload = {
        key: item
        for key, item in value.items()
        if key not in {"previous_receipt_digest", "receipt_digest"}
    }
    event = AuditEvent(
        _payload_json=canonical_json(payload),
        previous_receipt_digest=previous,
        receipt_digest=digest,
    )
    if event.payload["schema_version"] != AUDIT_SCHEMA_VERSION:
        raise ValueError("unsupported audit schema version")
    parse_timestamp(event.payload["observed_at"], field_name="observed_at")
    sequence = event.payload["sequence"]
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise ValueError("sequence must be a positive integer")
    Decision(cast(str, event.payload["decision"]))
    if not AuditEventStream.verify_receipt(event):
        raise ValueError("receipt digest verification failed")
    return event


def _validate_digest(value: str, *, field_name: str) -> None:
    if len(value) != 71 or not value.startswith("sha256:"):
        raise ValueError(f"{field_name} must be a SHA-256 digest")
    try:
        int(value.removeprefix("sha256:"), 16)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a SHA-256 digest") from exc
