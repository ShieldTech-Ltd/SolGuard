"""Basic request expiry and per-agent nonce replay protection."""

from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Protocol

from solguard.contracts import (
    Decision,
    JsonValue,
    PaymentRequest,
    ReasonCode,
    format_timestamp,
)


class NonceStore(Protocol):
    """Atomic storage boundary required by the request integrity guard."""

    def consume_if_unused(self, agent_id: str, nonce: str) -> bool:
        """Return true only when this agent/nonce pair was atomically recorded."""


class InMemoryNonceStore:
    """Thread-safe process-local nonce store for the hackathon prototype."""

    def __init__(self) -> None:
        self._consumed: set[tuple[str, str]] = set()
        self._lock = threading.Lock()

    def consume_if_unused(self, agent_id: str, nonce: str) -> bool:
        """Atomically reject a previously consumed nonce for the same agent."""

        key = (agent_id, nonce)
        with self._lock:
            if key in self._consumed:
                return False
            self._consumed.add(key)
            return True


@dataclass(frozen=True, slots=True)
class IntegrityResult:
    """Stable request-integrity decision and non-sensitive evidence."""

    decision: Decision
    reason_codes: tuple[ReasonCode, ...]
    evidence: Mapping[str, JsonValue]


class RequestIntegrityGuard:
    """Reject expired requests and atomically consume fresh per-agent nonces."""

    def __init__(self, nonce_store: NonceStore | None = None) -> None:
        self._nonce_store = nonce_store if nonce_store is not None else InMemoryNonceStore()

    def evaluate(self, request: PaymentRequest, *, observed_at: datetime) -> IntegrityResult:
        """Evaluate freshness, then consume the nonce at the integrity boundary."""

        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")

        common_evidence: dict[str, JsonValue] = {
            "expires_at": format_timestamp(request.expires_at),
            "observed_at": format_timestamp(observed_at),
        }
        if observed_at >= request.expires_at:
            return self._result(
                decision=Decision.BLOCK,
                reason_codes=(ReasonCode.REQUEST_EXPIRED,),
                evidence={**common_evidence, "nonce_state": "NOT_CONSUMED"},
            )

        consumed = self._nonce_store.consume_if_unused(request.agent_id, request.nonce)
        if not isinstance(consumed, bool):
            raise TypeError("nonce store must return a boolean")
        if not consumed:
            return self._result(
                decision=Decision.BLOCK,
                reason_codes=(ReasonCode.REQUEST_REPLAYED,),
                evidence={**common_evidence, "nonce_state": "ALREADY_CONSUMED"},
            )
        return self._result(
            decision=Decision.ALLOW,
            reason_codes=(),
            evidence={**common_evidence, "nonce_state": "CONSUMED"},
        )

    @staticmethod
    def _result(
        *,
        decision: Decision,
        reason_codes: tuple[ReasonCode, ...],
        evidence: dict[str, JsonValue],
    ) -> IntegrityResult:
        return IntegrityResult(
            decision=decision,
            reason_codes=reason_codes,
            evidence=MappingProxyType(evidence),
        )
