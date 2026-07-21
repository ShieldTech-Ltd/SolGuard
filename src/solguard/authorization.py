"""Single-use authorization enforcement at the wallet settlement boundary."""

from __future__ import annotations

import threading
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol

from solguard.contracts import PaymentRequest, ReasonCode, SigningAuthorization


class AuthorizationStore(Protocol):
    """Atomic storage boundary for consumed authorization identifiers."""

    def consume_if_unused(self, authorization_id: str) -> bool:
        """Return true only when the identifier was atomically recorded."""


class InMemoryAuthorizationStore:
    """Thread-safe process-local authorization store for sandbox use."""

    def __init__(self) -> None:
        self._consumed: set[str] = set()
        self._lock = threading.Lock()

    def consume_if_unused(self, authorization_id: str) -> bool:
        with self._lock:
            if authorization_id in self._consumed:
                return False
            self._consumed.add(authorization_id)
            return True


class AuthorizationRejected(RuntimeError):
    """Stable wallet-boundary rejection without sensitive details."""

    def __init__(self, reason_code: ReasonCode) -> None:
        super().__init__(f"wallet authorization rejected: {reason_code.value}")
        self.reason_code = reason_code


class WalletAuthorizationGuard:
    """Validate request binding and atomically consume one authorization."""

    def __init__(
        self,
        store: AuthorizationStore | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._store = store if store is not None else InMemoryAuthorizationStore()
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))

    def authorize(
        self,
        request: PaymentRequest,
        authorization: SigningAuthorization | None,
    ) -> SigningAuthorization:
        """Return a consumed valid authorization or raise a stable rejection."""

        if authorization is None:
            raise AuthorizationRejected(ReasonCode.AUTHORIZATION_MISSING)
        observed_at = self._clock()
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise ValueError("authorization clock must include a timezone")
        if authorization.request_id != request.request_id:
            raise AuthorizationRejected(ReasonCode.AUTHORIZATION_MISMATCH)
        if authorization.request_digest != request.digest:
            raise AuthorizationRejected(ReasonCode.AUTHORIZATION_MISMATCH)
        if observed_at >= authorization.expires_at:
            raise AuthorizationRejected(ReasonCode.AUTHORIZATION_EXPIRED)
        consumed = self._store.consume_if_unused(authorization.authorization_id)
        if not isinstance(consumed, bool):
            raise TypeError("authorization store must return a boolean")
        if not consumed:
            raise AuthorizationRejected(ReasonCode.AUTHORIZATION_REPLAYED)
        return authorization
