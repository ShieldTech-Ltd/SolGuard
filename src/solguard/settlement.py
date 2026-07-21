"""Shared settlement result and failure boundaries."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol

from solguard.contracts import JsonValue


class SettlementResult(Protocol):
    """Portable result returned by any successful settlement adapter."""

    settlement_reference: str

    def to_dict(self) -> dict[str, JsonValue]:
        """Return safe computed settlement evidence."""


class SettlementFailureKind(StrEnum):
    """Stable operational failures distinct from security decisions."""

    COMMAND_FAILED = "COMMAND_FAILED"
    INVALID_RESPONSE = "INVALID_RESPONSE"
    NETWORK = "NETWORK"
    TIMEOUT = "TIMEOUT"


class SettlementUnavailable(RuntimeError):
    """Raised when an allowed request cannot reach external settlement."""

    def __init__(self, kind: SettlementFailureKind, *, settlement_type: str) -> None:
        super().__init__(f"external settlement unavailable: {kind.value}")
        self.kind = kind
        self.settlement_type = settlement_type
