"""Bounded metadata sanitization for logs and dashboard events."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType

from solguard.contracts import JsonValue, PaymentRequest, canonical_json


class RedactionCategory(StrEnum):
    """Classes of sensitive values recognized by the local sanitizer."""

    API_KEY = "API_KEY"
    BEARER_TOKEN = "BEARER_TOKEN"
    CARD_LIKE = "CARD_LIKE"
    EMAIL = "EMAIL"
    SESSION_ID = "SESSION_ID"


@dataclass(frozen=True, slots=True)
class SanitizationLimits:
    """Hard bounds applied before metadata reaches observability surfaces."""

    max_depth: int = 5
    max_collection_items: int = 50
    max_string_length: int = 1024
    max_metadata_bytes: int = 8192

    def __post_init__(self) -> None:
        values = (
            self.max_depth,
            self.max_collection_items,
            self.max_string_length,
            self.max_metadata_bytes,
        )
        if any(value < 1 for value in values):
            raise ValueError("all sanitization limits must be positive")


@dataclass(frozen=True, slots=True)
class SanitizedMetadata:
    """Safe metadata copy plus non-sensitive redaction evidence."""

    data: Mapping[str, JsonValue]
    redaction_counts: Mapping[RedactionCategory, int]
    limits_applied: tuple[str, ...]

    def to_dict(self) -> dict[str, JsonValue]:
        """Return a stable object suitable for an audit event or dashboard."""

        return {
            "data": dict(self.data),
            "limits_applied": list(self.limits_applied),
            "redaction_counts": {
                category.value: count
                for category, count in sorted(
                    self.redaction_counts.items(), key=lambda item: item[0].value
                )
            },
        }


@dataclass(slots=True)
class _SanitizationState:
    counts: dict[RedactionCategory, int] = field(default_factory=dict)
    limits: set[str] = field(default_factory=set)

    def record(self, category: RedactionCategory, count: int = 1) -> None:
        self.counts[category] = self.counts.get(category, 0) + count


class MetadataSanitizer:
    """Create a deterministic safe copy without mutating the payment request."""

    _EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])")
    _BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
    _TOKEN = re.compile(
        r"(?i)\b(?:gh[pousr]_[A-Za-z0-9]{12,}|github_pat_[A-Za-z0-9_]{12,}|"
        r"sk-[A-Za-z0-9_-]{12,}|xox[baprs]-[A-Za-z0-9-]{12,})\b"
    )
    _SESSION = re.compile(r"(?i)(\bsession(?:_id|_token)?\s*[=:]\s*)([A-Za-z0-9._~+/-]{8,})")
    _CARD_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")

    _API_KEY_FIELDS = frozenset(
        {
            "accesskey",
            "accesstoken",
            "apikey",
            "authtoken",
            "authorization",
            "password",
            "privatekey",
            "secret",
        }
    )
    _SESSION_FIELDS = frozenset({"cookie", "session", "sessionid", "sessiontoken", "setcookie"})

    def __init__(self, limits: SanitizationLimits | None = None) -> None:
        self._limits = limits or SanitizationLimits()

    def sanitize_payment(self, request: PaymentRequest) -> SanitizedMetadata:
        """Sanitize the immutable metadata copy exposed by a payment request."""

        return self.sanitize(request.metadata)

    def sanitize(self, metadata: Mapping[str, JsonValue]) -> SanitizedMetadata:
        """Return bounded metadata with sensitive values removed."""

        state = _SanitizationState()
        sanitized = self._sanitize_mapping(metadata, depth=0, state=state)
        if len(canonical_json(sanitized).encode("utf-8")) > self._limits.max_metadata_bytes:
            state.limits.add("METADATA_SIZE")
            sanitized = {"_redacted": "METADATA_SIZE_LIMIT"}
        counts = {category: count for category, count in state.counts.items() if count > 0}
        return SanitizedMetadata(
            data=MappingProxyType(sanitized),
            redaction_counts=MappingProxyType(counts),
            limits_applied=tuple(sorted(state.limits)),
        )

    def _sanitize_mapping(
        self,
        value: Mapping[str, JsonValue],
        *,
        depth: int,
        state: _SanitizationState,
    ) -> dict[str, JsonValue]:
        if depth >= self._limits.max_depth:
            state.limits.add("DEPTH")
            return {"_redacted": "DEPTH_LIMIT"}

        result: dict[str, JsonValue] = {}
        entries = sorted(value.items(), key=lambda item: item[0])
        if len(entries) > self._limits.max_collection_items:
            state.limits.add("COLLECTION_ITEMS")
            entries = entries[: self._limits.max_collection_items]
        for index, (key, item) in enumerate(entries):
            safe_key = self._sanitize_text(key, state=state)
            if safe_key != key:
                safe_key = f"_redacted_key_{index}"
            if len(safe_key) > self._limits.max_string_length:
                state.limits.add("STRING_LENGTH")
                safe_key = safe_key[: self._limits.max_string_length]
            if safe_key in result:
                suffix = f"_{index}"
                prefix_length = max(1, self._limits.max_string_length - len(suffix))
                safe_key = f"{safe_key[:prefix_length]}{suffix}"
            result[safe_key] = self._sanitize_value(
                item,
                key_hint=key,
                depth=depth + 1,
                state=state,
            )
        return result

    def _sanitize_value(
        self,
        value: JsonValue,
        *,
        key_hint: str,
        depth: int,
        state: _SanitizationState,
    ) -> JsonValue:
        field_category = self._field_category(key_hint)
        if field_category is not None and value is not None:
            state.record(field_category)
            return f"[REDACTED:{field_category.value}]"
        if isinstance(value, str):
            sanitized = self._sanitize_text(value, state=state)
            if len(sanitized) > self._limits.max_string_length:
                state.limits.add("STRING_LENGTH")
                return f"{sanitized[: self._limits.max_string_length]}[TRUNCATED]"
            return sanitized
        if isinstance(value, list):
            if depth >= self._limits.max_depth:
                state.limits.add("DEPTH")
                return "[REDACTED:DEPTH_LIMIT]"
            items = value
            if len(items) > self._limits.max_collection_items:
                state.limits.add("COLLECTION_ITEMS")
                items = items[: self._limits.max_collection_items]
            return [
                self._sanitize_value(item, key_hint="", depth=depth + 1, state=state)
                for item in items
            ]
        if isinstance(value, dict):
            return self._sanitize_mapping(value, depth=depth, state=state)
        return value

    def _sanitize_text(self, value: str, *, state: _SanitizationState) -> str:
        value = self._replace_pattern(
            value, self._BEARER, RedactionCategory.BEARER_TOKEN, state=state
        )
        value = self._replace_pattern(value, self._TOKEN, RedactionCategory.API_KEY, state=state)

        def replace_session(match: re.Match[str]) -> str:
            state.record(RedactionCategory.SESSION_ID)
            return f"{match.group(1)}[REDACTED:SESSION_ID]"

        value = self._SESSION.sub(replace_session, value)
        value = self._replace_pattern(value, self._EMAIL, RedactionCategory.EMAIL, state=state)

        def replace_card(match: re.Match[str]) -> str:
            candidate = match.group(0)
            digits = re.sub(r"\D", "", candidate)
            if not self._passes_luhn(digits):
                return candidate
            state.record(RedactionCategory.CARD_LIKE)
            return "[REDACTED:CARD_LIKE]"

        return self._CARD_CANDIDATE.sub(replace_card, value)

    @staticmethod
    def _replace_pattern(
        value: str,
        pattern: re.Pattern[str],
        category: RedactionCategory,
        *,
        state: _SanitizationState,
    ) -> str:
        def replace(_: re.Match[str]) -> str:
            state.record(category)
            return f"[REDACTED:{category.value}]"

        return pattern.sub(replace, value)

    @classmethod
    def _field_category(cls, key: str) -> RedactionCategory | None:
        normalized = re.sub(r"[^a-z0-9]", "", key.lower())
        if normalized in cls._SESSION_FIELDS:
            return RedactionCategory.SESSION_ID
        if normalized == "authorization":
            return RedactionCategory.BEARER_TOKEN
        if normalized in cls._API_KEY_FIELDS:
            return RedactionCategory.API_KEY
        return None

    @staticmethod
    def _passes_luhn(digits: str) -> bool:
        if not 13 <= len(digits) <= 19:
            return False
        checksum = 0
        parity = len(digits) % 2
        for index, character in enumerate(digits):
            digit = int(character)
            if index % 2 == parity:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit
        return checksum % 10 == 0
