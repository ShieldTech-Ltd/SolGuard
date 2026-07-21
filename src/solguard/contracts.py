"""Protocol-independent contracts for SolGuard payment decisions."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from types import MappingProxyType
from typing import Any, TypeAlias, cast

JsonScalar: TypeAlias = str | int | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]

_DECIMAL_PATTERN = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")


class ContractValidationError(ValueError):
    """Raised when untrusted data cannot form a valid SolGuard contract."""


class Decision(StrEnum):
    """Public gateway decisions."""

    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    BLOCK = "BLOCK"


class ReasonCode(StrEnum):
    """Stable, machine-readable reasons emitted by SolGuard controls."""

    REQUEST_INVALID = "REQUEST_INVALID"
    REQUEST_EXPIRED = "REQUEST_EXPIRED"
    REQUEST_REPLAYED = "REQUEST_REPLAYED"
    AUTHORIZATION_EXPIRED = "AUTHORIZATION_EXPIRED"
    AUTHORIZATION_MISMATCH = "AUTHORIZATION_MISMATCH"
    AUTHORIZATION_MISSING = "AUTHORIZATION_MISSING"
    AUTHORIZATION_REPLAYED = "AUTHORIZATION_REPLAYED"
    POLICY_MISSING = "POLICY_MISSING"
    POLICY_MANDATE_MISMATCH = "POLICY_MANDATE_MISMATCH"
    POLICY_AMOUNT_LIMIT = "POLICY_AMOUNT_LIMIT"
    POLICY_RECIPIENT_BLOCKED = "POLICY_RECIPIENT_BLOCKED"
    POLICY_RECIPIENT_NOT_ALLOWED = "POLICY_RECIPIENT_NOT_ALLOWED"
    DETECTION_VELOCITY = "DETECTION_VELOCITY"
    DETECTION_AMOUNT_ANOMALY = "DETECTION_AMOUNT_ANOMALY"
    DETECTION_RECIPIENT_NOVEL = "DETECTION_RECIPIENT_NOVEL"
    DETECTION_COMPOUND_DRAIN = "DETECTION_COMPOUND_DRAIN"
    SETTLEMENT_INSUFFICIENT_FUNDS = "SETTLEMENT_INSUFFICIENT_FUNDS"
    SETTLEMENT_UNAVAILABLE = "SETTLEMENT_UNAVAILABLE"
    SYSTEM_FAILURE = "SYSTEM_FAILURE"


def parse_amount(value: object, *, field_name: str = "amount") -> Decimal:
    """Parse a positive canonical decimal string without binary floating point."""

    if not isinstance(value, str) or _DECIMAL_PATTERN.fullmatch(value) is None:
        raise ContractValidationError(
            f"{field_name} must be a positive decimal string without signs or exponents"
        )
    try:
        amount = Decimal(value)
    except InvalidOperation as exc:  # pragma: no cover - guarded by the strict pattern
        raise ContractValidationError(f"{field_name} is not a valid decimal") from exc
    if not amount.is_finite() or amount <= 0:
        raise ContractValidationError(f"{field_name} must be greater than zero")
    return amount


def format_amount(value: Decimal) -> str:
    """Return one stable fixed-point representation for a decimal amount."""

    normalized = value.normalize()
    return format(normalized, "f")


def parse_timestamp(value: object, *, field_name: str) -> datetime:
    """Parse an ISO-8601 timestamp and normalize it to UTC."""

    if not isinstance(value, str):
        raise ContractValidationError(f"{field_name} must be an ISO-8601 string")
    candidate = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        timestamp = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ContractValidationError(f"{field_name} must be a valid ISO-8601 timestamp") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ContractValidationError(f"{field_name} must include a timezone")
    return timestamp.astimezone(UTC)


def format_timestamp(value: datetime) -> str:
    """Return a stable UTC ISO-8601 timestamp."""

    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def canonical_json(value: Mapping[str, JsonValue]) -> str:
    """Serialize a validated JSON object deterministically."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _validate_text(value: object, *, field_name: str, maximum: int = 128) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ContractValidationError(f"{field_name} must be a non-empty trimmed string")
    if len(value) > maximum:
        raise ContractValidationError(f"{field_name} exceeds {maximum} characters")
    return value


def _validate_fields(data: Mapping[str, object], expected: set[str]) -> None:
    supplied = set(data)
    missing = expected - supplied
    unknown = supplied - expected
    if missing or unknown:
        details: list[str] = []
        if missing:
            details.append(f"missing fields: {', '.join(sorted(missing))}")
        if unknown:
            details.append(f"unknown fields: {', '.join(sorted(unknown))}")
        raise ContractValidationError("; ".join(details))


def _validate_json_value(value: object, *, path: str) -> JsonValue:
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        raise ContractValidationError(f"{path} must not contain floating-point values")
    if isinstance(value, list):
        return [_validate_json_value(item, path=f"{path}[]") for item in value]
    if isinstance(value, dict):
        result: JsonObject = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ContractValidationError(f"{path} keys must be strings")
            result[key] = _validate_json_value(item, path=f"{path}.{key}")
        return result
    raise ContractValidationError(f"{path} contains a non-JSON value")


def _validated_json_object(value: object, *, field_name: str) -> JsonObject:
    if not isinstance(value, dict):
        raise ContractValidationError(f"{field_name} must be an object")
    validated = _validate_json_value(value, path=field_name)
    return cast(JsonObject, validated)


def _json_object_from_canonical(value: str) -> Mapping[str, JsonValue]:
    parsed = cast(JsonObject, json.loads(value))
    return MappingProxyType(parsed)


@dataclass(frozen=True, slots=True)
class PaymentRequest:
    """Canonical payment request evaluated by the SolGuard gateway."""

    request_id: str
    agent_id: str
    mandate_id: str
    recipient: str
    amount: Decimal
    asset: str
    purpose: str
    nonce: str
    created_at: datetime
    expires_at: datetime
    _metadata_json: str

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> PaymentRequest:
        """Validate untrusted mapping data into a canonical request."""

        expected = {
            "request_id",
            "agent_id",
            "mandate_id",
            "recipient",
            "amount",
            "asset",
            "purpose",
            "nonce",
            "created_at",
            "expires_at",
            "metadata",
        }
        _validate_fields(data, expected)
        created_at = parse_timestamp(data["created_at"], field_name="created_at")
        expires_at = parse_timestamp(data["expires_at"], field_name="expires_at")
        if expires_at <= created_at:
            raise ContractValidationError("expires_at must be later than created_at")
        metadata = _validated_json_object(data["metadata"], field_name="metadata")
        return cls(
            request_id=_validate_text(data["request_id"], field_name="request_id"),
            agent_id=_validate_text(data["agent_id"], field_name="agent_id"),
            mandate_id=_validate_text(data["mandate_id"], field_name="mandate_id"),
            recipient=_validate_text(data["recipient"], field_name="recipient", maximum=256),
            amount=parse_amount(data["amount"]),
            asset=_validate_text(data["asset"], field_name="asset", maximum=32),
            purpose=_validate_text(data["purpose"], field_name="purpose", maximum=500),
            nonce=_validate_text(data["nonce"], field_name="nonce", maximum=256),
            created_at=created_at,
            expires_at=expires_at,
            _metadata_json=canonical_json(metadata),
        )

    @property
    def metadata(self) -> Mapping[str, JsonValue]:
        """Return a read-only top-level copy of payment metadata."""

        return _json_object_from_canonical(self._metadata_json)

    def to_dict(self) -> JsonObject:
        """Return the stable JSON representation used for protocol adapters."""

        return {
            "agent_id": self.agent_id,
            "amount": format_amount(self.amount),
            "asset": self.asset,
            "created_at": format_timestamp(self.created_at),
            "expires_at": format_timestamp(self.expires_at),
            "mandate_id": self.mandate_id,
            "metadata": cast(JsonValue, dict(self.metadata)),
            "nonce": self.nonce,
            "purpose": self.purpose,
            "recipient": self.recipient,
            "request_id": self.request_id,
        }

    @property
    def canonical(self) -> str:
        """Return the deterministic serialized request."""

        return canonical_json(self.to_dict())

    @property
    def digest(self) -> str:
        """Bind decisions and authorizations to the exact canonical request."""

        value = hashlib.sha256(self.canonical.encode("utf-8")).hexdigest()
        return f"sha256:{value}"


@dataclass(frozen=True, slots=True)
class AgentMandate:
    """Simple per-agent authority used by the initial policy engine."""

    mandate_id: str
    agent_id: str
    purpose: str
    asset: str
    max_single_payment: Decimal
    allowed_recipients: tuple[str, ...]
    blocked_recipients: tuple[str, ...]
    valid_from: datetime
    expires_at: datetime

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> AgentMandate:
        """Validate untrusted mapping data into a simple mandate."""

        expected = {
            "mandate_id",
            "agent_id",
            "purpose",
            "asset",
            "max_single_payment",
            "allowed_recipients",
            "blocked_recipients",
            "valid_from",
            "expires_at",
        }
        _validate_fields(data, expected)
        valid_from = parse_timestamp(data["valid_from"], field_name="valid_from")
        expires_at = parse_timestamp(data["expires_at"], field_name="expires_at")
        if expires_at <= valid_from:
            raise ContractValidationError("expires_at must be later than valid_from")
        allowed = _validate_recipients(data["allowed_recipients"], field_name="allowed_recipients")
        blocked = _validate_recipients(data["blocked_recipients"], field_name="blocked_recipients")
        return cls(
            mandate_id=_validate_text(data["mandate_id"], field_name="mandate_id"),
            agent_id=_validate_text(data["agent_id"], field_name="agent_id"),
            purpose=_validate_text(data["purpose"], field_name="purpose", maximum=500),
            asset=_validate_text(data["asset"], field_name="asset", maximum=32),
            max_single_payment=parse_amount(
                data["max_single_payment"], field_name="max_single_payment"
            ),
            allowed_recipients=allowed,
            blocked_recipients=blocked,
            valid_from=valid_from,
            expires_at=expires_at,
        )

    def to_dict(self) -> JsonObject:
        """Return a stable JSON representation of the mandate."""

        return {
            "agent_id": self.agent_id,
            "allowed_recipients": list(self.allowed_recipients),
            "asset": self.asset,
            "blocked_recipients": list(self.blocked_recipients),
            "expires_at": format_timestamp(self.expires_at),
            "mandate_id": self.mandate_id,
            "max_single_payment": format_amount(self.max_single_payment),
            "purpose": self.purpose,
            "valid_from": format_timestamp(self.valid_from),
        }


def _validate_recipients(value: object, *, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ContractValidationError(f"{field_name} must be an array")
    recipients = {_validate_text(item, field_name=f"{field_name}[]", maximum=256) for item in value}
    if len(recipients) != len(value):
        raise ContractValidationError(f"{field_name} must not contain duplicates")
    return tuple(sorted(recipients))


@dataclass(frozen=True, slots=True)
class SigningAuthorization:
    """Short-lived request-bound permission presented to a wallet adapter."""

    authorization_id: str
    request_id: str
    request_digest: str
    issued_at: datetime
    expires_at: datetime

    def to_dict(self) -> JsonObject:
        """Return a stable JSON representation of the authorization."""

        return {
            "authorization_id": self.authorization_id,
            "expires_at": format_timestamp(self.expires_at),
            "issued_at": format_timestamp(self.issued_at),
            "request_digest": self.request_digest,
            "request_id": self.request_id,
        }


@dataclass(frozen=True, slots=True)
class DecisionResult:
    """Explainable gateway decision returned to protocol and UI adapters."""

    request_id: str
    decision: Decision
    reason_codes: tuple[ReasonCode, ...]
    request_digest: str
    _evidence_json: str
    authorization: SigningAuthorization | None = None

    @classmethod
    def create(
        cls,
        *,
        request_id: str,
        decision: Decision,
        reason_codes: tuple[ReasonCode, ...],
        request_digest: str,
        evidence: Mapping[str, object],
        authorization: SigningAuthorization | None = None,
    ) -> DecisionResult:
        """Create a deterministic result from validated gateway output."""

        if decision is not Decision.ALLOW and authorization is not None:
            raise ContractValidationError("only ALLOW decisions may include an authorization")
        validated_evidence = _validated_json_object(dict(evidence), field_name="evidence")
        stable_reasons = tuple(sorted(set(reason_codes), key=str))
        return cls(
            request_id=_validate_text(request_id, field_name="request_id"),
            decision=decision,
            reason_codes=stable_reasons,
            request_digest=_validate_text(request_digest, field_name="request_digest", maximum=128),
            _evidence_json=canonical_json(validated_evidence),
            authorization=authorization,
        )

    @property
    def evidence(self) -> Mapping[str, JsonValue]:
        """Return a read-only top-level copy of decision evidence."""

        return _json_object_from_canonical(self._evidence_json)

    def to_dict(self) -> JsonObject:
        """Return a stable JSON representation of the decision."""

        return {
            "authorization": (
                cast(JsonValue, self.authorization.to_dict())
                if self.authorization is not None
                else None
            ),
            "decision": self.decision.value,
            "evidence": cast(JsonValue, dict(self.evidence)),
            "reason_codes": [reason.value for reason in self.reason_codes],
            "request_digest": self.request_digest,
            "request_id": self.request_id,
        }


def contract_from_json(raw: str) -> JsonObject:
    """Decode a JSON object while rejecting non-standard numeric constants."""

    def reject_constant(value: str) -> Any:
        raise ContractValidationError(f"non-finite JSON number is not allowed: {value}")

    try:
        decoded = json.loads(raw, parse_constant=reject_constant)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ContractValidationError("payload must be valid JSON") from exc
    return _validated_json_object(decoded, field_name="payload")
