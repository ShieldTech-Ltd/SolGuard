"""Strict x402 v2 mapping and a simulated Solana-devnet signing boundary."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import MappingProxyType
from typing import cast
from urllib.parse import urlsplit, urlunsplit

from solguard.authorization import AuthorizationRejected, WalletAuthorizationGuard
from solguard.contracts import (
    AgentMandate,
    ContractValidationError,
    Decision,
    JsonObject,
    JsonValue,
    PaymentRequest,
    ReasonCode,
    SigningAuthorization,
    canonical_json,
    contract_from_json,
    format_amount,
    format_timestamp,
)
from solguard.detection import BehaviourEngine
from solguard.gateway import GatewayOutcome, PaymentGateway
from solguard.policy import MandatePolicyEngine
from solguard.settlement import SettlementFailureKind, SettlementResult, SettlementUnavailable

X402_VERSION = 2
X402_PAYMENT_REQUIRED_HEADER = "PAYMENT-REQUIRED"
X402_PAYMENT_SIGNATURE_HEADER = "PAYMENT-SIGNATURE"
X402_SOLANA_DEVNET_NETWORK = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
X402_SOLANA_DEVNET_USDC_MINT = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
X402_DEVNET_SETTLEMENT_TYPE = "X402_DEVNET_SIMULATED"
_USDC_DECIMALS = 6
_MAX_HEADER_BYTES = 65_536
_MAX_TIMEOUT_SECONDS = 300


class X402ProtocolError(ValueError):
    """Raised when an untrusted x402 envelope is invalid or unsupported."""


@dataclass(frozen=True, slots=True)
class X402PaymentRequirement:
    """One supported x402 v2 exact-payment requirement."""

    resource_url: str
    description: str
    network: str
    amount: Decimal
    amount_atomic: str
    asset_mint: str
    recipient: str
    max_timeout_seconds: int
    payment_required_digest: str
    _accepted_json: str

    @property
    def accepted(self) -> Mapping[str, JsonValue]:
        """Return the exact accepted requirement as a read-only mapping."""

        return MappingProxyType(cast(JsonObject, json.loads(self._accepted_json)))

    def to_payment_request(
        self,
        *,
        agent_id: str,
        mandate_id: str,
        attempt_id: str,
        observed_at: datetime,
    ) -> PaymentRequest:
        """Bind a payment attempt and the complete x402 requirement to SolGuard."""

        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise X402ProtocolError("observed_at must include a timezone")
        validated_attempt = _bounded_text(attempt_id, field_name="attempt_id", maximum=128)
        binding: JsonObject = {
            "attempt_id": validated_attempt,
            "payment_required_digest": self.payment_required_digest,
        }
        identifier = hashlib.sha256(canonical_json(binding).encode("utf-8")).hexdigest()
        metadata: JsonObject = {
            "asset_mint": self.asset_mint,
            "network": self.network,
            "payment_protocol": "X402",
            "payment_required_digest": self.payment_required_digest,
            "resource_url": safe_resource_url(self.resource_url),
            "scheme": "exact",
            "settlement_mode": "SIMULATED_DEVNET",
            "x402_version": X402_VERSION,
        }
        try:
            return PaymentRequest.from_dict(
                {
                    "request_id": f"x402_{identifier[:24]}",
                    "agent_id": agent_id,
                    "mandate_id": mandate_id,
                    "recipient": self.recipient,
                    "amount": format_amount(self.amount),
                    "asset": "USDC",
                    "purpose": self.description,
                    "nonce": f"x402:{identifier}",
                    "created_at": format_timestamp(observed_at),
                    "expires_at": format_timestamp(
                        observed_at + timedelta(seconds=self.max_timeout_seconds)
                    ),
                    "metadata": metadata,
                }
            )
        except ContractValidationError as exc:
            raise X402ProtocolError("x402 requirement cannot form a canonical request") from exc

    def matches(self, request: PaymentRequest) -> bool:
        """Return whether a canonical request is bound to this exact requirement."""

        expected_metadata: JsonObject = {
            "asset_mint": self.asset_mint,
            "network": self.network,
            "payment_protocol": "X402",
            "payment_required_digest": self.payment_required_digest,
            "resource_url": safe_resource_url(self.resource_url),
            "scheme": "exact",
            "settlement_mode": "SIMULATED_DEVNET",
            "x402_version": X402_VERSION,
        }
        return (
            request.recipient == self.recipient
            and request.amount == self.amount
            and request.asset == "USDC"
            and request.purpose == self.description
            and request.expires_at
            == request.created_at + timedelta(seconds=self.max_timeout_seconds)
            and request.metadata == expected_metadata
        )


def parse_payment_required_response(
    *, status: int, headers: Mapping[str, str]
) -> X402PaymentRequirement:
    """Require HTTP 402 and decode its single case-insensitive x402 v2 header."""

    if status != 402:
        raise X402ProtocolError("x402 resource did not return HTTP 402")
    values = [
        value
        for name, value in headers.items()
        if name.lower() == X402_PAYMENT_REQUIRED_HEADER.lower()
    ]
    if len(values) != 1:
        raise X402ProtocolError("HTTP 402 must include exactly one PAYMENT-REQUIRED header")
    return parse_payment_required_header(values[0])


def parse_payment_required_header(header: str) -> X402PaymentRequirement:
    """Decode one official x402 v2 ``PAYMENT-REQUIRED`` header."""

    payment_required = _decode_header_object(header, field_name=X402_PAYMENT_REQUIRED_HEADER)
    version = payment_required.get("x402Version")
    if not isinstance(version, int) or isinstance(version, bool) or version != X402_VERSION:
        raise X402ProtocolError("PAYMENT-REQUIRED must use x402Version 2")
    extensions = payment_required.get("extensions")
    if extensions is not None and not isinstance(extensions, dict):
        raise X402ProtocolError("PAYMENT-REQUIRED extensions must be an object")

    resource = _required_object(payment_required, "resource")
    resource_url = validate_resource_url(_required_text(resource, "url", maximum=2048))
    description_value = resource.get("description")
    description = (
        "x402 protected resource"
        if description_value is None
        else _bounded_text(description_value, field_name="resource.description", maximum=500)
    )

    accepts = payment_required.get("accepts")
    if not isinstance(accepts, list) or not accepts:
        raise X402ProtocolError("PAYMENT-REQUIRED accepts must be a non-empty array")
    supported: list[JsonObject] = []
    for candidate in accepts:
        if not isinstance(candidate, dict):
            raise X402ProtocolError("PAYMENT-REQUIRED accepts entries must be objects")
        if (
            candidate.get("scheme") == "exact"
            and candidate.get("network") == X402_SOLANA_DEVNET_NETWORK
            and candidate.get("asset") == X402_SOLANA_DEVNET_USDC_MINT
        ):
            supported.append(candidate)
    if not supported:
        raise X402ProtocolError("no supported Solana-devnet USDC exact requirement")
    if len(supported) != 1:
        raise X402ProtocolError("PAYMENT-REQUIRED contains ambiguous supported requirements")

    accepted = supported[0]
    amount_atomic = _required_text(accepted, "amount", maximum=64)
    if not amount_atomic.isascii() or not amount_atomic.isdigit() or int(amount_atomic) <= 0:
        raise X402ProtocolError("x402 amount must be a positive atomic-unit integer")
    recipient = _required_text(accepted, "payTo", maximum=256)
    timeout = accepted.get("maxTimeoutSeconds")
    if (
        not isinstance(timeout, int)
        or isinstance(timeout, bool)
        or not 1 <= timeout <= _MAX_TIMEOUT_SECONDS
    ):
        raise X402ProtocolError("x402 maxTimeoutSeconds is outside the local safety limit")
    extra = accepted.get("extra")
    if extra is not None and not isinstance(extra, dict):
        raise X402ProtocolError("x402 requirement extra must be an object")

    canonical_required = canonical_json(payment_required)
    payment_required_digest = f"sha256:{hashlib.sha256(canonical_required.encode()).hexdigest()}"
    amount = Decimal(amount_atomic) / (Decimal(10) ** _USDC_DECIMALS)
    return X402PaymentRequirement(
        resource_url=resource_url,
        description=description,
        network=X402_SOLANA_DEVNET_NETWORK,
        amount=amount,
        amount_atomic=amount_atomic,
        asset_mint=X402_SOLANA_DEVNET_USDC_MINT,
        recipient=recipient,
        max_timeout_seconds=timeout,
        payment_required_digest=payment_required_digest,
        _accepted_json=canonical_json(accepted),
    )


X402PayloadSigner = Callable[[X402PaymentRequirement, PaymentRequest], str]


@dataclass(frozen=True, slots=True)
class X402DevnetSimulationResult(SettlementResult):
    """Safe local evidence that signing was reached only after SolGuard allowed it."""

    settlement_reference: str
    network: str
    amount: Decimal
    recipient: str
    payment_required_digest: str
    payment_signature_digest: str
    payment_signature_bytes: int

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "amount": format_amount(self.amount),
            "asset": "USDC",
            "network": self.network,
            "payment_required_digest": self.payment_required_digest,
            "payment_signature_bytes": self.payment_signature_bytes,
            "payment_signature_digest": self.payment_signature_digest,
            "recipient": self.recipient,
            "settlement_reference": self.settlement_reference,
            "settlement_type": X402_DEVNET_SETTLEMENT_TYPE,
            "status": "PREPARED_SIMULATION",
        }


class X402DevnetSimulatedSettlement:
    """Call an x402 payload signer only after consuming a valid SolGuard authorization."""

    def __init__(
        self,
        *,
        requirement: X402PaymentRequirement,
        signer: X402PayloadSigner,
        authorization_guard: WalletAuthorizationGuard | None = None,
    ) -> None:
        self._requirement = requirement
        self._signer = signer
        self._authorization_guard = (
            authorization_guard if authorization_guard is not None else WalletAuthorizationGuard()
        )

    def settle(
        self,
        request: PaymentRequest,
        authorization: SigningAuthorization | None,
    ) -> X402DevnetSimulationResult:
        """Prepare one simulated devnet payload after exact-request authorization."""

        if not self._requirement.matches(request):
            raise AuthorizationRejected(ReasonCode.AUTHORIZATION_MISMATCH)
        consumed = self._authorization_guard.authorize(request, authorization)
        header = self._signer(self._requirement, request)
        try:
            _validate_payment_signature_header(header, requirement=self._requirement)
        except X402ProtocolError as exc:
            raise SettlementUnavailable(
                SettlementFailureKind.INVALID_RESPONSE,
                settlement_type=X402_DEVNET_SETTLEMENT_TYPE,
            ) from exc
        encoded = header.encode("ascii")
        signature_digest = f"sha256:{hashlib.sha256(encoded).hexdigest()}"
        reference_payload: JsonObject = {
            "authorization_id": consumed.authorization_id,
            "payment_required_digest": self._requirement.payment_required_digest,
            "payment_signature_digest": signature_digest,
            "request_digest": request.digest,
            "settlement_type": X402_DEVNET_SETTLEMENT_TYPE,
        }
        reference = hashlib.sha256(canonical_json(reference_payload).encode()).hexdigest()
        return X402DevnetSimulationResult(
            settlement_reference=f"x402:devnet:simulated:sha256:{reference}",
            network=self._requirement.network,
            amount=request.amount,
            recipient=request.recipient,
            payment_required_digest=self._requirement.payment_required_digest,
            payment_signature_digest=signature_digest,
            payment_signature_bytes=len(encoded),
        )


def validate_resource_url(resource_url: str) -> str:
    """Require a bounded, credential-free HTTPS x402 resource URL."""

    parsed = urlsplit(resource_url)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise X402ProtocolError("x402 resource URL must be absolute, credential-free HTTPS")
    return resource_url


def safe_resource_url(resource_url: str) -> str:
    """Remove untrusted query values before evidence or logs."""

    parsed = urlsplit(resource_url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def run_x402_devnet_demo(*, clock: Callable[[], datetime] | None = None) -> dict[str, JsonValue]:
    """Run one allowed and one blocked x402 v2 devnet-labelled simulation."""

    now = (clock or (lambda: datetime.now(UTC)))()
    allowed_requirement = parse_payment_required_response(
        status=402,
        headers={X402_PAYMENT_REQUIRED_HEADER: _demo_required_header("10000")},
    )
    blocked_requirement = parse_payment_required_response(
        status=402,
        headers={X402_PAYMENT_REQUIRED_HEADER: _demo_required_header("1000000")},
    )
    allowed_request = allowed_requirement.to_payment_request(
        agent_id="x402-demo-agent",
        mandate_id="x402-demo-mandate",
        attempt_id="allowed-attempt",
        observed_at=now,
    )
    blocked_request = blocked_requirement.to_payment_request(
        agent_id="x402-demo-agent",
        mandate_id="x402-demo-mandate",
        attempt_id="blocked-attempt",
        observed_at=now,
    )
    mandate = AgentMandate.from_dict(
        {
            "mandate_id": allowed_request.mandate_id,
            "agent_id": allowed_request.agent_id,
            "purpose": "x402 Solana-devnet simulation",
            "asset": "USDC",
            "max_single_payment": "0.1",
            "allowed_recipients": [allowed_request.recipient],
            "blocked_recipients": [],
            "valid_from": format_timestamp(now - timedelta(minutes=1)),
            "expires_at": format_timestamp(now + timedelta(minutes=10)),
        }
    )
    signer_calls: list[str] = []

    def simulated_signer(requirement: X402PaymentRequirement, request: PaymentRequest) -> str:
        signer_calls.append(request.request_id)
        payload: JsonObject = {
            "accepted": cast(JsonValue, dict(requirement.accepted)),
            "payload": {"transaction": f"SIMULATED:{request.digest}"},
            "resource": {"url": requirement.resource_url},
            "x402Version": X402_VERSION,
        }
        return _encode_header_object(payload)

    def gateway(requirement: X402PaymentRequirement) -> PaymentGateway:
        return PaymentGateway(
            policy=MandatePolicyEngine({mandate.agent_id: mandate}),
            detection=BehaviourEngine(),
            settlement=X402DevnetSimulatedSettlement(
                requirement=requirement,
                signer=simulated_signer,
                authorization_guard=WalletAuthorizationGuard(clock=lambda: now),
            ),
            clock=lambda: now,
        )

    allowed = gateway(allowed_requirement).process(allowed_request)
    blocked = gateway(blocked_requirement).process(blocked_request)
    verified = (
        allowed.result.decision is Decision.ALLOW
        and allowed.settlement is not None
        and blocked.result.decision is Decision.BLOCK
        and blocked.settlement is None
        and signer_calls == [allowed_request.request_id]
    )
    return {
        "allowed": _demo_outcome(allowed),
        "blocked": _demo_outcome(blocked),
        "network": X402_SOLANA_DEVNET_NETWORK,
        "settlement_mode": "SIMULATED_DEVNET",
        "signer_calls": len(signer_calls),
        "status": "VERIFIED" if verified else "FAILED",
        "x402_version": X402_VERSION,
    }


def _demo_outcome(outcome: GatewayOutcome) -> JsonObject:
    return {
        "decision": outcome.result.decision.value,
        "reason_codes": [reason.value for reason in outcome.result.reason_codes],
        "request_digest": outcome.result.request_digest,
        "settlement": (outcome.settlement.to_dict() if outcome.settlement is not None else None),
    }


def _demo_required_header(amount_atomic: str) -> str:
    payment_required: JsonObject = {
        "accepts": [
            {
                "amount": amount_atomic,
                "asset": X402_SOLANA_DEVNET_USDC_MINT,
                "extra": {"feePayer": "DemoFeePayer111111111111111111111111111111"},
                "maxTimeoutSeconds": 60,
                "network": X402_SOLANA_DEVNET_NETWORK,
                "payTo": "DemoRecipient11111111111111111111111111111",
                "scheme": "exact",
            }
        ],
        "extensions": {},
        "resource": {
            "description": "x402 protected weather resource",
            "mimeType": "application/json",
            "url": "https://demo.invalid/weather",
        },
        "x402Version": X402_VERSION,
    }
    return _encode_header_object(payment_required)


def _validate_payment_signature_header(
    header: str, *, requirement: X402PaymentRequirement
) -> JsonObject:
    payment_payload = _decode_header_object(header, field_name=X402_PAYMENT_SIGNATURE_HEADER)
    version = payment_payload.get("x402Version")
    if not isinstance(version, int) or isinstance(version, bool) or version != X402_VERSION:
        raise X402ProtocolError("PAYMENT-SIGNATURE must use x402Version 2")
    accepted = _required_object(payment_payload, "accepted")
    if canonical_json(accepted) != canonical_json(cast(JsonObject, dict(requirement.accepted))):
        raise X402ProtocolError("PAYMENT-SIGNATURE accepted requirement does not match")
    scheme_payload = _required_object(payment_payload, "payload")
    if not scheme_payload:
        raise X402ProtocolError("PAYMENT-SIGNATURE payload must not be empty")
    return payment_payload


def _decode_header_object(header: str, *, field_name: str) -> JsonObject:
    if not isinstance(header, str) or not header or header != header.strip():
        raise X402ProtocolError(f"{field_name} must be a non-empty trimmed Base64 string")
    try:
        encoded = header.encode("ascii")
    except UnicodeEncodeError as exc:
        raise X402ProtocolError(f"{field_name} must contain ASCII Base64") from exc
    if len(encoded) > _MAX_HEADER_BYTES:
        raise X402ProtocolError(f"{field_name} exceeds the local size limit")
    try:
        decoded = base64.b64decode(encoded + b"=" * (-len(encoded) % 4), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise X402ProtocolError(f"{field_name} is not valid Base64") from exc
    try:
        raw = decoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise X402ProtocolError(f"{field_name} payload must be UTF-8 JSON") from exc
    try:
        return contract_from_json(raw)
    except ContractValidationError as exc:
        raise X402ProtocolError(f"{field_name} payload must be a valid JSON object") from exc


def _encode_header_object(value: Mapping[str, JsonValue]) -> str:
    return base64.b64encode(canonical_json(value).encode()).decode("ascii")


def _required_object(value: Mapping[str, JsonValue], field_name: str) -> JsonObject:
    item = value.get(field_name)
    if not isinstance(item, dict):
        raise X402ProtocolError(f"x402 {field_name} must be an object")
    return item


def _required_text(value: Mapping[str, JsonValue], field_name: str, *, maximum: int) -> str:
    item = value.get(field_name)
    return _bounded_text(item, field_name=field_name, maximum=maximum)


def _bounded_text(value: object, *, field_name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum:
        raise X402ProtocolError(f"x402 {field_name} is invalid")
    return value


def main(arguments: Sequence[str] | None = None) -> int:
    """Run the deterministic x402 Solana-devnet-labelled simulation."""

    parser = argparse.ArgumentParser(description="Run the SolGuard x402 devnet simulation")
    parser.parse_args(arguments)
    report = run_x402_devnet_demo()
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0 if report["status"] == "VERIFIED" else 2


if __name__ == "__main__":  # pragma: no cover - exercised through the console entry point
    raise SystemExit(main())
