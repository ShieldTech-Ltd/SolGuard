"""Pay.sh sandbox challenge conversion and external settlement adapter."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

from solguard.contracts import (
    AgentMandate,
    ContractValidationError,
    JsonValue,
    PaymentRequest,
    ReasonCode,
    SigningAuthorization,
    canonical_json,
    format_amount,
    format_timestamp,
    parse_amount,
    parse_timestamp,
)
from solguard.detection import BehaviourEngine
from solguard.gateway import GatewayOutcome, PaymentGateway
from solguard.policy import MandatePolicyEngine
from solguard.settlement import SettlementFailureKind, SettlementResult, SettlementUnavailable

PAYSH_SANDBOX_ENDPOINT = "https://debugger.pay.sh/mpp/quote/AAPL"
PAYSH_SETTLEMENT_TYPE = "PAYSH_SANDBOX"
SOLANA_USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
_PAYMENT_PARAMETER = re.compile(
    r"(?P<key>[A-Za-z][A-Za-z0-9_-]*)=(?P<value>\"(?:\\.|[^\"])*\"|[^,\s]+)"
)


class PayShProtocolError(ValueError):
    """Raised when untrusted Pay.sh requirements are not supported or valid."""


class PayShNetworkError(RuntimeError):
    """Raised when payment requirements cannot be retrieved from the endpoint."""


@dataclass(frozen=True, slots=True)
class HttpResult:
    """Minimal challenge-probe response."""

    status: int
    headers: Mapping[str, str]


ChallengeTransport = Callable[[str, float], HttpResult]


@dataclass(frozen=True, slots=True)
class PayShPaymentRequirement:
    """Validated MPP charge requirement converted from an HTTP 402 challenge."""

    challenge_id: str
    endpoint: str
    recipient: str
    amount: Decimal
    currency_mint: str
    description: str
    expires_at: datetime
    network: str

    def to_payment_request(
        self,
        *,
        agent_id: str,
        mandate_id: str,
        observed_at: datetime,
    ) -> PaymentRequest:
        """Bind the validated external requirement into SolGuard's canonical contract."""

        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise PayShProtocolError("observed_at must include a timezone")
        if self.expires_at <= observed_at:
            raise PayShProtocolError("Pay.sh challenge expired before evaluation")
        identifier_material = f"{self.challenge_id}|{self.endpoint}".encode()
        request_identifier = hashlib.sha256(identifier_material).hexdigest()[:24]
        metadata: dict[str, JsonValue] = {
            "currency_mint": self.currency_mint,
            "endpoint": safe_endpoint(self.endpoint),
            "network": self.network,
            "payment_protocol": "MPP",
            "settlement_mode": "SANDBOX",
        }
        try:
            return PaymentRequest.from_dict(
                {
                    "request_id": f"paysh_{request_identifier}",
                    "agent_id": agent_id,
                    "mandate_id": mandate_id,
                    "recipient": self.recipient,
                    "amount": format_amount(self.amount),
                    "asset": "USDC",
                    "purpose": self.description or "Pay.sh sandbox API request",
                    "nonce": self.challenge_id,
                    "created_at": format_timestamp(observed_at),
                    "expires_at": format_timestamp(self.expires_at),
                    "metadata": metadata,
                }
            )
        except ContractValidationError as exc:
            raise PayShProtocolError("Pay.sh requirement cannot form a canonical request") from exc


class PayShChallengeProbe:
    """Retrieve and validate a Pay.sh MPP sandbox payment challenge."""

    def __init__(self, transport: ChallengeTransport | None = None) -> None:
        self._transport = transport if transport is not None else _http_probe

    def probe(self, endpoint: str, *, timeout_seconds: float = 10.0) -> PayShPaymentRequirement:
        """Return validated payment requirements from an expected HTTP 402 response."""

        validated_endpoint = validate_endpoint(endpoint)
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        result = self._transport(validated_endpoint, timeout_seconds)
        if result.status != 402:
            raise PayShProtocolError("Pay.sh endpoint did not return HTTP 402")
        header = next(
            (value for key, value in result.headers.items() if key.lower() == "www-authenticate"),
            None,
        )
        if header is None:
            raise PayShProtocolError("Pay.sh response omitted WWW-Authenticate")
        return parse_payment_requirement(header, endpoint=validated_endpoint)


def _http_probe(endpoint: str, timeout_seconds: float) -> HttpResult:
    request = Request(endpoint, method="GET", headers={"User-Agent": "SolGuard/0.1"})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return HttpResult(status=response.status, headers=dict(response.headers.items()))
    except HTTPError as exc:
        try:
            return HttpResult(status=exc.code, headers=dict(exc.headers.items()))
        finally:
            exc.close()
    except (TimeoutError, URLError, OSError) as exc:
        raise PayShNetworkError("Pay.sh challenge probe failed") from exc


def parse_payment_requirement(header: str, *, endpoint: str) -> PayShPaymentRequirement:
    """Parse one strict MPP sandbox charge from a Payment authentication challenge."""

    scheme, separator, raw_parameters = header.partition(" ")
    if scheme.lower() != "payment" or not separator:
        raise PayShProtocolError("unsupported payment authentication scheme")
    parameters = _parse_parameters(raw_parameters)
    required = {"id", "method", "intent", "request", "expires"}
    if not required.issubset(parameters):
        raise PayShProtocolError("payment challenge omitted required parameters")
    if parameters["method"] != "solana" or parameters["intent"] != "charge":
        raise PayShProtocolError("only Solana MPP charge challenges are supported")

    payload = _decode_request(parameters["request"])
    amount_minor = _required_text(payload, "amount")
    if not amount_minor.isascii() or not amount_minor.isdigit():
        raise PayShProtocolError("payment amount must be an unsigned integer")
    method_details = payload.get("methodDetails")
    if not isinstance(method_details, dict):
        raise PayShProtocolError("payment methodDetails must be an object")
    decimals = method_details.get("decimals")
    if not isinstance(decimals, int) or isinstance(decimals, bool) or not 0 <= decimals <= 18:
        raise PayShProtocolError("payment decimals are invalid")
    network = _required_text(method_details, "network")
    if network != "localnet":
        raise PayShProtocolError("Pay.sh sandbox challenge must use localnet")
    currency = _required_text(payload, "currency")
    if currency != SOLANA_USDC_MINT:
        raise PayShProtocolError("Pay.sh sandbox challenge currency is not supported USDC")
    amount = Decimal(amount_minor) / (Decimal(10) ** decimals)
    if amount <= 0:
        raise PayShProtocolError("payment amount must be positive")
    try:
        expires_at = parse_timestamp(parameters["expires"], field_name="expires")
    except ContractValidationError as exc:
        raise PayShProtocolError("payment challenge expiry is invalid") from exc

    return PayShPaymentRequirement(
        challenge_id=_bounded_text(parameters["id"], field_name="challenge id", maximum=256),
        endpoint=validate_endpoint(endpoint),
        recipient=_bounded_text(
            _required_text(payload, "recipient"), field_name="recipient", maximum=256
        ),
        amount=amount,
        currency_mint=currency,
        description=_bounded_text(
            parameters.get("description", "Pay.sh sandbox API request"),
            field_name="description",
            maximum=500,
        ),
        expires_at=expires_at,
        network=network,
    )


def _parse_parameters(value: str) -> dict[str, str]:
    parameters: dict[str, str] = {}
    cursor = 0
    for match in _PAYMENT_PARAMETER.finditer(value):
        if value[cursor : match.start()].strip(" ,"):
            raise PayShProtocolError("payment challenge parameters are malformed")
        key = match.group("key").lower()
        if key in parameters:
            raise PayShProtocolError("payment challenge contains duplicate parameters")
        raw = match.group("value")
        try:
            parsed = cast(str, json.loads(raw)) if raw.startswith('"') else raw
        except json.JSONDecodeError as exc:
            raise PayShProtocolError("payment challenge quoting is malformed") from exc
        parameters[key] = parsed
        cursor = match.end()
    if value[cursor:].strip(" ,") or not parameters:
        raise PayShProtocolError("payment challenge parameters are malformed")
    return parameters


def _decode_request(value: str) -> dict[str, Any]:
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(f"{value}{padding}")
        payload = json.loads(decoded)
    except (ValueError, json.JSONDecodeError) as exc:
        raise PayShProtocolError("payment request payload is invalid") from exc
    if not isinstance(payload, dict):
        raise PayShProtocolError("payment request payload must be an object")
    return cast(dict[str, Any], payload)


def _required_text(value: Mapping[str, Any], field_name: str) -> str:
    item = value.get(field_name)
    if not isinstance(item, str) or not item:
        raise PayShProtocolError(f"payment {field_name} must be text")
    return item


def _bounded_text(value: str, *, field_name: str, maximum: int) -> str:
    if not value or value != value.strip() or len(value) > maximum:
        raise PayShProtocolError(f"payment {field_name} is invalid")
    return value


def validate_endpoint(endpoint: str) -> str:
    """Require an absolute HTTPS URL without embedded credentials."""

    parsed = urlsplit(endpoint)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise PayShProtocolError("Pay.sh endpoint must be an absolute credential-free HTTPS URL")
    return endpoint


def safe_endpoint(endpoint: str) -> str:
    """Remove query data before an endpoint reaches evidence or logs."""

    parsed = urlsplit(endpoint)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


@dataclass(frozen=True, slots=True)
class PayCommandOutput:
    """Captured non-interactive Pay CLI process result."""

    returncode: int
    stdout: str
    stderr: str


PayCommandRunner = Callable[[Sequence[str], float], PayCommandOutput]


def run_pay_command(arguments: Sequence[str], timeout_seconds: float) -> PayCommandOutput:
    """Run the Pay CLI without a shell and capture output for bounded processing."""

    completed = subprocess.run(
        list(arguments),
        capture_output=True,
        check=False,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
    )
    return PayCommandOutput(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


@dataclass(frozen=True, slots=True)
class PayShSandboxSettlementResult(SettlementResult):
    """Safe evidence computed from one successful real Pay.sh sandbox response."""

    settlement_reference: str
    endpoint: str
    amount: Decimal
    asset: str
    recipient: str
    response_digest: str
    response_bytes: int

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "amount": format_amount(self.amount),
            "asset": self.asset,
            "endpoint": self.endpoint,
            "recipient": self.recipient,
            "response_bytes": self.response_bytes,
            "response_digest": self.response_digest,
            "settlement_reference": self.settlement_reference,
            "settlement_type": PAYSH_SETTLEMENT_TYPE,
        }


class PayShSandboxSettlement:
    """Invoke the official Pay CLI only after the gateway produces ALLOW."""

    def __init__(
        self,
        *,
        endpoint: str,
        pay_executable: str = "pay",
        timeout_seconds: float = 30.0,
        max_response_bytes: int = 1_000_000,
        runner: PayCommandRunner | None = None,
    ) -> None:
        self._endpoint = validate_endpoint(endpoint)
        if not pay_executable.strip():
            raise ValueError("pay_executable must not be empty")
        if timeout_seconds <= 0 or max_response_bytes < 1:
            raise ValueError("Pay.sh execution limits must be positive")
        self._pay_executable = pay_executable
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._runner = runner if runner is not None else run_pay_command

    def settle(
        self,
        request: PaymentRequest,
        authorization: SigningAuthorization,
    ) -> PayShSandboxSettlementResult:
        """Perform one non-interactive ephemeral-wallet sandbox request."""

        arguments = (
            self._pay_executable,
            "--no-dna",
            "--sandbox",
            "fetch",
            self._endpoint,
        )
        try:
            output = self._runner(arguments, self._timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            raise SettlementUnavailable(
                SettlementFailureKind.TIMEOUT,
                settlement_type=PAYSH_SETTLEMENT_TYPE,
            ) from exc
        except OSError as exc:
            raise SettlementUnavailable(
                SettlementFailureKind.COMMAND_FAILED,
                settlement_type=PAYSH_SETTLEMENT_TYPE,
            ) from exc
        if output.returncode != 0:
            raise SettlementUnavailable(
                SettlementFailureKind.COMMAND_FAILED,
                settlement_type=PAYSH_SETTLEMENT_TYPE,
            )
        response = output.stdout.encode("utf-8")
        if not response or len(response) > self._max_response_bytes:
            raise SettlementUnavailable(
                SettlementFailureKind.INVALID_RESPONSE,
                settlement_type=PAYSH_SETTLEMENT_TYPE,
            )
        response_digest = f"sha256:{hashlib.sha256(response).hexdigest()}"
        reference_payload: dict[str, JsonValue] = {
            "authorization_id": authorization.authorization_id,
            "endpoint": safe_endpoint(self._endpoint),
            "request_digest": request.digest,
            "response_digest": response_digest,
            "settlement_type": PAYSH_SETTLEMENT_TYPE,
        }
        reference_digest = hashlib.sha256(
            canonical_json(reference_payload).encode("utf-8")
        ).hexdigest()
        return PayShSandboxSettlementResult(
            settlement_reference=f"paysh:sandbox:sha256:{reference_digest}",
            endpoint=safe_endpoint(self._endpoint),
            amount=request.amount,
            asset=request.asset,
            recipient=request.recipient,
            response_digest=response_digest,
            response_bytes=len(response),
        )


@dataclass(frozen=True, slots=True)
class PayShAttempt:
    """One externally attempted purchase with security and settlement status separated."""

    status: str
    request: PaymentRequest
    outcome: GatewayOutcome

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "decision": self.outcome.result.decision.value,
            "reason_codes": [reason.value for reason in self.outcome.result.reason_codes],
            "request_id": self.request.request_id,
            "settlement": (
                self.outcome.settlement.to_dict() if self.outcome.settlement is not None else None
            ),
            "status": self.status,
        }


def attempt_sandbox_purchase(
    *,
    endpoint: str = PAYSH_SANDBOX_ENDPOINT,
    pay_executable: str = "pay",
    max_payment: str = "0.1",
    timeout_seconds: float = 30.0,
    clock: Callable[[], datetime] | None = None,
    transport: ChallengeTransport | None = None,
    runner: PayCommandRunner | None = None,
) -> PayShAttempt:
    """Probe, canonicalize, secure, and attempt one Pay.sh sandbox purchase."""

    now = (clock or (lambda: datetime.now(UTC)))()
    probe = PayShChallengeProbe(transport)
    requirement = probe.probe(endpoint, timeout_seconds=min(timeout_seconds, 10.0))
    request = requirement.to_payment_request(
        agent_id="paysh-demo-agent",
        mandate_id="paysh-demo-mandate",
        observed_at=now,
    )
    maximum = parse_amount(max_payment, field_name="max_payment")
    mandate = AgentMandate.from_dict(
        {
            "mandate_id": request.mandate_id,
            "agent_id": request.agent_id,
            "purpose": "Pay.sh sandbox demonstration",
            "asset": request.asset,
            "max_single_payment": format_amount(maximum),
            "allowed_recipients": [request.recipient],
            "blocked_recipients": [],
            "valid_from": format_timestamp(now - timedelta(minutes=1)),
            "expires_at": format_timestamp(now + timedelta(minutes=10)),
        }
    )
    settlement = PayShSandboxSettlement(
        endpoint=endpoint,
        pay_executable=pay_executable,
        timeout_seconds=timeout_seconds,
        runner=runner,
    )
    gateway = PaymentGateway(
        policy=MandatePolicyEngine({request.agent_id: mandate}),
        detection=BehaviourEngine(),
        settlement=settlement,
        clock=lambda: now,
    )
    outcome = gateway.process(request)
    if outcome.settlement is not None:
        status = "SETTLED"
    elif ReasonCode.SETTLEMENT_UNAVAILABLE in outcome.result.reason_codes:
        status = "SETTLEMENT_UNAVAILABLE"
    else:
        status = "SECURITY_REJECTED"
    return PayShAttempt(status=status, request=request, outcome=outcome)


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def main(arguments: Sequence[str] | None = None) -> int:
    """Run one documented, non-interactive Pay.sh sandbox purchase attempt."""

    parser = argparse.ArgumentParser(description="Run a Pay.sh sandbox purchase through SolGuard")
    parser.add_argument("--endpoint", default=PAYSH_SANDBOX_ENDPOINT)
    parser.add_argument(
        "--pay-executable",
        default=os.environ.get("SOLGUARD_PAY_EXECUTABLE", "pay"),
    )
    parser.add_argument("--max-payment", default="0.1")
    parser.add_argument("--timeout-seconds", type=_positive_float, default=30.0)
    parsed = parser.parse_args(arguments)
    try:
        attempt = attempt_sandbox_purchase(
            endpoint=parsed.endpoint,
            pay_executable=parsed.pay_executable,
            max_payment=parsed.max_payment,
            timeout_seconds=parsed.timeout_seconds,
        )
    except PayShNetworkError:
        print(json.dumps({"stage": "CHALLENGE_PROBE", "status": "NETWORK_FAILURE"}))
        return 3
    except PayShProtocolError:
        print(json.dumps({"stage": "CHALLENGE_PROBE", "status": "PROTOCOL_FAILURE"}))
        return 3
    print(json.dumps(attempt.to_dict(), separators=(",", ":"), sort_keys=True))
    return 0 if attempt.status == "SETTLED" else 2


if __name__ == "__main__":  # pragma: no cover - exercised through the console entry point
    raise SystemExit(main())
