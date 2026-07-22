"""Authenticated decision-only HTTP API for autonomous payment intents."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar, cast
from urllib.parse import urlparse

from solguard.agent_auth import (
    AgentAuthenticationError,
    AgentIdentityRegistry,
    RegisteredAgent,
)
from solguard.audit import AuditEventStream
from solguard.contracts import (
    AgentMandate,
    ContractValidationError,
    Decision,
    DecisionResult,
    JsonValue,
    PaymentRequest,
    ReasonCode,
    SigningAuthorization,
    canonical_json,
    contract_from_json,
)
from solguard.detection import BehaviourEngine
from solguard.gateway import PaymentGateway
from solguard.policy import MandatePolicyEngine
from solguard.privacy import MetadataSanitizer
from solguard.settlement import SettlementResult

API_VERSION = "1"
AGENT_KEY_HEADER = "X-SolGuard-Key-Id"
AGENT_SIGNATURE_HEADER = "X-SolGuard-Signature"
MAX_REQUEST_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class AutonomousApiResult:
    """One HTTP-safe decision response without a settlement operation."""

    status: HTTPStatus
    payload: Mapping[str, JsonValue]


class AutonomousDecisionService:
    """Authenticate an agent, evaluate its intent, and emit sanitized evidence."""

    def __init__(
        self,
        *,
        gateway: PaymentGateway,
        identities: AgentIdentityRegistry,
        mandates: Mapping[str, AgentMandate],
        audit_stream: AuditEventStream | None = None,
        sanitizer: MetadataSanitizer | None = None,
    ) -> None:
        validated_mandates = dict(mandates)
        missing = identities.agent_ids - validated_mandates.keys()
        if missing:
            raise ValueError("every registered agent must have a mandate")
        self._gateway = gateway
        self._identities = identities
        self._mandates = validated_mandates
        self._audit_stream = audit_stream or AuditEventStream()
        self._sanitizer = sanitizer or MetadataSanitizer()

    @property
    def audit_stream(self) -> AuditEventStream:
        """Expose the existing event stream to trusted in-process observers."""

        return self._audit_stream

    def evaluate(
        self,
        payload: Mapping[str, object],
        *,
        key_id: str,
        signature: str,
    ) -> AutonomousApiResult:
        """Return a fail-closed decision for one authenticated canonical request."""

        try:
            request = PaymentRequest.from_dict(payload)
        except (ContractValidationError, KeyError, TypeError, ValueError):
            result = _blocked_result(
                payload,
                reason=ReasonCode.REQUEST_INVALID,
                stage="CONTRACT_VALIDATION",
            )
            return AutonomousApiResult(
                status=HTTPStatus.BAD_REQUEST,
                payload=_response_payload(result, receipt_digest=None),
            )

        try:
            self._identities.verify(request, key_id=key_id, signature=signature)
        except AgentAuthenticationError:
            result = DecisionResult.create(
                request_id=request.request_id,
                decision=Decision.BLOCK,
                reason_codes=(ReasonCode.AGENT_AUTHENTICATION_FAILED,),
                request_digest=request.digest,
                evidence={"stage": "AGENT_AUTHENTICATION"},
            )
            return AutonomousApiResult(
                status=HTTPStatus.UNAUTHORIZED,
                payload=_response_payload(result, receipt_digest=None),
            )

        outcome = self._gateway.evaluate(request)
        mandate = self._mandates[request.agent_id]
        event = self._audit_stream.publish(
            request=request,
            outcome=outcome,
            mandate=mandate,
            sanitized_metadata=self._sanitizer.sanitize_payment(request),
            signing_state=(
                "AUTHORIZED_NOT_SIGNED"
                if outcome.result.decision is Decision.ALLOW
                else "NOT_SIGNED"
            ),
            traffic_type="AUTONOMOUS_INTENT",
        )
        return AutonomousApiResult(
            status=HTTPStatus.OK,
            payload=_response_payload(outcome.result, receipt_digest=event.receipt_digest),
        )


def _response_payload(
    result: DecisionResult,
    *,
    receipt_digest: str | None,
) -> dict[str, JsonValue]:
    execution_state = {
        Decision.ALLOW: "AUTHORIZED",
        Decision.REQUIRE_APPROVAL: "QUARANTINED",
        Decision.BLOCK: "BLOCKED",
    }[result.decision]
    return {
        "api_version": API_VERSION,
        "audit_receipt_digest": receipt_digest,
        "authorization": (
            cast(JsonValue, result.authorization.to_dict())
            if result.authorization is not None
            else None
        ),
        "decision": result.decision.value,
        "evidence": cast(JsonValue, dict(result.evidence)),
        "execution_state": execution_state,
        "reason_codes": [reason.value for reason in result.reason_codes],
        "request_digest": result.request_digest,
        "request_id": result.request_id,
    }


def _blocked_result(
    payload: Mapping[str, object],
    *,
    reason: ReasonCode,
    stage: str,
) -> DecisionResult:
    request_id = payload.get("request_id")
    safe_request_id = (
        request_id.strip()[:128]
        if isinstance(request_id, str) and request_id.strip()
        else "unparsed"
    )
    try:
        material = canonical_json(cast(Mapping[str, JsonValue], payload)).encode("utf-8")
    except (TypeError, ValueError):
        material = type(payload).__name__.encode("utf-8")
    digest = f"sha256:{hashlib.sha256(material).hexdigest()}"
    return DecisionResult.create(
        request_id=safe_request_id,
        decision=Decision.BLOCK,
        reason_codes=(reason,),
        request_digest=digest,
        evidence={"stage": stage},
    )


class AutonomousApiServer(ThreadingHTTPServer):
    """Threaded HTTP server carrying one isolated decision service."""

    def __init__(
        self,
        server_address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        service: AutonomousDecisionService,
    ) -> None:
        super().__init__(server_address, handler)
        self.service = service


class AutonomousApiRequestHandler(BaseHTTPRequestHandler):
    """Expose the decision service without any signing or settlement route."""

    server: AutonomousApiServer
    server_version = "SolGuard"
    sys_version = ""

    _SECURITY_HEADERS: ClassVar[dict[str, str]] = {
        "Cache-Control": "no-store",
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    }

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/healthz":
            self._send_json(
                HTTPStatus.OK,
                {
                    "service": "solguard-autonomous-api",
                    "settlement_capability": False,
                    "status": "ok",
                },
            )
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/v1/payment-intents/evaluate":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if self.headers.get_content_type() != "application/json":
            self._send_json(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                _safe_failure_payload(ReasonCode.REQUEST_INVALID),
            )
            return
        length = self._content_length()
        if length is None:
            return
        try:
            raw = self.rfile.read(length).decode("utf-8", errors="strict")
            payload = contract_from_json(raw)
        except (ContractValidationError, UnicodeDecodeError):
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                _safe_failure_payload(ReasonCode.REQUEST_INVALID),
            )
            return
        key_id = self.headers.get(AGENT_KEY_HEADER, "")
        signature = self.headers.get(AGENT_SIGNATURE_HEADER, "")
        try:
            result = self.server.service.evaluate(
                cast(Mapping[str, object], payload),
                key_id=key_id,
                signature=signature,
            )
        except Exception:
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                _safe_failure_payload(ReasonCode.SYSTEM_FAILURE),
            )
            return
        self._send_json(result.status, result.payload)

    def log_message(self, format: str, *args: object) -> None:
        """Avoid logging signed request headers or payment metadata."""

        del format, args

    def _content_length(self) -> int | None:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            self._send_json(
                HTTPStatus.LENGTH_REQUIRED,
                _safe_failure_payload(ReasonCode.REQUEST_INVALID),
            )
            return None
        try:
            length = int(raw_length)
        except ValueError:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                _safe_failure_payload(ReasonCode.REQUEST_INVALID),
            )
            return None
        if length < 1:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                _safe_failure_payload(ReasonCode.REQUEST_INVALID),
            )
            return None
        if length > MAX_REQUEST_BYTES:
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                _safe_failure_payload(ReasonCode.REQUEST_INVALID),
            )
            return None
        return length

    def _send_json(
        self,
        status: HTTPStatus,
        payload: Mapping[str, JsonValue],
    ) -> None:
        body = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name, value in self._SECURITY_HEADERS.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)


def _safe_failure_payload(reason: ReasonCode) -> dict[str, JsonValue]:
    return {
        "api_version": API_VERSION,
        "audit_receipt_digest": None,
        "authorization": None,
        "decision": Decision.BLOCK.value,
        "evidence": {"stage": "HTTP_BOUNDARY"},
        "execution_state": "BLOCKED",
        "reason_codes": [reason.value],
        "request_digest": None,
        "request_id": "unparsed",
    }


class _ForbiddenSettlement:
    """Make accidental settlement from the decision API an explicit failure."""

    def settle(
        self,
        request: PaymentRequest,
        authorization: SigningAuthorization | None,
    ) -> SettlementResult:
        del request, authorization
        raise RuntimeError("the autonomous decision API cannot settle payments")


def build_autonomous_service(config: Mapping[str, object]) -> AutonomousDecisionService:
    """Build one single-agent demonstration service from validated public configuration."""

    if set(config) != {"agent_identity", "mandate"}:
        raise ValueError("configuration must contain agent_identity and mandate")
    raw_identity = config["agent_identity"]
    raw_mandate = config["mandate"]
    if not isinstance(raw_identity, dict) or set(raw_identity) != {
        "agent_id",
        "key_id",
        "public_key",
    }:
        raise ValueError("agent_identity fields are invalid")
    if not isinstance(raw_mandate, dict):
        raise ValueError("mandate must be an object")
    agent_id = raw_identity["agent_id"]
    key_id = raw_identity["key_id"]
    public_key = raw_identity["public_key"]
    if not all(isinstance(item, str) for item in (agent_id, key_id, public_key)):
        raise ValueError("agent_identity values must be strings")
    mandate = AgentMandate.from_dict(raw_mandate)
    if mandate.agent_id != agent_id:
        raise ValueError("agent identity and mandate agent_id must match")
    registered = RegisteredAgent.from_base64(
        agent_id=cast(str, agent_id),
        public_key=cast(str, public_key),
    )
    identities = AgentIdentityRegistry({cast(str, key_id): registered})
    mandates = {mandate.agent_id: mandate}
    gateway = PaymentGateway(
        policy=MandatePolicyEngine(mandates),
        detection=BehaviourEngine(),
        settlement=_ForbiddenSettlement(),
    )
    return AutonomousDecisionService(
        gateway=gateway,
        identities=identities,
        mandates=mandates,
    )


def create_autonomous_api_server(
    service: AutonomousDecisionService,
    *,
    host: str = "127.0.0.1",
    port: int = 8780,
) -> AutonomousApiServer:
    """Create, but do not start, the autonomous decision server."""

    return AutonomousApiServer((host, port), AutonomousApiRequestHandler, service)


def main(argv: Sequence[str] | None = None) -> int:  # pragma: no cover - manual boundary
    """Run the autonomous decision API from a public-key-only configuration."""

    parser = argparse.ArgumentParser(description="Run the SolGuard autonomous decision API")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8780, type=int)
    args = parser.parse_args(argv)
    try:
        config = contract_from_json(args.config.read_text(encoding="utf-8"))
        service = build_autonomous_service(cast(Mapping[str, object], config))
    except (OSError, ContractValidationError, ValueError) as exc:
        parser.error(str(exc))
    server = create_autonomous_api_server(service, host=args.host, port=args.port)
    print(f"SolGuard autonomous decision API: http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover - module execution boundary
    raise SystemExit(main())
