"""Tests for the authenticated autonomous payment-intent API."""

from __future__ import annotations

import base64
import http.client
import json
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from http import HTTPStatus
from typing import cast
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from solguard.agent_auth import (
    AgentIdentityRegistry,
    RegisteredAgent,
    public_key_base64,
    sign_agent_request,
)
from solguard.autonomous_api import (
    AGENT_KEY_HEADER,
    AGENT_SIGNATURE_HEADER,
    MAX_REQUEST_BYTES,
    AutonomousApiResult,
    AutonomousDecisionService,
    _ForbiddenSettlement,
    build_autonomous_service,
    create_autonomous_api_server,
)
from solguard.contracts import (
    AgentMandate,
    JsonValue,
    PaymentRequest,
    SigningAuthorization,
)
from solguard.detection import BehaviourEngine
from solguard.gateway import PaymentGateway
from solguard.policy import MandatePolicyEngine, PolicyResult
from solguard.settlement import SettlementResult
from tests.test_contracts import mandate_data, payment_data

NOW = datetime(2026, 7, 25, 10, 0, tzinfo=UTC)
KEY_ID = "research-agent-key-01"


class ForbiddenCountingSettlement:
    def __init__(self) -> None:
        self.attempt_count = 0

    def settle(
        self,
        request: PaymentRequest,
        authorization: SigningAuthorization | None,
    ) -> SettlementResult:
        del request, authorization
        self.attempt_count += 1
        raise AssertionError("decision API reached settlement")


class BrokenPolicy:
    def evaluate(self, request: PaymentRequest) -> PolicyResult:
        del request
        raise RuntimeError("private policy failure")


def payment(**overrides: object) -> PaymentRequest:
    return PaymentRequest.from_dict(payment_data(**overrides))


def mandate(**overrides: object) -> AgentMandate:
    return AgentMandate.from_dict(mandate_data(allowed_recipients=[], **overrides))


def service(
    private_key: Ed25519PrivateKey,
    *,
    active_mandate: AgentMandate | None = None,
    detection: BehaviourEngine | None = None,
    policy: object | None = None,
) -> tuple[AutonomousDecisionService, ForbiddenCountingSettlement]:
    selected_mandate = active_mandate or mandate()
    identities = AgentIdentityRegistry(
        {
            KEY_ID: RegisteredAgent.from_base64(
                agent_id=selected_mandate.agent_id,
                public_key=public_key_base64(private_key),
            )
        }
    )
    settlement = ForbiddenCountingSettlement()
    gateway = PaymentGateway(
        policy=cast(
            MandatePolicyEngine,
            policy
            if policy is not None
            else MandatePolicyEngine({selected_mandate.agent_id: selected_mandate}),
        ),
        detection=detection or BehaviourEngine(),
        settlement=settlement,
        clock=lambda: NOW,
    )
    return (
        AutonomousDecisionService(
            gateway=gateway,
            identities=identities,
            mandates={selected_mandate.agent_id: selected_mandate},
        ),
        settlement,
    )


def signed_evaluation(
    instance: AutonomousDecisionService,
    private_key: Ed25519PrivateKey,
    request: PaymentRequest,
) -> AutonomousApiResult:
    return instance.evaluate(
        cast(Mapping[str, object], request.to_dict()),
        key_id=KEY_ID,
        signature=sign_agent_request(request, key_id=KEY_ID, private_key=private_key),
    )


def test_service_authorizes_without_calling_settlement_and_publishes_receipt() -> None:
    private_key = Ed25519PrivateKey.generate()
    instance, settlement = service(private_key)
    request = payment()

    result = signed_evaluation(instance, private_key, request)

    assert result.status is HTTPStatus.OK
    assert result.payload["decision"] == "ALLOW"
    assert result.payload["execution_state"] == "AUTHORIZED"
    assert result.payload["authorization"] is not None
    assert str(result.payload["audit_receipt_digest"]).startswith("sha256:")
    assert settlement.attempt_count == 0
    event = instance.audit_stream.snapshot()[0]
    assert event.payload["traffic_type"] == "AUTONOMOUS_INTENT"
    assert event.payload["signing_state"] == "AUTHORIZED_NOT_SIGNED"
    assert event.payload["settlement_reference"] is None


def test_service_rejects_invalid_contract_without_audit_or_authorization() -> None:
    private_key = Ed25519PrivateKey.generate()
    instance, settlement = service(private_key)

    result = instance.evaluate(
        payment_data(amount=0.1),
        key_id=KEY_ID,
        signature="not-used",
    )
    fallback = instance.evaluate(
        {"request_id": " bad ", "metadata": object()},
        key_id=KEY_ID,
        signature="not-used",
    )

    assert result.status is HTTPStatus.BAD_REQUEST
    assert result.payload["decision"] == "BLOCK"
    assert result.payload["reason_codes"] == ["REQUEST_INVALID"]
    assert result.payload["authorization"] is None
    assert result.payload["request_id"] == "req_01"
    assert fallback.payload["request_id"] == "bad"
    assert instance.audit_stream.snapshot() == ()
    assert settlement.attempt_count == 0


@pytest.mark.parametrize(
    ("key_id", "signature"),
    [
        ("unknown-key", base64.b64encode(b"x" * 64).decode()),
        (KEY_ID, "invalid-signature"),
        ("", ""),
    ],
)
def test_service_returns_one_generic_authentication_failure(
    key_id: str,
    signature: str,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    instance, settlement = service(private_key)

    result = instance.evaluate(
        cast(Mapping[str, object], payment().to_dict()),
        key_id=key_id,
        signature=signature,
    )

    assert result.status is HTTPStatus.UNAUTHORIZED
    assert result.payload["reason_codes"] == ["AGENT_AUTHENTICATION_FAILED"]
    assert result.payload["authorization"] is None
    assert result.payload["audit_receipt_digest"] is None
    assert instance.audit_stream.snapshot() == ()
    assert settlement.attempt_count == 0


def test_service_quarantines_detection_flag_and_blocks_policy_or_system_failure() -> None:
    private_key = Ed25519PrivateKey.generate()
    engine = BehaviourEngine()
    engine.record_allowed(payment(recipient="weather-api"))
    quarantining, _ = service(private_key, detection=engine)
    policy_blocking, _ = service(private_key, active_mandate=mandate(max_single_payment="1"))
    broken, _ = service(private_key, policy=BrokenPolicy())

    quarantined = signed_evaluation(
        quarantining,
        private_key,
        payment(recipient="new-api"),
    )
    blocked = signed_evaluation(
        policy_blocking,
        private_key,
        payment(amount="2"),
    )
    failed = signed_evaluation(broken, private_key, payment())

    assert quarantined.payload["decision"] == "REQUIRE_APPROVAL"
    assert quarantined.payload["execution_state"] == "QUARANTINED"
    assert quarantined.payload["authorization"] is None
    assert blocked.payload["decision"] == "BLOCK"
    assert blocked.payload["execution_state"] == "BLOCKED"
    assert failed.payload["reason_codes"] == ["SYSTEM_FAILURE"]
    assert all(
        event.payload["signing_state"] == "NOT_SIGNED"
        for instance in (quarantining, policy_blocking, broken)
        for event in instance.audit_stream.snapshot()
    )


def test_service_requires_a_mandate_for_every_registered_agent() -> None:
    private_key = Ed25519PrivateKey.generate()
    identities = AgentIdentityRegistry(
        {
            KEY_ID: RegisteredAgent.from_base64(
                agent_id="research-agent-01",
                public_key=public_key_base64(private_key),
            )
        }
    )
    gateway = PaymentGateway(
        policy=MandatePolicyEngine({}),
        detection=BehaviourEngine(),
        settlement=ForbiddenCountingSettlement(),
        clock=lambda: NOW,
    )

    with pytest.raises(ValueError, match="must have a mandate"):
        AutonomousDecisionService(gateway=gateway, identities=identities, mandates={})


def valid_config(private_key: Ed25519PrivateKey) -> dict[str, object]:
    return {
        "agent_identity": {
            "agent_id": "research-agent-01",
            "key_id": KEY_ID,
            "public_key": public_key_base64(private_key),
        },
        "mandate": mandate().to_dict(),
    }


def test_build_autonomous_service_accepts_public_configuration_only() -> None:
    private_key = Ed25519PrivateKey.generate()
    instance = build_autonomous_service(valid_config(private_key))

    result = signed_evaluation(instance, private_key, payment())

    assert result.payload["decision"] == "ALLOW"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda config: config.update({"extra": {}}),
        lambda config: config.update({"agent_identity": "invalid"}),
        lambda config: cast(dict[str, object], config["agent_identity"]).update(
            {"extra": "invalid"}
        ),
        lambda config: config.update({"mandate": "invalid"}),
        lambda config: cast(dict[str, object], config["agent_identity"]).update({"agent_id": 123}),
        lambda config: cast(dict[str, object], config["mandate"]).update({"amount": "invalid"}),
        lambda config: cast(dict[str, object], config["agent_identity"]).update(
            {"agent_id": "different-agent"}
        ),
    ],
)
def test_build_autonomous_service_rejects_invalid_configuration(
    mutate: Callable[[dict[str, object]], None],
) -> None:
    private_key = Ed25519PrivateKey.generate()
    config = valid_config(private_key)
    mutate(config)

    with pytest.raises(ValueError):
        build_autonomous_service(config)


def test_forbidden_settlement_is_explicit() -> None:
    with pytest.raises(RuntimeError, match="cannot settle"):
        _ForbiddenSettlement().settle(payment(), None)


@contextmanager
def running_server(
    api_service: AutonomousDecisionService,
) -> Iterator[tuple[str, int]]:
    server = create_autonomous_api_server(api_service, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = cast(tuple[str, int], server.server_address)
    try:
        yield host, port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def http_post(
    base: str,
    request: PaymentRequest,
    private_key: Ed25519PrivateKey,
) -> tuple[int, dict[str, JsonValue], Mapping[str, str]]:
    body = json.dumps(request.to_dict(), separators=(",", ":")).encode()
    call = Request(
        f"{base}/v1/payment-intents/evaluate",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            AGENT_KEY_HEADER: KEY_ID,
            AGENT_SIGNATURE_HEADER: sign_agent_request(
                request,
                key_id=KEY_ID,
                private_key=private_key,
            ),
        },
    )
    with urlopen(call, timeout=5) as response:
        return response.status, cast(dict[str, JsonValue], json.load(response)), response.headers


def raw_request(
    host: str,
    port: int,
    *,
    method: str = "POST",
    path: str = "/v1/payment-intents/evaluate",
    headers: Mapping[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, dict[str, JsonValue]]:
    connection = http.client.HTTPConnection(host, port, timeout=5)
    connection.putrequest(method, path)
    for name, value in (headers or {}).items():
        connection.putheader(name, value)
    connection.endheaders(body)
    response = connection.getresponse()
    payload = cast(dict[str, JsonValue], json.loads(response.read()))
    connection.close()
    return response.status, payload


def test_http_server_exposes_health_and_signed_decision_with_security_headers() -> None:
    private_key = Ed25519PrivateKey.generate()
    instance, settlement = service(private_key)

    with running_server(instance) as (host, port):
        base = f"http://{host}:{port}"
        with urlopen(f"{base}/healthz", timeout=5) as health:
            health_payload = json.load(health)
        status, payload, headers = http_post(base, payment(), private_key)

    assert health_payload == {
        "service": "solguard-autonomous-api",
        "settlement_capability": False,
        "status": "ok",
    }
    assert status == 200
    assert payload["decision"] == "ALLOW"
    assert headers["Server"].strip() == "SolGuard"
    assert headers["Cache-Control"] == "no-store"
    assert "default-src 'none'" in headers["Content-Security-Policy"]
    assert settlement.attempt_count == 0


def test_http_server_returns_json_for_missing_routes() -> None:
    private_key = Ed25519PrivateKey.generate()
    instance, _ = service(private_key)

    with running_server(instance) as (host, port):
        base = f"http://{host}:{port}"
        with pytest.raises(HTTPError) as missing_get:
            urlopen(f"{base}/missing", timeout=5)
        missing_post = raw_request(host, port, path="/missing", body=b"")

    assert missing_get.value.code == 404
    assert json.load(missing_get.value) == {"error": "not found"}
    assert missing_post == (404, {"error": "not found"})


@pytest.mark.parametrize(
    ("headers", "body", "expected_status"),
    [
        ({}, None, 415),
        ({"Content-Type": "application/json"}, None, 411),
        ({"Content-Type": "application/json", "Content-Length": "invalid"}, None, 400),
        ({"Content-Type": "application/json", "Content-Length": "0"}, None, 400),
        (
            {
                "Content-Type": "application/json",
                "Content-Length": str(MAX_REQUEST_BYTES + 1),
            },
            None,
            413,
        ),
        (
            {"Content-Type": "application/json", "Content-Length": "2"},
            b"\xff\xff",
            400,
        ),
        (
            {"Content-Type": "application/json", "Content-Length": "1"},
            b"{",
            400,
        ),
    ],
)
def test_http_boundary_rejects_malformed_requests(
    headers: Mapping[str, str],
    body: bytes | None,
    expected_status: int,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    instance, settlement = service(private_key)

    with running_server(instance) as (host, port):
        status, payload = raw_request(host, port, headers=headers, body=body)

    assert status == expected_status
    assert payload["decision"] == "BLOCK"
    assert payload["authorization"] is None
    assert settlement.attempt_count == 0


class BrokenService:
    def evaluate(
        self,
        payload: Mapping[str, object],
        *,
        key_id: str,
        signature: str,
    ) -> AutonomousApiResult:
        del payload, key_id, signature
        raise RuntimeError("private service failure")


def test_http_boundary_fails_closed_on_service_exception() -> None:
    broken = cast(AutonomousDecisionService, BrokenService())
    request = payment()
    body = json.dumps(request.to_dict(), separators=(",", ":")).encode()

    with running_server(broken) as (host, port):
        status, payload = raw_request(
            host,
            port,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
            body=body,
        )

    assert status == 500
    assert payload["reason_codes"] == ["SYSTEM_FAILURE"]
    assert payload["authorization"] is None
