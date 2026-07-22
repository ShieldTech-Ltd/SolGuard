"""Tests for runtime-derived dashboard state and local HTTP delivery."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from decimal import Decimal
from typing import cast
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from solguard.audit import AuditEventStream
from solguard.contracts import AgentMandate, JsonValue, PaymentRequest
from solguard.dashboard import (
    DashboardRuntime,
    DashboardStore,
    DemoRuntime,
    create_dashboard_server,
    create_seeded_demo_runtime,
)
from solguard.gateway import build_simulated_gateway
from solguard.privacy import MetadataSanitizer
from tests.test_contracts import mandate_data, payment_data

START = datetime(2026, 7, 25, 10, 0, tzinfo=UTC)


def runtime(*, max_events: int = 50) -> DemoRuntime:
    return DemoRuntime(start_time=START, max_events=max_events)


def test_initial_snapshot_contains_only_computed_empty_state() -> None:
    snapshot = runtime().snapshot()

    assert snapshot["decision_counts"] == {
        "allowed": 0,
        "blocked": 0,
        "require_approval": 0,
        "total": 0,
    }
    assert snapshot["events"] == []
    assert snapshot["latest_latency_ms"] is None
    assert snapshot["active_scenario"] == "READY"
    assert snapshot["value_protected"] == "0"
    assert snapshot["wallet_balance"] == "1000"
    assert snapshot["settlement_type"] == "SIMULATED"
    assert snapshot["active_mandate"] == {
        "agent_id": "demo-agent",
        "allowed_recipients": [],
        "asset": "USDC",
        "blocked_recipients": ["blocked-wallet"],
        "max_single_payment": "100",
        "purpose": "verified API purchase",
        "policy_mode": "OPEN_WITH_HARD_BLOCKS",
        "valid_until": "2026-07-26T10:00:00Z",
    }


def test_normal_action_uses_real_gateway_and_settlement_result() -> None:
    snapshot = runtime().run_normal()

    assert snapshot["decision_counts"] == {
        "allowed": 1,
        "blocked": 0,
        "require_approval": 0,
        "total": 1,
    }
    assert snapshot["wallet_balance"] == "990"
    event = cast(list[dict[str, JsonValue]], snapshot["events"])[0]
    assert event["decision"] == "ALLOW"
    assert event["signing_state"] == "SIGNED_SIMULATED"
    assert str(event["settlement_reference"]).startswith("simulated:sha256:")
    assert event["traffic_type"] == "SIMULATED"


def test_stage_runtime_opens_with_one_computed_normal_payment() -> None:
    snapshot = create_seeded_demo_runtime().snapshot()

    assert snapshot["decision_counts"] == {
        "allowed": 1,
        "blocked": 0,
        "require_approval": 0,
        "total": 1,
    }
    assert snapshot["wallet_balance"] == "990"
    assert snapshot["active_scenario"] == "NORMAL_PAYMENT"
    event = cast(list[dict[str, JsonValue]], snapshot["events"])[0]
    assert event["decision"] == "ALLOW"
    assert event["signing_state"] == "SIGNED_SIMULATED"


def test_first_seen_recipient_scenario_requires_approval_without_signing() -> None:
    snapshot = runtime().run_approval_scenario()

    assert snapshot["active_scenario"] == "NEW_RECIPIENT"
    assert snapshot["decision_counts"] == {
        "allowed": 3,
        "blocked": 0,
        "require_approval": 1,
        "total": 4,
    }
    events = cast(list[dict[str, JsonValue]], snapshot["events"])
    latest = events[0]
    assert latest["recipient"] == "market-data-api"
    assert latest["decision"] == "REQUIRE_APPROVAL"
    assert latest["reason_codes"] == ["DETECTION_RECIPIENT_NOVEL"]
    assert latest["signing_state"] == "NOT_SIGNED"
    assert latest["settlement_reference"] is None


def test_replayed_request_scenario_allows_once_then_blocks_exact_replay() -> None:
    snapshot = runtime().run_replay_scenario()

    assert snapshot["active_scenario"] == "REPLAY_ATTACK"
    assert snapshot["decision_counts"] == {
        "allowed": 1,
        "blocked": 1,
        "require_approval": 0,
        "total": 2,
    }
    events = cast(list[dict[str, JsonValue]], snapshot["events"])
    replayed, original = events
    assert replayed["request_id"] == original["request_id"]
    assert original["decision"] == "ALLOW"
    assert replayed["decision"] == "BLOCK"
    assert replayed["reason_codes"] == ["REQUEST_REPLAYED"]
    assert replayed["signing_state"] == "NOT_SIGNED"
    assert replayed["settlement_reference"] is None


def test_attack_action_seeds_baseline_then_blocks_compound_drain() -> None:
    snapshot = runtime().run_attack()

    assert snapshot["decision_counts"] == {
        "allowed": 3,
        "blocked": 1,
        "require_approval": 4,
        "total": 8,
    }
    assert snapshot["wallet_balance"] == "970"
    assert snapshot["value_protected"] == "25"
    assert snapshot["active_scenario"] == "COMPOUND_DRAIN"
    events = cast(list[dict[str, JsonValue]], snapshot["events"])
    latest = events[0]
    assert latest["decision"] == "BLOCK"
    assert latest["signing_state"] == "NOT_SIGNED"
    assert latest["settlement_reference"] is None
    assert "DETECTION_COMPOUND_DRAIN" in cast(list[str], latest["reason_codes"])
    rendered = json.dumps(latest)
    assert "dashboard-demo-secret" not in rendered
    assert "attacker@example.com" not in rendered
    assert "BEARER_TOKEN" in rendered
    assert "EMAIL" in rendered


def test_attack_uses_existing_clean_baseline_without_inventing_seed_events() -> None:
    instance = runtime()
    instance.run_normal()
    instance.run_normal()

    snapshot = instance.run_attack()

    assert cast(dict[str, int], snapshot["decision_counts"])["allowed"] == 3
    assert cast(dict[str, int], snapshot["decision_counts"])["total"] == 8


def test_reset_restores_actual_empty_runtime_state() -> None:
    instance = runtime()
    instance.run_attack()

    snapshot = instance.reset()

    assert cast(dict[str, int], snapshot["decision_counts"])["total"] == 0
    assert snapshot["wallet_balance"] == "1000"
    assert snapshot["value_protected"] == "0"
    assert snapshot["active_scenario"] == "READY"


def test_normal_action_after_attack_does_not_count_as_clean_seed() -> None:
    instance = runtime()
    instance.run_attack()

    snapshot = instance.run_normal()

    counts = cast(dict[str, int], snapshot["decision_counts"])
    assert counts["allowed"] == 3
    assert counts["require_approval"] == 5


def test_demo_runtime_validates_configuration() -> None:
    with pytest.raises(ValueError, match="finite and positive"):
        DemoRuntime(initial_balance=Decimal("0"))
    with pytest.raises(ValueError, match="finite and positive"):
        DemoRuntime(initial_balance=Decimal("NaN"))
    with pytest.raises(ValueError, match="timezone"):
        DemoRuntime(start_time=datetime(2026, 7, 25, 10, 0))


def test_dashboard_store_validates_and_bounds_events() -> None:
    with pytest.raises(ValueError, match="positive"):
        DashboardStore(max_events=0)

    mandate = AgentMandate.from_dict(mandate_data(allowed_recipients=[]))
    payment = PaymentRequest.from_dict(payment_data(amount="1"))
    ticks = iter((1_000_000, 2_000_000))
    gateway = build_simulated_gateway(
        mandates={payment.agent_id: mandate},
        balances={payment.agent_id: Decimal("10")},
        clock=lambda: START,
        timer_ns=lambda: next(ticks),
    )
    outcome = gateway.process(payment)
    sanitizer = MetadataSanitizer()
    store = DashboardStore(max_events=1)
    stream = AuditEventStream(max_events=1)
    stream.subscribe(store.ingest, replay=False)
    stream.publish(
        request=payment,
        outcome=outcome,
        mandate=mandate,
        sanitized_metadata=sanitizer.sanitize_payment(payment),
    )
    stream.publish(
        request=payment,
        outcome=outcome,
        mandate=mandate,
        sanitized_metadata=sanitizer.sanitize_payment(payment),
    )

    snapshot = store.snapshot(mandate=mandate, wallet_balance=Decimal("9"))
    assert cast(dict[str, int], snapshot["decision_counts"])["total"] == 1
    assert len(cast(list[object], snapshot["events"])) == 1


@contextmanager
def running_server(
    server_runtime: DashboardRuntime,
) -> Iterator[str]:
    server = create_dashboard_server(server_runtime, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = cast(tuple[str, int], server.server_address)
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def get(url: str) -> tuple[int, str, Mapping[str, str]]:
    with urlopen(url, timeout=5) as response:
        return response.status, response.read().decode(), response.headers


def post(url: str) -> tuple[int, dict[str, JsonValue]]:
    request = Request(url, data=b"", method="POST")
    with urlopen(request, timeout=5) as response:
        return response.status, cast(dict[str, JsonValue], json.load(response))


@pytest.mark.parametrize(
    ("path", "content_type", "marker"),
    [
        ("/", "text/html", "decision-value"),
        ("/styles.css", "text/css", "--background"),
        ("/app.js", "text/javascript", "renderDecisionSpotlight"),
        ("/favicon.svg", "image/svg+xml", "#27b7ff"),
    ],
)
def test_server_delivers_dashboard_assets(path: str, content_type: str, marker: str) -> None:
    with running_server(runtime()) as base:
        status, body, headers = get(f"{base}{path}")

    assert status == 200
    assert content_type in headers["Content-Type"]
    assert marker in body
    assert headers["Cache-Control"] == "no-store"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert headers["Cross-Origin-Resource-Policy"] == "same-origin"
    assert headers["Permissions-Policy"] == "camera=(), microphone=(), geolocation=()"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Server"].strip() == "SolGuard"


def test_server_exposes_dependency_free_health_check() -> None:
    with running_server(runtime()) as base:
        status, body, headers = get(f"{base}/healthz")

    assert status == 200
    assert json.loads(body) == {
        "service": "solguard-dashboard",
        "settlement": "simulated",
        "status": "ok",
    }
    assert headers["Cache-Control"] == "no-store"


def test_stage_dashboard_packages_visible_enforcement_proof() -> None:
    with running_server(runtime()) as base:
        _, html, _ = get(f"{base}/")
        _, javascript, _ = get(f"{base}/app.js")

    assert "Stop the signature" in html
    assert "AUTONOMOUS SECURITY CONTROL PLANE" in html
    assert "ATTEMPTED VALUE BLOCKED" in html
    assert 'data-action="approval"' in html
    assert 'data-action="replay"' in html
    assert 'data-pipeline="integrity"' in html
    assert 'id="capabilities"' in html
    assert 'id="signer-state"' in html
    assert 'id="settlement-state"' in html
    assert 'id="privacy-state"' in html
    assert 'id="receipt-state"' in html
    assert 'id="audit-dialog"' in html
    assert 'id="guided-demo"' in html
    assert 'id="start-guided-demo"' in html
    assert 'data-guide-action="attack"' in html
    assert "LIVE SECURITY ENGINE" in html
    assert "SIMULATED SETTLEMENT" in html
    assert "No signing authorization reached the wallet" in javascript
    assert "No settlement reference generated" in javascript
    assert "redactionEvidence" in javascript
    assert "renderPipeline" in javascript
    assert "renderAudit" in javascript
    assert "executeGuideScenario" in javascript
    assert "guideStageContent" in javascript
    assert "Guided replay of one live gateway result" in html
    assert "REQUEST_REPLAYED" in javascript


def test_server_state_and_scenario_endpoints_return_runtime_data() -> None:
    with running_server(runtime()) as base:
        status, initial, _ = get(f"{base}/api/state")
        normal_status, normal = post(f"{base}/api/demo/normal")
        audit_status, audit_body, _ = get(f"{base}/api/audit")
        approval_status, approval = post(f"{base}/api/demo/approval")
        replay_status, replay = post(f"{base}/api/demo/replay")
        attack_status, attack = post(f"{base}/api/demo/attack")
        reset_status, reset = post(f"{base}/api/demo/reset")

    assert status == 200
    assert json.loads(initial)["decision_counts"]["total"] == 0
    assert normal_status == approval_status == replay_status == attack_status == reset_status == 200
    assert cast(dict[str, int], normal["decision_counts"])["total"] == 1
    normal_event = cast(list[dict[str, JsonValue]], normal["events"])[0]
    assert str(normal_event["request_digest"]).startswith("sha256:")
    assert str(normal_event["policy_version"]).startswith("sha256:")
    assert approval["active_scenario"] == "NEW_RECIPIENT"
    assert cast(dict[str, int], approval["decision_counts"])["require_approval"] == 1
    assert replay["active_scenario"] == "REPLAY_ATTACK"
    assert cast(dict[str, int], replay["decision_counts"])["blocked"] == 1
    audit = json.loads(audit_body)
    assert audit_status == 200
    assert audit["retained"] == 1
    assert audit["valid_chain"] is True
    assert audit["events"][0]["receipt_digest"].startswith("sha256:")
    assert cast(dict[str, int], attack["decision_counts"])["blocked"] == 1
    assert cast(dict[str, int], reset["decision_counts"])["total"] == 0


@pytest.mark.parametrize(("method", "path"), [("GET", "/missing"), ("POST", "/api/demo/missing")])
def test_server_returns_json_not_found(method: str, path: str) -> None:
    with running_server(runtime()) as base:
        request = Request(f"{base}{path}", data=b"" if method == "POST" else None, method=method)
        with pytest.raises(HTTPError) as caught:
            urlopen(request, timeout=5)

    assert caught.value.code == 404
    assert json.load(caught.value) == {"error": "not found"}


class BrokenRuntime:
    def snapshot(self) -> dict[str, JsonValue]:
        return {}

    def run_normal(self) -> dict[str, JsonValue]:
        raise RuntimeError("private failure")

    def run_attack(self) -> dict[str, JsonValue]:
        return {}

    def run_normal_scenario(self) -> dict[str, JsonValue]:
        raise RuntimeError("private failure")

    def run_approval_scenario(self) -> dict[str, JsonValue]:
        return {}

    def run_replay_scenario(self) -> dict[str, JsonValue]:
        return {}

    def run_attack_scenario(self) -> dict[str, JsonValue]:
        return {}

    def reset(self) -> dict[str, JsonValue]:
        return {}

    def audit_receipts(self) -> dict[str, JsonValue]:
        return {"events": [], "retained": 0, "valid_chain": True}


def test_server_scenario_failure_is_generic() -> None:
    with running_server(BrokenRuntime()) as base:
        request = Request(f"{base}/api/demo/normal", data=b"", method="POST")
        with pytest.raises(HTTPError) as caught:
            urlopen(request, timeout=5)

    assert caught.value.code == 500
    assert json.load(caught.value) == {"error": "scenario failed safely"}
