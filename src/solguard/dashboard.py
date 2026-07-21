"""Local runtime-driven dashboard for the SolGuard demonstration."""

from __future__ import annotations

import argparse
import json
import threading
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import ClassVar, Protocol
from urllib.parse import urlparse

from solguard.audit import AuditEvent, AuditEventStream
from solguard.authorization import WalletAuthorizationGuard
from solguard.contracts import (
    AgentMandate,
    Decision,
    JsonValue,
    PaymentRequest,
    format_amount,
    format_timestamp,
)
from solguard.detection import BehaviourEngine
from solguard.gateway import GatewayOutcome, PaymentGateway
from solguard.policy import MandatePolicyEngine
from solguard.privacy import MetadataSanitizer
from solguard.simulation import SimulatedSettlement


class DashboardStore:
    """Retain bounded runtime events and derive every displayed metric from them."""

    def __init__(self, *, max_events: int = 50) -> None:
        if max_events < 1:
            raise ValueError("max_events must be positive")
        self._max_events = max_events
        self._events: list[AuditEvent] = []

    def ingest(self, event: AuditEvent) -> None:
        """Consume one formal event from the local audit stream."""

        self._events.append(event)
        if len(self._events) > self._max_events:
            self._events = self._events[-self._max_events :]

    def snapshot(
        self,
        *,
        mandate: AgentMandate,
        wallet_balance: Decimal,
    ) -> dict[str, JsonValue]:
        """Compute the complete dashboard state from retained runtime events."""

        allowed = sum(event.decision is Decision.ALLOW for event in self._events)
        approval = sum(event.decision is Decision.REQUIRE_APPROVAL for event in self._events)
        blocked = sum(event.decision is Decision.BLOCK for event in self._events)
        protected_value = sum(
            (event.amount for event in self._events if event.decision is Decision.BLOCK),
            start=Decimal("0"),
        )
        latest_latency = self._events[-1].latency_ms if self._events else None
        return {
            "active_mandate": {
                "agent_id": mandate.agent_id,
                "allowed_recipients": list(mandate.allowed_recipients),
                "asset": mandate.asset,
                "blocked_recipients": list(mandate.blocked_recipients),
                "max_single_payment": format_amount(mandate.max_single_payment),
                "policy_mode": (
                    "STRICT_ALLOWLIST" if mandate.allowed_recipients else "OPEN_WITH_HARD_BLOCKS"
                ),
            },
            "decision_counts": {
                "allowed": allowed,
                "blocked": blocked,
                "require_approval": approval,
                "total": len(self._events),
            },
            "events": [event.dashboard_dict() for event in reversed(self._events)],
            "latest_latency_ms": latest_latency,
            "settlement_type": "SIMULATED",
            "value_protected": format_amount(protected_value),
            "wallet_balance": format_amount(wallet_balance),
        }


class DemoRuntime:
    """Deterministic local scenario controller used by the judge-facing dashboard."""

    AGENT_ID = "demo-agent"
    MANDATE_ID = "demo-mandate"
    NORMAL_RECIPIENT = "weather-api"
    ATTACK_RECIPIENT = "attacker-wallet"

    def __init__(
        self,
        *,
        initial_balance: Decimal = Decimal("1000"),
        start_time: datetime | None = None,
        max_events: int = 50,
        timer_ns: Callable[[], int] | None = None,
    ) -> None:
        if not initial_balance.is_finite() or initial_balance <= 0:
            raise ValueError("initial_balance must be finite and positive")
        self._initial_balance = initial_balance
        self._configured_start_time = start_time
        self._max_events = max_events
        self._timer_ns = timer_ns
        self._lock = threading.RLock()
        self._reset_locked()

    def snapshot(self) -> dict[str, JsonValue]:
        """Return the current computed state without exposing mutable internals."""

        with self._lock:
            return self._store.snapshot(
                mandate=self._mandate,
                wallet_balance=self._settlement.balances[self.AGENT_ID],
            )

    def run_normal(self) -> dict[str, JsonValue]:
        """Run one normal payment through the real local gateway."""

        with self._lock:
            self._process_normal()
            return self.snapshot()

    def run_attack(self) -> dict[str, JsonValue]:
        """Run a deterministic baseline followed by the compound drain attempt."""

        with self._lock:
            while self._clean_seed_count < 3:
                self._process_normal()
            self._observed_at += timedelta(seconds=11)
            for _ in range(5):
                self._process(
                    recipient=self.ATTACK_RECIPIENT,
                    amount="25",
                    metadata={
                        "authorization": "Bearer dashboard-demo-secret",
                        "contact": "attacker@example.com",
                        "scenario": "compound-drain",
                    },
                )
            return self.snapshot()

    def reset(self) -> dict[str, JsonValue]:
        """Reset only local simulated state and return the computed empty snapshot."""

        with self._lock:
            self._reset_locked()
            return self.snapshot()

    def audit_receipts(self) -> dict[str, JsonValue]:
        """Return retained portable receipts for local inspection and reconnect."""

        with self._lock:
            events = self._audit_stream.snapshot()
            return {
                "events": [event.to_dict() for event in events],
                "retained": len(events),
                "valid_chain": AuditEventStream.verify_chain(events),
            }

    def _reset_locked(self) -> None:
        start = self._configured_start_time or datetime.now(UTC)
        if start.tzinfo is None or start.utcoffset() is None:
            raise ValueError("start_time must include a timezone")
        self._observed_at = start.astimezone(UTC)
        self._sequence = 0
        self._clean_seed_count = 0
        self._mandate = AgentMandate.from_dict(
            {
                "mandate_id": self.MANDATE_ID,
                "agent_id": self.AGENT_ID,
                "purpose": "verified API purchase",
                "asset": "USDC",
                "max_single_payment": "100",
                "allowed_recipients": [],
                "blocked_recipients": ["blocked-wallet"],
                "valid_from": format_timestamp(self._observed_at - timedelta(hours=1)),
                "expires_at": format_timestamp(self._observed_at + timedelta(days=1)),
            }
        )
        self._settlement = SimulatedSettlement(
            {self.AGENT_ID: self._initial_balance},
            authorization_guard=WalletAuthorizationGuard(clock=lambda: self._observed_at),
        )
        self._detection = BehaviourEngine()
        self._gateway = PaymentGateway(
            policy=MandatePolicyEngine({self.AGENT_ID: self._mandate}),
            detection=self._detection,
            settlement=self._settlement,
            clock=lambda: self._observed_at,
            timer_ns=self._timer_ns,
        )
        self._sanitizer = MetadataSanitizer()
        self._store = DashboardStore(max_events=self._max_events)
        self._audit_stream = AuditEventStream(max_events=self._max_events)
        self._audit_stream.subscribe(self._store.ingest, replay=False)

    def _process_normal(self) -> None:
        outcome = self._process(
            recipient=self.NORMAL_RECIPIENT,
            amount="10",
            metadata={"scenario": "normal-api-purchase"},
        )
        if outcome.result.decision is Decision.ALLOW:
            self._clean_seed_count += 1

    def _process(
        self,
        *,
        recipient: str,
        amount: str,
        metadata: dict[str, JsonValue],
    ) -> GatewayOutcome:
        self._sequence += 1
        request = PaymentRequest.from_dict(
            {
                "request_id": f"demo-{self._sequence:04d}",
                "agent_id": self.AGENT_ID,
                "mandate_id": self.MANDATE_ID,
                "recipient": recipient,
                "amount": amount,
                "asset": "USDC",
                "purpose": "verified API purchase",
                "nonce": f"demo-nonce-{self._sequence:04d}",
                "created_at": format_timestamp(self._observed_at),
                "expires_at": format_timestamp(self._observed_at + timedelta(minutes=1)),
                "metadata": metadata,
            }
        )
        outcome = self._gateway.process(request)
        sanitized = self._sanitizer.sanitize_payment(request)
        self._audit_stream.publish(
            request=request,
            outcome=outcome,
            mandate=self._mandate,
            sanitized_metadata=sanitized,
        )
        self._observed_at += timedelta(seconds=1)
        return outcome


class DashboardRuntime(Protocol):
    """Operations exposed to the local HTTP handler."""

    def snapshot(self) -> dict[str, JsonValue]: ...

    def run_normal(self) -> dict[str, JsonValue]: ...

    def run_attack(self) -> dict[str, JsonValue]: ...

    def reset(self) -> dict[str, JsonValue]: ...

    def audit_receipts(self) -> dict[str, JsonValue]: ...


class DashboardServer(ThreadingHTTPServer):
    """Threaded local server carrying the isolated demo runtime."""

    def __init__(
        self,
        server_address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        runtime: DashboardRuntime,
    ) -> None:
        super().__init__(server_address, handler)
        self.runtime = runtime


class DashboardRequestHandler(BaseHTTPRequestHandler):
    """Serve static dashboard assets and local scenario endpoints."""

    server: DashboardServer

    _ASSETS: ClassVar[dict[str, tuple[str, str]]] = {
        "/": ("index.html", "text/html; charset=utf-8"),
        "/app.js": ("app.js", "text/javascript; charset=utf-8"),
        "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    }

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/state":
            self._send_json(self.server.runtime.snapshot())
            return
        if path == "/api/audit":
            self._send_json(self.server.runtime.audit_receipts())
            return
        asset = self._ASSETS.get(path)
        if asset is None:
            self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        filename, content_type = asset
        content = resources.files("solguard").joinpath("dashboard_assets", filename).read_bytes()
        self._send_bytes(content, content_type=content_type)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        actions: dict[str, Callable[[], dict[str, JsonValue]]] = {
            "/api/demo/attack": self.server.runtime.run_attack,
            "/api/demo/normal": self.server.runtime.run_normal,
            "/api/demo/reset": self.server.runtime.reset,
        }
        action = actions.get(path)
        if action is None:
            self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        try:
            self._send_json(action())
        except Exception:
            self._send_json(
                {"error": "scenario failed safely"},
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
            )

    def log_message(self, format: str, *args: object) -> None:
        """Keep the judge-facing local process free from request log noise."""

        del format, args

    def _send_json(
        self,
        payload: Mapping[str, JsonValue],
        *,
        status: HTTPStatus = HTTPStatus.OK,
    ) -> None:
        body = json.dumps(
            payload, ensure_ascii=False, allow_nan=False, separators=(",", ":")
        ).encode("utf-8")
        self._send_bytes(
            body,
            content_type="application/json; charset=utf-8",
            status=status,
        )

    def _send_bytes(
        self,
        body: bytes,
        *,
        content_type: str,
        status: HTTPStatus = HTTPStatus.OK,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'")
        self.end_headers()
        self.wfile.write(body)


def create_dashboard_server(
    runtime: DashboardRuntime,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
) -> DashboardServer:
    """Create, but do not start, the local dashboard server."""

    return DashboardServer((host, port), DashboardRequestHandler, runtime)


def main(argv: Sequence[str] | None = None) -> int:  # pragma: no cover - manual entry point
    """Run the local dashboard until interrupted."""

    parser = argparse.ArgumentParser(description="Run the local SolGuard dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8765, type=int)
    args = parser.parse_args(argv)
    server = create_dashboard_server(DemoRuntime(), host=args.host, port=args.port)
    print(f"SolGuard dashboard: http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover - module execution boundary
    raise SystemExit(main())
