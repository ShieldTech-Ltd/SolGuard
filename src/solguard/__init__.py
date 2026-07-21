"""SolGuard pre-signing security gateway."""

from solguard.audit import AuditEvent, AuditEventStream
from solguard.authorization import InMemoryAuthorizationStore, WalletAuthorizationGuard
from solguard.contracts import AgentMandate, Decision, DecisionResult, PaymentRequest
from solguard.dashboard import DashboardStore, DemoRuntime
from solguard.demo import DemoReport, run_demo
from solguard.detection import BehaviourEngine, DetectionSignal
from solguard.gateway import GatewayOutcome, PaymentGateway, build_simulated_gateway
from solguard.integrity import InMemoryNonceStore, RequestIntegrityGuard
from solguard.paysh import PayShChallengeProbe, PayShSandboxSettlement, attempt_sandbox_purchase
from solguard.policy import MandatePolicyEngine
from solguard.privacy import MetadataSanitizer, RedactionCategory, SanitizationLimits
from solguard.simulation import SimulatedSettlement

__all__ = [
    "AgentMandate",
    "AuditEvent",
    "AuditEventStream",
    "BehaviourEngine",
    "DashboardStore",
    "Decision",
    "DecisionResult",
    "DemoReport",
    "DemoRuntime",
    "DetectionSignal",
    "GatewayOutcome",
    "InMemoryAuthorizationStore",
    "InMemoryNonceStore",
    "MandatePolicyEngine",
    "MetadataSanitizer",
    "PayShChallengeProbe",
    "PayShSandboxSettlement",
    "PaymentGateway",
    "PaymentRequest",
    "RedactionCategory",
    "RequestIntegrityGuard",
    "SanitizationLimits",
    "SimulatedSettlement",
    "WalletAuthorizationGuard",
    "__version__",
    "attempt_sandbox_purchase",
    "build_simulated_gateway",
    "run_demo",
]

__version__ = "0.1.0"
