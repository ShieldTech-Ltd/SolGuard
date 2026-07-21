"""SolGuard pre-signing security gateway."""

from solguard.audit import AuditEvent, AuditEventStream
from solguard.contracts import AgentMandate, Decision, DecisionResult, PaymentRequest
from solguard.dashboard import DashboardStore, DemoRuntime
from solguard.detection import BehaviourEngine, DetectionSignal
from solguard.gateway import GatewayOutcome, PaymentGateway, build_simulated_gateway
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
    "DemoRuntime",
    "DetectionSignal",
    "GatewayOutcome",
    "MandatePolicyEngine",
    "MetadataSanitizer",
    "PaymentGateway",
    "PaymentRequest",
    "RedactionCategory",
    "SanitizationLimits",
    "SimulatedSettlement",
    "__version__",
    "build_simulated_gateway",
]

__version__ = "0.1.0"
