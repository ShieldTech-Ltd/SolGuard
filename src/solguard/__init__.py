"""SolGuard pre-signing security gateway."""

from solguard.contracts import AgentMandate, Decision, DecisionResult, PaymentRequest
from solguard.detection import BehaviourEngine, DetectionSignal
from solguard.gateway import GatewayOutcome, PaymentGateway, build_simulated_gateway
from solguard.policy import MandatePolicyEngine
from solguard.simulation import SimulatedSettlement

__all__ = [
    "AgentMandate",
    "BehaviourEngine",
    "Decision",
    "DecisionResult",
    "DetectionSignal",
    "GatewayOutcome",
    "MandatePolicyEngine",
    "PaymentGateway",
    "PaymentRequest",
    "SimulatedSettlement",
    "__version__",
    "build_simulated_gateway",
]

__version__ = "0.1.0"
