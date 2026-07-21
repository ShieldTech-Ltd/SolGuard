"""SolGuard pre-signing security gateway."""

from solguard.contracts import AgentMandate, Decision, DecisionResult, PaymentRequest
from solguard.detection import BehaviourEngine, DetectionSignal
from solguard.policy import MandatePolicyEngine

__all__ = [
    "AgentMandate",
    "BehaviourEngine",
    "Decision",
    "DecisionResult",
    "DetectionSignal",
    "MandatePolicyEngine",
    "PaymentRequest",
    "__version__",
]

__version__ = "0.1.0"
