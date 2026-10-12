"""AgentGuard: control de acceso de mínimo privilegio para agentes LLM.

Uso desde el agente (Config. B):

    from agentguard import AgentGuard
    guard = AgentGuard.from_file("config/policies.yaml")
    decision = guard.authorize(session, "eliminar_pedido", {"order_id": "123"})
    # decision.action -> Action.ALLOW | Action.BLOCK | Action.HITL
"""

from .approval import ApprovalRequest, ApprovalResult, Approver, ConsoleApprover, FixedApprover
from .decision import Decision, Rule
from .guard import AgentGuard, SessionLike
from .policy import Action, PolicyError, PolicySet, Risk, load_policies

__version__ = "0.2.0"

__all__ = [
    "Action",
    "AgentGuard",
    "ApprovalRequest",
    "ApprovalResult",
    "Approver",
    "ConsoleApprover",
    "Decision",
    "FixedApprover",
    "PolicyError",
    "PolicySet",
    "Risk",
    "Rule",
    "SessionLike",
    "load_policies",
]
