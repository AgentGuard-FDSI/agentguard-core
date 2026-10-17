"""AgentGuard: control de acceso de mínimo privilegio para agentes LLM.

Uso desde el agente (Config. B):

    from agentguard import AgentGuard
    guard = AgentGuard.from_file("config/policies.yaml")
    decision = guard.authorize(session, "eliminar_pedido", {"order_id": "123"})
    # decision.action -> Action.ALLOW | Action.BLOCK | Action.HITL
"""

from .approval import ApprovalRequest, ApprovalResult, Approver, ConsoleApprover, FixedApprover
from .audit import AuditChain, AuditEntry, VerifyResult
from .decision import Decision, Rule
from .directory import Directory, InMemoryDirectory, Person
from .guard import AgentGuard, SessionLike
from .hitl import ApprovalRule, ApprovalService, StoredApproval, ValidatingApprover, puede_aprobar
from .policy import Action, PolicyError, PolicySet, Risk, load_policies

__version__ = "0.3.0"

__all__ = [
    "Action",
    "AgentGuard",
    "ApprovalRequest",
    "ApprovalResult",
    "ApprovalRule",
    "ApprovalService",
    "Approver",
    "AuditChain",
    "AuditEntry",
    "ConsoleApprover",
    "Decision",
    "Directory",
    "FixedApprover",
    "InMemoryDirectory",
    "Person",
    "PolicyError",
    "PolicySet",
    "Risk",
    "Rule",
    "SessionLike",
    "StoredApproval",
    "ValidatingApprover",
    "VerifyResult",
    "load_policies",
    "puede_aprobar",
]
