"""AgentGuard: control de acceso de mínimo privilegio para agentes LLM.

Uso desde el agente (Config. B):

    from agentguard import AgentGuard
    guard = AgentGuard.from_file("config/policies.yaml")
    decision = guard.authorize(session, "eliminar_pedido", {"order_id": "123"})
    # decision.action -> Action.ALLOW | Action.BLOCK | Action.HITL

Antes del agente, el verificador de entrada (InputGuard) revisa el prompt; después de authorize(),
la regla entre áreas (CrossAreaMonitor) observa los BLOCK. Ver docs/arquitectura.md.
"""

from .approval import ApprovalRequest, ApprovalResult, Approver, ConsoleApprover, FixedApprover
from .audit import AuditChain, AuditEntry, VerifyResult
from .cross_area import CrossAreaEvent, CrossAreaMonitor
from .decision import Decision, Rule
from .directory import Directory, InMemoryDirectory, Person
from .guard import AgentGuard, SessionLike
from .hitl import ApprovalRule, ApprovalService, StoredApproval, ValidatingApprover, puede_aprobar
from .input_guard import InputGuard, InputVerdict, LabeledPrompt
from .notify import (
    AuditNotifier,
    ConsoleNotifier,
    InMemoryNotifier,
    MultiNotifier,
    Notification,
    NotificationKind,
    Notifier,
    Priority,
)
from .policy import Action, PolicyError, PolicySet, Risk, load_policies

__version__ = "0.4.0"

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
    "AuditNotifier",
    "ConsoleApprover",
    "ConsoleNotifier",
    "CrossAreaEvent",
    "CrossAreaMonitor",
    "Decision",
    "Directory",
    "FixedApprover",
    "InMemoryDirectory",
    "InMemoryNotifier",
    "InputGuard",
    "InputVerdict",
    "LabeledPrompt",
    "MultiNotifier",
    "Notification",
    "NotificationKind",
    "Notifier",
    "Person",
    "PolicyError",
    "PolicySet",
    "Priority",
    "Risk",
    "Rule",
    "SessionLike",
    "StoredApproval",
    "ValidatingApprover",
    "VerifyResult",
    "load_policies",
    "puede_aprobar",
]
