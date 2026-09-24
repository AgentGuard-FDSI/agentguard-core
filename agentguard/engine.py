from dataclasses import dataclass
from enum import Enum


class Decision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    HITL = "HITL"


@dataclass(frozen=True)
class Session:
    user: str
    area: str
    level: str


@dataclass(frozen=True)
class Verdict:
    decision: Decision
    reason: str


class AgentGuard:
    def __init__(self, policy: dict):
        self.policy = policy

    @classmethod
    def from_yaml(cls, path: str) -> "AgentGuard":
        from agentguard.policy import load_policy

        return cls(load_policy(path))

    def authorize(self, session: Session, tool: str, arguments: dict) -> Verdict:
        raise NotImplementedError("Avance 2: evaluar area, herramienta y argumentos contra la politica")
