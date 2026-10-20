"""Resultado de AgentGuard.authorize(): la acción, su motivo y la regla que la produjo."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .policy import Action


class Rule(str, Enum):
    """Regla que produjo la decisión. Es un código estable para el audit log y las métricas."""

    ARGUMENTOS_INVALIDOS = "argumentos_invalidos"
    HERRAMIENTA_NO_DECLARADA = "herramienta_no_declarada"
    SESION_INVALIDA = "sesion_invalida"
    AREA_NO_DECLARADA = "area_no_declarada"
    NIVEL_NO_DECLARADO = "nivel_no_declarado"
    FUERA_DE_ROL = "fuera_de_rol"
    ARGUMENTO_INVALIDO = "argumento_invalido"
    TABLA_NO_PERMITIDA = "tabla_no_permitida"
    DESTINATARIO_NO_PERMITIDO = "destinatario_no_permitido"
    LOTE_EXCEDIDO = "lote_excedido"
    ACCION_BASE = "accion_base"
    ERROR_INTERNO = "error_interno"


@dataclass(frozen=True)
class Decision:
    """Decisión de AgentGuard sobre una llamada a herramienta.

    action: ALLOW (ejecutar), BLOCK (rechazar) o HITL (pausar hasta que una persona apruebe).
    reason: motivo legible para la persona y para el audit log.
    rule:   código de la regla que decidió (ver Rule).
    """

    action: Action
    reason: str
    rule: Rule

    @property
    def allowed(self) -> bool:
        return self.action is Action.ALLOW

    @property
    def blocked(self) -> bool:
        return self.action is Action.BLOCK

    @property
    def needs_approval(self) -> bool:
        return self.action is Action.HITL

    def to_dict(self) -> dict[str, str]:
        """Forma serializable (JSON) para el audit log: {"action": "BLOCK", "rule": "fuera_de_rol", "reason": "..."}.

        Solo trae la decisión. Quien registra (el agente de la Config. B) agrega el contexto: marca de
        tiempo, run_id, usuario, área, nivel, herramienta y argumentos.
        """
        return {"action": self.action.value, "rule": self.rule.value, "reason": self.reason}

    def __str__(self) -> str:
        return f"{self.action.value} [{self.rule.value}] {self.reason}"
