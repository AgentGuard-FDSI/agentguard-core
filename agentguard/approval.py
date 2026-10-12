"""Aprobación humana (HITL) por consola.

authorize() solo decide; no pregunta nada. Cuando la decisión es HITL, quien llamó arma una
ApprovalRequest y se la pasa a un aprobador. El aprobador se inyecta, para que:

  * en la demostración se pregunte por consola (ConsoleApprover);
  * en las pruebas y en el experimento no haya input() que deje el proceso colgado
    (FixedApprover devuelve siempre la misma respuesta).

AVANCE 3: separación de funciones (el aprobador debe ser un jefe distinto del solicitante, con
gerencia como respaldo), solicitudes PENDING en SQLite y registro en el log encadenado. En el
Avance 2 el aprobador por consola solo pide un nombre y lo devuelve en la respuesta.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol

from .decision import Decision


@dataclass(frozen=True)
class ApprovalRequest:
    """Lo que ve el aprobador: quién pide, qué herramienta, con qué argumentos y por qué se pausó."""

    usuario: str
    area: str
    nivel: str
    tool: str
    arguments: Mapping[str, Any]
    reason: str

    @classmethod
    def from_decision(cls, session: Any, tool: str, arguments: Mapping[str, Any], decision: Decision) -> "ApprovalRequest":
        return cls(
            usuario=session.usuario,
            area=session.area,
            nivel=session.nivel,
            tool=tool,
            arguments=MappingProxyType(dict(arguments)),
            reason=decision.reason,
        )


@dataclass(frozen=True)
class ApprovalResult:
    approved: bool
    approver: str
    comment: str = field(default="")


class Approver(Protocol):
    def request(self, req: ApprovalRequest) -> ApprovalResult: ...


class ConsoleApprover:
    """Pregunta por consola si se aprueba la acción. input_fn y output_fn se pueden inyectar en pruebas."""

    def __init__(self, input_fn: Callable[[str], str] | None = None, output_fn: Callable[[str], None] | None = None):
        # Se resuelven al usarse (no al definir la clase) para poder sustituir input/print en pruebas.
        self._input = input_fn or (lambda prompt: input(prompt))
        self._output = output_fn or (lambda text: print(text))

    def request(self, req: ApprovalRequest) -> ApprovalResult:
        self._output("")
        self._output("=" * 60)
        self._output("APROBACIÓN REQUERIDA (HITL)")
        self._output(f"  Solicitante : {req.usuario} ({req.area}, {req.nivel})")
        self._output(f"  Herramienta : {req.tool}")
        self._output(f"  Argumentos  : {json.dumps(dict(req.arguments), ensure_ascii=False)}")
        self._output(f"  Motivo      : {req.reason}")
        self._output("=" * 60)
        try:
            approver = self._input("Aprobador (usuario): ").strip() or "anonimo"
            return self._ask(approver)
        except (EOFError, KeyboardInterrupt):
            # Nadie puede responder (stdin cerrado o Ctrl-C): ante la duda no se ejecuta.
            self._output("\nSin respuesta del aprobador: solicitud RECHAZADA.")
            return ApprovalResult(False, "sin_respuesta")

    def _ask(self, approver: str) -> ApprovalResult:
        while True:
            answer = self._input("¿Aprobar? [s/n]: ").strip().lower()
            if answer in {"s", "si", "sí", "y", "yes"}:
                return ApprovalResult(True, approver)
            if answer in {"n", "no", ""}:  # vacío = no: ante la duda, no se ejecuta
                return ApprovalResult(False, approver)
            self._output("Responde 's' o 'n'.")


class FixedApprover:
    """Aprobador sin interacción, para pruebas y corridas automáticas: siempre aprueba o siempre rechaza."""

    def __init__(self, approve: bool, approver: str = "aprobador_automatico"):
        self._approve = approve
        self._approver = approver
        self.requests: list[ApprovalRequest] = []

    def request(self, req: ApprovalRequest) -> ApprovalResult:
        self.requests.append(req)
        return ApprovalResult(self._approve, self._approver)
