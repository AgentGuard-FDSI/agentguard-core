"""Aprobación humana con separación de funciones y cola de solicitudes pendientes.

Reglas para que una persona apruebe una solicitud HITL (todas deben cumplirse):

  1. No es quien la pidió (no hay autoaprobación).
  2. Existe en el directorio de la organización.
  3. Tiene el nivel más alto de su área (el último de `levels` en policies.yaml; por ejemplo jefe).
  4. Es del área del solicitante, o del área de aprobación final de la organización (gerencia).

Así, un empleado lo aprueba el jefe de su área o gerencia; y si quien pide es el jefe, lo aprueba
otro jefe de su área o gerencia, nunca él mismo.

ApprovalService guarda cada solicitud como PENDING en SQLite, valida a quien decide y registra
la solicitud y la decisión en el log encadenado (agentguard.audit). ValidatingApprover envuelve un
aprobador síncrono (ConsoleApprover, FixedApprover) para que el agente de la Config. B use esas
reglas sin cambiar su flujo.

Fail-closed: si no se puede registrar la decisión, no se aprueba.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .approval import ApprovalRequest, ApprovalResult, Approver
from .audit import AuditChain
from .directory import Directory, normalizar_usuario
from .policy import PolicySet

PENDING, APPROVED, REJECTED, ANULADA = "PENDING", "APPROVED", "REJECTED", "ANULADA"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS solicitudes_hitl (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    run_id        TEXT,
    usuario       TEXT NOT NULL,
    area          TEXT NOT NULL,
    nivel         TEXT NOT NULL,
    tool          TEXT NOT NULL,
    args_json     TEXT NOT NULL,
    motivo        TEXT NOT NULL,
    estado        TEXT NOT NULL CHECK (estado IN ('PENDING', 'APPROVED', 'REJECTED', 'ANULADA')),
    aprobador     TEXT,
    ts_decision   TEXT,
    comentario    TEXT
)
"""


class ApprovalRule(str, Enum):
    """Por qué se denegó una aprobación. Código estable para el audit log y las métricas."""

    AUTOAPROBACION = "autoaprobacion"
    APROBADOR_DESCONOCIDO = "aprobador_desconocido"
    APROBADOR_SIN_RANGO = "aprobador_sin_rango"
    APROBADOR_AJENO_AL_AREA = "aprobador_ajeno_al_area"
    SOLICITUD_NO_EXISTE = "solicitud_no_existe"
    SOLICITUD_YA_DECIDIDA = "solicitud_ya_decidida"


@dataclass(frozen=True)
class StoredApproval:
    id: int
    ts: str
    run_id: str | None
    usuario: str
    area: str
    nivel: str
    tool: str
    arguments: Mapping[str, Any]
    reason: str
    estado: str
    aprobador: str | None = None
    ts_decision: str | None = None
    comentario: str | None = None


def puede_aprobar(
    policy: PolicySet, directory: Directory, solicitante: Any, aprobador: str
) -> tuple[bool, ApprovalRule | None, str]:
    """(ok, regla, motivo): si `aprobador` puede aprobar lo que pidió `solicitante` (usuario, área, nivel)."""
    if normalizar_usuario(aprobador) == normalizar_usuario(solicitante.usuario):
        return False, ApprovalRule.AUTOAPROBACION, "nadie puede aprobar su propia solicitud"
    persona = directory.lookup(aprobador) if isinstance(aprobador, str) else None
    if persona is None:
        return False, ApprovalRule.APROBADOR_DESCONOCIDO, f"el aprobador {aprobador!r} no existe en el directorio"
    nivel_maximo = policy.top_level(persona.area)
    if nivel_maximo is None or persona.nivel != nivel_maximo:
        return False, ApprovalRule.APROBADOR_SIN_RANGO, (
            f"{persona.usuario!r} es {persona.nivel!r} en {persona.area!r}; solo aprueba el nivel más alto del área"
        )
    ultima_instancia = policy.organization.final_approver_area
    if persona.area != solicitante.area and persona.area != ultima_instancia:
        return False, ApprovalRule.APROBADOR_AJENO_AL_AREA, (
            f"{persona.usuario!r} es del área {persona.area!r}; debe ser del área {solicitante.area!r}"
            + (f" o de {ultima_instancia!r}" if ultima_instancia else "")
        )
    return True, None, "aprobador válido"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class ApprovalService:
    """Cola de solicitudes HITL con validación de quien decide. `path` puede ser ":memory:"."""

    def __init__(
        self,
        policy: PolicySet,
        directory: Directory,
        path: str | Path = ":memory:",
        *,
        chain: AuditChain | None = None,
        clock: Callable[[], str] = _utc_now,
    ):
        self._policy = policy
        self._directory = directory
        self._chain = chain
        self._clock = clock
        self._lock = threading.Lock()
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False, timeout=10)
        self._conn.execute(_SCHEMA)

    # ------------------------------------------------------------------
    def solicitar(self, req: ApprovalRequest, *, run_id: str | None = None) -> int:
        """Guarda la solicitud como PENDING y devuelve su id."""
        args_json = json.dumps(dict(req.arguments), sort_keys=True, ensure_ascii=False)
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO solicitudes_hitl (ts, run_id, usuario, area, nivel, tool, args_json, motivo, estado) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING')",
                (self._clock(), run_id, req.usuario, req.area, req.nivel, req.tool, args_json, req.reason),
            )
            solicitud_id = cur.lastrowid
        self._registrar({
            "tipo": "hitl_solicitada", "solicitud": solicitud_id, "run_id": run_id, "usuario": req.usuario,
            "area": req.area, "nivel": req.nivel, "tool": req.tool, "arguments": dict(req.arguments),
        })
        return solicitud_id

    def obtener(self, solicitud_id: int) -> StoredApproval | None:
        with self._lock:
            fila = self._conn.execute("SELECT * FROM solicitudes_hitl WHERE id = ?", (solicitud_id,)).fetchone()
        return self._a_objeto(fila) if fila else None

    def pendientes(self, *, para: str | None = None) -> list[StoredApproval]:
        """Solicitudes PENDING. Con `para`, solo las que ese usuario podría aprobar."""
        with self._lock:
            filas = self._conn.execute("SELECT * FROM solicitudes_hitl WHERE estado = 'PENDING' ORDER BY id").fetchall()
        solicitudes = [self._a_objeto(f) for f in filas]
        if para is None:
            return solicitudes
        return [s for s in solicitudes if puede_aprobar(self._policy, self._directory, s, para)[0]]

    def decidir(self, solicitud_id: int, aprobador: str, aprobar: bool, comentario: str = "") -> ApprovalResult:
        """Aprueba o rechaza. Si `aprobador` no cumple las reglas, la solicitud sigue PENDING."""
        solicitud = self.obtener(solicitud_id)
        if solicitud is None:
            return self._denegada(aprobador, ApprovalRule.SOLICITUD_NO_EXISTE, f"no existe la solicitud {solicitud_id}")
        if solicitud.estado != PENDING:
            return self._denegada(aprobador, ApprovalRule.SOLICITUD_YA_DECIDIDA, f"la solicitud ya está {solicitud.estado}")

        ok, regla, motivo = puede_aprobar(self._policy, self._directory, solicitud, aprobador)
        if not ok:
            self._registrar({
                "tipo": "hitl_intento_rechazado", "solicitud": solicitud_id, "aprobador": aprobador,
                "solicitante": solicitud.usuario, "tool": solicitud.tool, "regla": regla.value, "motivo": motivo,
            })
            return self._denegada(aprobador, regla, motivo)

        persona = self._directory.lookup(aprobador)
        nuevo = APPROVED if aprobar else REJECTED
        # Primero el registro auditable: si no se puede escribir, no se cambia el estado ni se aprueba.
        self._registrar({
            "tipo": "hitl_decidida", "solicitud": solicitud_id, "estado": nuevo, "aprobador": persona.usuario,
            "aprobador_area": persona.area, "aprobador_nivel": persona.nivel, "solicitante": solicitud.usuario,
            "tool": solicitud.tool, "arguments": dict(solicitud.arguments), "comentario": comentario,
        })
        with self._lock:
            cur = self._conn.execute(
                "UPDATE solicitudes_hitl SET estado = ?, aprobador = ?, ts_decision = ?, comentario = ? "
                "WHERE id = ? AND estado = 'PENDING'",
                (nuevo, persona.usuario, self._clock(), comentario, solicitud_id),
            )
        if cur.rowcount != 1:  # otra persona decidió justo antes
            return self._denegada(aprobador, ApprovalRule.SOLICITUD_YA_DECIDIDA, "la solicitud ya fue decidida")
        return ApprovalResult(aprobar, persona.usuario, comentario)

    def anular(self, solicitud_id: int, motivo: str) -> None:
        """Cierra una solicitud que no se va a decidir (sin respuesta, aprobador inválido)."""
        with self._lock:
            self._conn.execute(
                "UPDATE solicitudes_hitl SET estado = 'ANULADA', ts_decision = ?, comentario = ? "
                "WHERE id = ? AND estado = 'PENDING'",
                (self._clock(), motivo, solicitud_id),
            )
        self._registrar({"tipo": "hitl_anulada", "solicitud": solicitud_id, "motivo": motivo})

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------
    def _registrar(self, record: dict[str, Any]) -> None:
        if self._chain is not None:
            self._chain.append(record)

    @staticmethod
    def _denegada(aprobador: str, regla: ApprovalRule, motivo: str) -> ApprovalResult:
        return ApprovalResult(False, aprobador if isinstance(aprobador, str) else "", motivo, regla.value)

    @staticmethod
    def _a_objeto(fila: tuple) -> StoredApproval:
        (id_, ts, run_id, usuario, area, nivel, tool, args_json, motivo, estado, aprobador, ts_decision, comentario) = fila
        return StoredApproval(
            id=id_, ts=ts, run_id=run_id, usuario=usuario, area=area, nivel=nivel, tool=tool,
            arguments=MappingProxyType(json.loads(args_json)), reason=motivo, estado=estado,
            aprobador=aprobador, ts_decision=ts_decision, comentario=comentario,
        )


class ValidatingApprover:
    """Aprobador síncrono que aplica la separación de funciones.

    Envuelve otro aprobador (la consola, uno fijo para pruebas): este responde quién aprueba y si
    aprueba, y la cola valida a esa persona. Si no cumple las reglas, la solicitud se rechaza y el
    resultado trae el código de la regla en `rule`. Cualquier error al registrar rechaza (fail-closed).
    """

    def __init__(self, service: ApprovalService, inner: Approver, *, run_id: str | None = None):
        self._service = service
        self._inner = inner
        self._run_id = run_id

    def request(self, req: ApprovalRequest) -> ApprovalResult:
        try:
            solicitud_id = self._service.solicitar(req, run_id=self._run_id)
        except Exception as exc:  # noqa: BLE001 - si no se puede registrar la solicitud, no se aprueba
            return ApprovalResult(False, "sistema", f"no se pudo registrar la solicitud ({type(exc).__name__})")
        respuesta = self._inner.request(req)
        try:
            if respuesta.approver in ("sin_respuesta", ""):
                self._service.anular(solicitud_id, "sin respuesta del aprobador")
                return ApprovalResult(False, respuesta.approver or "sin_respuesta", "sin respuesta del aprobador")
            resultado = self._service.decidir(solicitud_id, respuesta.approver, respuesta.approved, respuesta.comment)
            if resultado.rule:  # la persona no podía aprobar: la solicitud no queda colgada
                self._service.anular(solicitud_id, resultado.comment)
            return resultado
        except Exception as exc:  # noqa: BLE001
            return ApprovalResult(False, respuesta.approver, f"no se pudo registrar la decisión ({type(exc).__name__})")
