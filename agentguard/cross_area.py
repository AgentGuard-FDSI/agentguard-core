"""Regla de acceso entre áreas: avisa al área dueña de un recurso cuando otra área lo pide, y alerta
a Tecnología si el mismo usuario insiste (posible cuenta comprometida).

Es una regla estática, sin aprendizaje: no decide nada nuevo. La acción ya es BLOCK (la tomó
authorize() o el verificador de entrada); esta regla observa ese bloqueo y, si el recurso es propio
de otra área, notifica. Así authorize() sigue siendo puro y la regla se puede apagar sin cambiar
ninguna decisión.

Qué cuenta como recurso de otra área (con la política de ANDIMARKET):

  * una herramienta fuera de rol (regla fuera_de_rol): sus dueñas son las áreas que la tienen.
    Atención al cliente pidiendo admin_action -> dueña tecnologia_ti.
  * una tabla no permitida (regla tabla_no_permitida): sus dueñas son las áreas que la tienen en
    table_by_area. Finanzas pidiendo config_ti -> dueña tecnologia_ti.
  * un tema del verificador de entrada con área dueña (verificador_entrada.area_propietaria).
    Finanzas preguntando por la configuración de los servidores -> dueña tecnologia_ti.

Un recurso que no es de ninguna área (por ejemplo la tabla clientes, que ninguna área lee con
leer_base_datos) se bloquea igual, pero no es "acceso entre áreas" y no se cuenta aquí.

Conteo: por usuario, en una ventana deslizante de `ventana_minutos`. Al llegar a `intentos` se emite
UNA alerta prioritaria a `notificar_alerta` y el conteo vuelve a cero, para no repetir la alerta en
cada intento siguiente; si el usuario insiste otras `intentos` veces, se emite otra.

    monitor = CrossAreaMonitor.from_file("config/policies.yaml", notifier=notificador)
    decision = guard.authorize(session, tool, arguments)
    evento = monitor.observe_decision(session, tool, arguments, decision)   # después de authorize()
    evento = monitor.observe_input(session, veredicto)                      # después del verificador

Nunca lanza excepciones: un fallo al observar o al notificar no cambia la decisión, que ya es BLOCK.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .decision import Decision, Rule
from .directory import normalizar_usuario
from .guard import ARG_TABLA
from .notify import Notification, NotificationKind, Notifier, Priority, entregar
from .policy import Action, PolicySet, load_policies

_MAX_USUARIOS_EN_MEMORIA = 10_000


@dataclass(frozen=True)
class CrossAreaEvent:
    """Lo que observó la regla.

    violation:          True si se pidió un recurso propio de otra área.
    resource:           "herramienta:admin_action", "tabla:config_ti" o "tema:config_interna".
    owner_areas:        áreas dueñas del recurso (a las que se notificó).
    attempts_in_window: intentos del usuario dentro de la ventana, contando este.
    alert:              True si este intento disparó la alerta prioritaria.
    """

    violation: bool
    resource: str = ""
    owner_areas: tuple[str, ...] = ()
    attempts_in_window: int = 0
    alert: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "violation": self.violation,
            "resource": self.resource,
            "owner_areas": list(self.owner_areas),
            "attempts_in_window": self.attempts_in_window,
            "alert": self.alert,
        }


NO_VIOLATION = CrossAreaEvent(False)


class CrossAreaMonitor:
    """Regla de acceso entre áreas configurada desde policies.yaml (sección regla_entre_areas).

    clock: función que devuelve segundos (por defecto time.monotonic). Se inyecta en las pruebas
    para simular el paso de los minutos sin esperar.
    """

    def __init__(
        self,
        policy: PolicySet,
        *,
        notifier: Notifier | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        if not isinstance(policy, PolicySet):
            raise TypeError("CrossAreaMonitor necesita un PolicySet ya validado (usar load_policies)")
        self._policy = policy
        self._config = policy.cross_area
        self._notifier = notifier
        self._clock = clock
        self._intentos: OrderedDict[str, deque[tuple[float, str]]] = OrderedDict()
        self._lock = threading.Lock()
        self.fallos_de_notificacion = 0
        self.errores = 0

    @classmethod
    def from_file(
        cls, path: str | Path, *, notifier: Notifier | None = None, clock: Callable[[], float] = time.monotonic
    ) -> "CrossAreaMonitor":
        return cls(load_policies(path), notifier=notifier, clock=clock)

    @property
    def enabled(self) -> bool:
        return self._config.enabled

    # ------------------------------------------------------------------
    def observe_decision(
        self, session: Any, tool: str, arguments: Mapping[str, Any], decision: Decision, *, run_id: str | None = None
    ) -> CrossAreaEvent:
        """Observa una decisión de authorize(). Solo los BLOCK por fuera de rol o tabla cuentan."""
        try:
            if not self._config.enabled or not isinstance(decision, Decision) or decision.action is not Action.BLOCK:
                return NO_VIOLATION
            area = getattr(session, "area", None)
            recurso, duenas = self._duenas_de_decision(area, tool, arguments, decision)
            if not duenas:
                return NO_VIOLATION
            return self._registrar(session, recurso, duenas, {"run_id": run_id, "tool": tool, "regla": decision.rule.value})
        except Exception:  # noqa: BLE001 - la decisión ya es BLOCK; un fallo aquí no la cambia
            self.errores += 1
            return NO_VIOLATION

    def observe_input(self, session: Any, verdict: Any, *, run_id: str | None = None) -> CrossAreaEvent:
        """Observa un veredicto del verificador de entrada. Cuenta los REJECT de temas de otra área."""
        try:
            if not self._config.enabled or not getattr(verdict, "rejected", False):
                return NO_VIOLATION
            area = getattr(session, "area", None)
            owners: Mapping[str, str] = getattr(verdict, "owner_areas", {}) or {}
            temas = [t for t, dueña in owners.items() if dueña != area]
            duenas = tuple(sorted({owners[t] for t in temas}))
            if not duenas:
                return NO_VIOLATION
            recurso = "tema:" + ",".join(temas)
            return self._registrar(session, recurso, duenas, {"run_id": run_id, "origen": "verificador_entrada"})
        except Exception:  # noqa: BLE001
            self.errores += 1
            return NO_VIOLATION

    def attempts(self, usuario: str) -> int:
        """Intentos del usuario dentro de la ventana actual (después de la última alerta)."""
        with self._lock:
            cola = self._intentos.get(normalizar_usuario(usuario))
            if not cola:
                return 0
            self._podar(cola, self._clock())
            return len(cola)

    # ------------------------------------------------------------------
    def _duenas_de_decision(
        self, area: Any, tool: str, arguments: Mapping[str, Any], decision: Decision
    ) -> tuple[str, tuple[str, ...]]:
        tool_policy = self._policy.get_tool(tool) if isinstance(tool, str) else None
        if tool_policy is None:
            return "", ()
        if decision.rule is Rule.FUERA_DE_ROL:
            return f"herramienta:{tool}", tuple(sorted(a for a in tool_policy.areas if a != area))
        if decision.rule is Rule.TABLA_NO_PERMITIDA:
            tabla = arguments.get(ARG_TABLA) if isinstance(arguments, Mapping) else None
            if not isinstance(tabla, str):
                return "", ()
            duenas = tuple(sorted(
                a for a, tablas in tool_policy.args.table_by_area.items() if tabla in tablas and a != area
            ))
            return f"tabla:{tabla}", duenas
        return "", ()

    def _registrar(self, session: Any, recurso: str, duenas: tuple[str, ...], contexto: Mapping[str, Any]) -> CrossAreaEvent:
        usuario = getattr(session, "usuario", None)
        area = getattr(session, "area", None)
        nivel = getattr(session, "nivel", None)
        clave = normalizar_usuario(usuario) or f"<sin_usuario:{area}>"
        ahora = self._clock()

        with self._lock:
            cola = self._intentos.setdefault(clave, deque())
            self._intentos.move_to_end(clave)
            self._podar(cola, ahora)
            cola.append((ahora, recurso))
            intentos = len(cola)
            alerta = intentos >= self._config.attempts
            recursos = [r for _, r in cola]
            if alerta:
                cola.clear()
            while len(self._intentos) > _MAX_USUARIOS_EN_MEMORIA:
                self._intentos.popitem(last=False)

        detalle = {**{k: v for k, v in contexto.items() if v is not None}, "recurso": recurso,
                   "intentos_en_ventana": intentos, "ventana_minutos": self._config.window_minutes}
        for duena in duenas:
            self._notificar(Notification(
                kind=NotificationKind.ACCESO_ENTRE_AREAS, priority=Priority.NORMAL, area_destino=duena,
                usuario=usuario, area=area, nivel=nivel,
                motivo=f"el área {area!r} pidió un recurso del área {duena!r} ({recurso}); se bloqueó",
                detalle=MappingProxyType(detalle),
            ))
        if alerta and self._config.alert_area:
            self._notificar(Notification(
                kind=NotificationKind.ALERTA_CUENTA_COMPROMETIDA, priority=Priority.PRIORITARIA,
                area_destino=self._config.alert_area, usuario=usuario, area=area, nivel=nivel,
                motivo=(f"{intentos} accesos a recursos de otras áreas en menos de {self._config.window_minutes} "
                        f"minutos: posible cuenta comprometida"),
                detalle=MappingProxyType({**detalle, "recursos": recursos}),
            ))
        return CrossAreaEvent(True, recurso, duenas, intentos, alerta)

    def _podar(self, cola: deque[tuple[float, str]], ahora: float) -> None:
        limite = ahora - self._config.window_minutes * 60
        while cola and cola[0][0] <= limite:
            cola.popleft()

    def _notificar(self, notificacion: Notification) -> None:
        entregar(self._notifier, notificacion, self._contar_fallo)

    def _contar_fallo(self, _exc: Exception) -> None:
        self.fallos_de_notificacion += 1
