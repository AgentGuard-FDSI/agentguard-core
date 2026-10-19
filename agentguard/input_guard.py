"""Verificador de entrada (Input Guard): revisa el prompt antes de que el agente elija una herramienta.

    guard_entrada = InputGuard.from_file("config/policies.yaml", notifier=InMemoryNotifier())
    veredicto = guard_entrada.check(session, "Dame nombre, teléfono y correo de todos los clientes")
    if veredicto.rejected:
        return veredicto.message          # "No puedo ayudarte con esta solicitud."

Funciona por reglas (agentguard.input_rules), sin LLM: decisiones deterministas y latencia mínima.
Si el prompt coincide con un tema configurado en verificador_entrada.temas:

  * devuelve REJECT con el rechazo estándar, que no dice qué regla coincidió (no le enseña al
    atacante qué palabra evitar);
  * notifica a verificador_entrada.notificar_area (Tecnología), con los temas y las reglas;
  * si se le pasa un log encadenado (chain), registra el resultado (también los PASS, para las métricas).

area_propietaria: un tema no se rechaza para su área dueña (Tecnología puede preguntar por la
configuración de sus servidores). Para las demás áreas, el veredicto trae `owner_areas`, que la
regla entre áreas (agentguard.cross_area) cuenta como acceso a un recurso de otra área.

Fail-closed: un prompt que no es texto, o un error inesperado al evaluar, es REJECT.

Limitación declarada: solo ve el prompt del usuario. La inyección indirecta llega dentro del
resultado de una herramienta y no pasa por aquí; la contienen authorize() y el HITL.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from .input_rules import match_rules, normalize
from .notify import Notification, NotificationKind, Notifier, Priority, entregar
from .policy import PolicySet, load_policies

PASS, REJECT = "PASS", "REJECT"
RULE_ENTRADA_INVALIDA = "entrada_invalida"
RULE_ERROR_INTERNO = "error_interno"
_EXTRACTO = 160


@dataclass(frozen=True)
class InputVerdict:
    """Resultado del verificador de entrada.

    action:      PASS (sigue al agente) o REJECT (se responde `message` y no se invoca al agente).
    topics:      temas que coincidieron (vacío si PASS).
    rules:       identificadores de las reglas que coincidieron (o entrada_invalida / error_interno).
    reason:      motivo interno, para el log y la notificación (no se le muestra a la persona).
    message:     rechazo estándar que ve la persona (None si PASS).
    owner_areas: {tema: área dueña} de los temas que pertenecen a otra área (regla entre áreas).
    notified:    True si la notificación a Tecnología se entregó.
    """

    action: str
    topics: tuple[str, ...] = ()
    rules: tuple[str, ...] = ()
    reason: str = ""
    message: str | None = None
    owner_areas: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    notified: bool = False

    @property
    def rejected(self) -> bool:
        return self.action == REJECT

    @property
    def passed(self) -> bool:
        return self.action == PASS

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "topics": list(self.topics),
            "rules": list(self.rules),
            "reason": self.reason,
            "owner_areas": dict(self.owner_areas),
            "notified": self.notified,
        }


class InputGuard:
    """Verificador de entrada configurado desde policies.yaml (sección verificador_entrada)."""

    def __init__(self, policy: PolicySet, *, notifier: Notifier | None = None, chain: Any = None):
        if not isinstance(policy, PolicySet):
            raise TypeError("InputGuard necesita un PolicySet ya validado (usar load_policies)")
        self._policy = policy
        self._config = policy.input_guard
        self._topics = frozenset(self._config.topics)
        self._notifier = notifier
        self._chain = chain
        self.fallos_de_notificacion = 0
        self.fallos_de_registro = 0

    @classmethod
    def from_file(cls, path: str | Path, *, notifier: Notifier | None = None, chain: Any = None) -> "InputGuard":
        return cls(load_policies(path), notifier=notifier, chain=chain)

    @property
    def enabled(self) -> bool:
        return self._config.enabled

    # ------------------------------------------------------------------
    def check(self, session: Any, prompt: Any, *, run_id: str | None = None) -> InputVerdict:
        """Evalúa el prompt de `session`. Nunca lanza excepciones (fail-closed: error = REJECT)."""
        try:
            verdict = self._evaluar(session, prompt)
        except Exception as exc:  # noqa: BLE001 - ante cualquier fallo, no se deja pasar
            verdict = self._rechazo((), (RULE_ERROR_INTERNO,), f"error interno del verificador ({type(exc).__name__})", {})
        if verdict.rejected:
            verdict = self._notificar(session, prompt, verdict, run_id)
        self._registrar(session, verdict, run_id)
        return verdict

    def _evaluar(self, session: Any, prompt: Any) -> InputVerdict:
        if not self._config.enabled:
            return InputVerdict(PASS, reason="verificador de entrada apagado en la política")
        if not isinstance(prompt, str):
            return self._rechazo((), (RULE_ENTRADA_INVALIDA,), "el prompt no es texto", {})

        area = getattr(session, "area", None)
        # Los temas cuya área dueña es la de la sesión no se revisan para ella.
        temas = frozenset(t for t in self._topics if self._config.topic_owner.get(t) != area)
        reglas = match_rules(normalize(prompt), temas)
        if not reglas:
            return InputVerdict(PASS, reason="sin coincidencias")

        topics = tuple(dict.fromkeys(r.topic for r in reglas))
        owners = {t: self._config.topic_owner[t] for t in topics if t in self._config.topic_owner}
        motivo = "; ".join(f"{r.topic}: {r.description}" for r in reglas)
        return self._rechazo(topics, tuple(r.id for r in reglas), motivo, owners)

    def _rechazo(self, topics: tuple[str, ...], rules: tuple[str, ...], reason: str, owners: Mapping[str, str]) -> InputVerdict:
        return InputVerdict(
            REJECT, topics, rules, reason, self._config.reject_message, MappingProxyType(dict(owners)),
        )

    def _notificar(self, session: Any, prompt: Any, verdict: InputVerdict, run_id: str | None) -> InputVerdict:
        area_destino = self._config.notify_area
        if area_destino is None:
            return verdict
        extracto = prompt[:_EXTRACTO] if isinstance(prompt, str) else repr(type(prompt))
        notificacion = Notification(
            kind=NotificationKind.ENTRADA_RECHAZADA,
            priority=Priority.NORMAL,
            area_destino=area_destino,
            usuario=getattr(session, "usuario", None),
            area=getattr(session, "area", None),
            nivel=getattr(session, "nivel", None),
            motivo=f"prompt rechazado por el verificador de entrada ({', '.join(verdict.topics or verdict.rules)})",
            detalle=MappingProxyType({
                "run_id": run_id, "temas": list(verdict.topics), "reglas": list(verdict.rules), "extracto": extracto,
            }),
        )
        entregado = entregar(self._notifier, notificacion, self._contar_fallo_notificacion)
        return InputVerdict(
            verdict.action, verdict.topics, verdict.rules, verdict.reason, verdict.message, verdict.owner_areas, entregado,
        )

    def _registrar(self, session: Any, verdict: InputVerdict, run_id: str | None) -> None:
        if self._chain is None:
            return
        try:
            self._chain.append({
                "tipo": "verificador_entrada",
                "run_id": run_id,
                "usuario": getattr(session, "usuario", None),
                "area": getattr(session, "area", None),
                "nivel": getattr(session, "nivel", None),
                "resultado": verdict.to_dict(),
            })
        except Exception:  # noqa: BLE001 - el registro no cambia el veredicto, pero se cuenta
            self.fallos_de_registro += 1

    def _contar_fallo_notificacion(self, _exc: Exception) -> None:
        self.fallos_de_notificacion += 1


# ---------------------------------------------------------------------------
# Evaluación sobre un conjunto etiquetado (métrica de la sección 4.2)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class LabeledPrompt:
    """Un prompt del conjunto etiquetado. confidencial=True si el verificador DEBE rechazarlo."""

    id: str
    texto: str
    area: str
    nivel: str
    confidencial: bool
    tema: str | None = None
    usuario: str = "evaluacion"


@dataclass(frozen=True)
class _Sesion:
    usuario: str
    area: str
    nivel: str


def evaluate(guard: InputGuard, casos: Iterable[LabeledPrompt]) -> dict[str, Any]:
    """Precisión y exhaustividad del verificador sobre un conjunto etiquetado.

    Positivo = REJECT. precision = VP / (VP + FP); exhaustividad (recall) = VP / (VP + FN).
    No notifica ni registra nada: se evalúa una copia sin notificador ni log.
    """
    evaluador = InputGuard(guard._policy)

    vp = fp = fn = vn = 0
    errores: list[dict[str, Any]] = []
    for caso in casos:
        veredicto = evaluador.check(_Sesion(caso.usuario, caso.area, caso.nivel), caso.texto)
        if caso.confidencial and veredicto.rejected:
            vp += 1
        elif caso.confidencial:
            fn += 1
            errores.append({"id": caso.id, "tipo": "falso_negativo", "texto": caso.texto, "tema_esperado": caso.tema})
        elif veredicto.rejected:
            fp += 1
            errores.append({"id": caso.id, "tipo": "falso_positivo", "texto": caso.texto, "reglas": list(veredicto.rules)})
        else:
            vn += 1
    precision = vp / (vp + fp) if vp + fp else None
    recall = vp / (vp + fn) if vp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else None
    return {
        "verdaderos_positivos": vp, "falsos_positivos": fp, "falsos_negativos": fn, "verdaderos_negativos": vn,
        "precision": precision, "exhaustividad": recall, "f1": f1, "total": vp + fp + fn + vn, "errores": errores,
    }


def load_labeled(path: str | Path) -> list[LabeledPrompt]:
    """Lee un conjunto etiquetado en JSON: {"casos": [{id, texto, area, nivel, confidencial, tema?}, ...]}."""
    import json

    datos = json.loads(Path(path).read_text(encoding="utf-8"))
    casos = datos["casos"] if isinstance(datos, dict) else datos
    return [
        LabeledPrompt(
            id=str(c["id"]), texto=c["texto"], area=c["area"], nivel=c["nivel"],
            confidencial=bool(c["confidencial"]), tema=c.get("tema"), usuario=c.get("usuario", "evaluacion"),
        )
        for c in casos
    ]
