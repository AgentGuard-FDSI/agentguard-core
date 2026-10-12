"""Motor de decisiones de AgentGuard: authorize(session, tool, arguments) -> Decision.

Orden de evaluación (la primera regla que falla decide BLOCK; fail-closed):

    0. Los argumentos deben ser un objeto (dict).
    1. La herramienta debe estar declarada en la política.
    2. La sesión debe traer usuario, área y nivel, y el área y el nivel deben existir en la política.
    3. El área de la sesión debe estar autorizada para la herramienta (fuera de rol = BLOCK siempre).
    4. Restricciones por argumento: AVANCE 3 (ver _check_arguments).
    5. Acción base declarada para la herramienta: ALLOW, HITL o BLOCK.

authorize() es puro: no ejecuta la herramienta, no pide aprobación y no escribe nada. Quien lo
llama (el agente de la Config. B) ejecuta, pide la aprobación (agentguard.approval) o rechaza
según la decisión, y la registra.

La identidad (área y nivel) sale de la sesión autenticada, nunca de los argumentos ni del
prompt: los argumentos que elige el modelo no se consultan para decidir quién es la persona.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, runtime_checkable

from .decision import Decision, Rule
from .policy import Action, PolicySet, ToolPolicy, load_policies


@runtime_checkable
class SessionLike(Protocol):
    """Lo mínimo que AgentGuard necesita de la sesión. El core no conoce la clase concreta del agente."""

    usuario: str
    area: str
    nivel: str


class AgentGuard:
    """Interceptor de mínimo privilegio. Se crea una vez al arrancar, con la política ya validada.

    es_cliente: función que dice si un correo pertenece a un cliente registrado. La inyecta el
    agente (consulta su base de datos) para que el core no dependa de ella. Se recibe desde ya para
    no cambiar la firma acordada, pero solo se usa en el Avance 3 (restricción recipient_in).
    """

    __slots__ = ("_policy", "_es_cliente")

    def __init__(self, policy: PolicySet, *, es_cliente: Callable[[str], bool] | None = None):
        if not isinstance(policy, PolicySet):
            raise TypeError("AgentGuard necesita un PolicySet ya validado (usar load_policies)")
        object.__setattr__(self, "_policy", policy)
        object.__setattr__(self, "_es_cliente", es_cliente)

    @classmethod
    def from_file(cls, path: str | Path, *, es_cliente: Callable[[str], bool] | None = None) -> "AgentGuard":
        """Carga y valida policies.yaml y crea el guard. Lanza PolicyError si la política es inválida."""
        return cls(load_policies(path), es_cliente=es_cliente)

    # La política es de solo lectura: no hay setter y el objeto no admite atributos nuevos
    # (regla "la política no la modifica el agente", docs/arquitectura.md).
    @property
    def policy(self) -> PolicySet:
        return self._policy

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("AgentGuard es inmutable: la política no se puede reemplazar en ejecución")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("AgentGuard es inmutable")

    # ------------------------------------------------------------------
    def authorize(self, session: Any, tool: str, arguments: Mapping[str, Any]) -> Decision:
        """Decide ALLOW, BLOCK o HITL para que `session` ejecute `tool` con `arguments`."""
        # 0. Argumentos con forma de objeto.
        if not isinstance(arguments, Mapping):
            return _block(Rule.ARGUMENTOS_INVALIDOS, "los argumentos deben ser un objeto clave: valor")

        # 1. Herramienta declarada. Cualquier herramienta que no esté en la política se bloquea,
        #    incluida cualquiera que intente editar la propia política.
        tool_policy = self._policy.get_tool(tool) if isinstance(tool, str) else None
        if tool_policy is None:
            return _block(Rule.HERRAMIENTA_NO_DECLARADA, f"la herramienta {tool!r} no está declarada en la política")

        # 2. Sesión válida: área y nivel existen en la política.
        usuario, area, nivel = (getattr(session, campo, None) for campo in ("usuario", "area", "nivel"))
        if not all(isinstance(v, str) and v for v in (usuario, area, nivel)):
            return _block(Rule.SESION_INVALIDA, "la sesión no trae usuario, área y nivel válidos")
        area_policy = self._policy.get_area(area)
        if area_policy is None:
            return _block(Rule.AREA_NO_DECLARADA, f"el área {area!r} no existe en la política")
        if nivel not in area_policy.levels:
            return _block(Rule.NIVEL_NO_DECLARADO, f"el nivel {nivel!r} no existe en el área {area!r}")

        # 3. Fuera de rol es siempre BLOCK, sin importar el nivel jerárquico.
        if not tool_policy.allows_area(area):
            return _block(Rule.FUERA_DE_ROL, f"el área {area!r} no tiene permitida la herramienta {tool!r}")

        # 4. Restricciones por argumento (Avance 3).
        argument_decision = self._check_arguments(area, tool_policy, arguments)
        if argument_decision is not None:
            return argument_decision

        # 5. Acción base de la herramienta.
        return _base_action(tool_policy)

    def _check_arguments(self, area: str, tool_policy: ToolPolicy, arguments: Mapping[str, Any]) -> Decision | None:
        """Restricciones por argumento declaradas en policies.yaml (tools.<herramienta>.args).

        PENDIENTE PARA EL AVANCE 3. Por la división de trabajo acordada, las restricciones por
        argumento son tarea de la Persona 3 en el Avance 3 (sección 8.2 de la propuesta). En el
        Avance 2 este método no restringe nada y devuelve None, así que la decisión la toma la
        acción base. Ya están cargadas y validadas en tool_policy.args:

          * table_by_area          leer_base_datos: tablas permitidas por área (Finanzas no lee
                                   clientes ni config_ti). Afecta los escenarios 6 y 7.
          * recipient_in           enviar_correo: destinatario cliente registrado (self._es_cliente)
                                   o del dominio corporativo. Afecta el escenario 5.
          * max_items_per_request  actualizar_pedido / eliminar_pedido: tamaño del lote. Las
                                   herramientas reciben un solo order_id, así que en una llamada
                                   solo se puede limitar una lista; contar varias llamadas de una
                                   misma solicitud (escenario 8) necesita estado por solicitud.

        Un argumento fuera de lo permitido debe devolver BLOCK aunque el área tenga la herramienta.
        Las pruebas marcadas con xfail en tests/test_authorize.py fallarán a propósito cuando esto
        se implemente, para recordar actualizarlas.
        """
        return None


def _block(rule: Rule, reason: str) -> Decision:
    return Decision(Action.BLOCK, reason, rule)


_BASE_REASONS = {
    Action.ALLOW: "permitida para el área (riesgo {risk})",
    Action.HITL: "requiere aprobación humana (riesgo {risk})",
    Action.BLOCK: "bloqueada siempre por la política (riesgo {risk})",
}


def _base_action(tool_policy: ToolPolicy) -> Decision:
    reason = f"{tool_policy.name}: " + _BASE_REASONS[tool_policy.action].format(risk=tool_policy.risk.value)
    return Decision(tool_policy.action, reason, Rule.ACCION_BASE)
