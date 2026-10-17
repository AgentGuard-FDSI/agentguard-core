"""Motor de decisiones de AgentGuard: authorize(session, tool, arguments) -> Decision.

Orden de evaluación (la primera regla que falla decide BLOCK; fail-closed). Si algo falla de
forma inesperada durante la evaluación, la decisión es BLOCK con la regla ERROR_INTERNO:

    0. Los argumentos deben ser un objeto (dict).
    1. La herramienta debe estar declarada en la política.
    2. La sesión debe traer usuario, área y nivel, y el área y el nivel deben existir en la política.
    3. El área de la sesión debe estar autorizada para la herramienta (fuera de rol = BLOCK siempre).
    4. Restricciones por argumento declaradas en la política (tabla por área, destinatario del
       correo y tamaño del lote). Un argumento fuera de lo permitido es BLOCK aunque el área tenga
       la herramienta.
    5. Acción base declarada para la herramienta: ALLOW, HITL o BLOCK.

authorize() no ejecuta la herramienta, no pide aprobación y no escribe nada. Quien lo llama (el
agente de la Config. B) ejecuta, pide la aprobación (agentguard.approval, agentguard.hitl) o
rechaza según la decisión, y la registra (agentguard.audit). La única memoria del guard es el
contador de lote por solicitud, que solo se usa si quien llama pasa `solicitud`.

La identidad (área y nivel) sale de la sesión autenticada, nunca de los argumentos ni del
prompt: los argumentos que elige el modelo no se consultan para decidir quién es la persona.
"""

from __future__ import annotations

import re
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, runtime_checkable

from .decision import Decision, Rule
from .policy import Action, PolicySet, ToolArgs, ToolPolicy, load_policies

# Nombres de los argumentos que las restricciones inspeccionan. Son una convención del catálogo de
# herramientas: otra empresa usa los mismos nombres al registrar sus herramientas.
ARG_TABLA = "tabla"
ARG_DESTINATARIO = "destinatario"
ARG_PEDIDOS = ("order_id", "order_ids")

_CORREO = re.compile(r'^[^@\s,;<>()\[\]"\\]+@[^@\s,;<>()\[\]"\\]+$')
_SEPARADORES = re.compile(r"[,;\s]+")
_COMODINES = frozenset({"*", "%", "todos", "todas", "all"})
_MAX_SOLICITUDES_EN_MEMORIA = 10_000


@runtime_checkable
class SessionLike(Protocol):
    """Lo mínimo que AgentGuard necesita de la sesión. El core no conoce la clase concreta del agente."""

    usuario: str
    area: str
    nivel: str


class AgentGuard:
    """Interceptor de mínimo privilegio. Se crea una vez al arrancar, con la política ya validada.

    es_cliente: función que dice si un correo pertenece a un cliente registrado. La inyecta el
    agente (consulta su base de datos) para que el core no dependa de ella. La usa la restricción
    recipient_in; si no se inyecta, ningún correo cuenta como cliente (fail-closed).
    """

    __slots__ = ("_policy", "_es_cliente", "_lotes")

    def __init__(self, policy: PolicySet, *, es_cliente: Callable[[str], bool] | None = None):
        if not isinstance(policy, PolicySet):
            raise TypeError("AgentGuard necesita un PolicySet ya validado (usar load_policies)")
        object.__setattr__(self, "_policy", policy)
        object.__setattr__(self, "_es_cliente", es_cliente)
        object.__setattr__(self, "_lotes", _ContadorDeLotes())

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
    def authorize(
        self, session: Any, tool: str, arguments: Mapping[str, Any], *, solicitud: str | None = None
    ) -> Decision:
        """Decide ALLOW, BLOCK o HITL para que `session` ejecute `tool` con `arguments`.

        solicitud: identificador de la solicitud del usuario (por ejemplo el run_id). Si se pasa, el
        límite max_items_per_request cuenta los pedidos de todas las llamadas de esa solicitud y no
        solo los de una llamada (escrituras masivas repartidas en varias llamadas).

        Nunca lanza excepciones: cualquier error inesperado al evaluar (una sesión que falla al
        leerse, un fallo del motor) se convierte en BLOCK con la regla ERROR_INTERNO (fail-closed).
        """
        try:
            return self._evaluar(session, tool, arguments, solicitud)
        except Exception as exc:  # noqa: BLE001 - ante cualquier fallo, no se autoriza
            return _block(Rule.ERROR_INTERNO, f"error interno al evaluar la política ({type(exc).__name__}: {exc})")

    def _evaluar(self, session: Any, tool: str, arguments: Mapping[str, Any], solicitud: str | None) -> Decision:
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

        # 4. Restricciones por argumento.
        argument_decision = self._check_arguments(area, tool_policy, arguments, solicitud)
        if argument_decision is not None:
            return argument_decision

        # 5. Acción base de la herramienta.
        return _base_action(tool_policy)

    def _check_arguments(
        self, area: str, tool_policy: ToolPolicy, arguments: Mapping[str, Any], solicitud: str | None = None
    ) -> Decision | None:
        """Restricciones por argumento declaradas en policies.yaml (tools.<herramienta>.args).

          * table_by_area          leer_base_datos: solo las tablas que el área tiene permitidas.
          * recipient_in           enviar_correo: un único destinatario que sea cliente registrado
                                   (self._es_cliente) o del dominio corporativo de la organización.
          * max_items_per_request  actualizar_pedido / eliminar_pedido: máximo de pedidos por solicitud.

        Devuelve None si todas se cumplen (la decisión la toma la acción base) o un BLOCK con el
        motivo. Un argumento ausente, de otro tipo o ambiguo cuenta como fuera de lo permitido.
        """
        args = tool_policy.args
        if args.table_by_area:
            decision = self._check_tabla(area, tool_policy.name, args, arguments)
            if decision:
                return decision
        if args.recipient_in:
            decision = self._check_destinatario(tool_policy.name, args, arguments)
            if decision:
                return decision
        if args.max_items_per_request is not None:
            decision = self._check_lote(tool_policy.name, args.max_items_per_request, arguments, solicitud)
            if decision:
                return decision
        return None

    def _check_tabla(self, area: str, tool: str, args: ToolArgs, arguments: Mapping[str, Any]) -> Decision | None:
        tabla = arguments.get(ARG_TABLA)
        if not isinstance(tabla, str) or not tabla:
            return _block(Rule.ARGUMENTO_INVALIDO, f"{tool}: falta el argumento {ARG_TABLA!r} (texto)")
        if tabla not in args.table_by_area.get(area, ()):
            return _block(Rule.TABLA_NO_PERMITIDA, f"el área {area!r} no puede leer la tabla {tabla!r} con {tool}")
        return None

    def _check_destinatario(self, tool: str, args: ToolArgs, arguments: Mapping[str, Any]) -> Decision | None:
        destinatario = arguments.get(ARG_DESTINATARIO)
        if not isinstance(destinatario, str) or not _CORREO.match(destinatario.strip()):
            return _block(
                Rule.ARGUMENTO_INVALIDO,
                f"{tool}: {ARG_DESTINATARIO!r} debe ser un único correo válido",
            )
        correo = destinatario.strip().lower()
        dominio = correo.rpartition("@")[2]
        if "clientes_registrados" in args.recipient_in and self._es_cliente is not None and self._es_cliente(correo):
            return None
        corporativo = self._policy.organization.corporate_domain
        if "dominio_corporativo" in args.recipient_in and corporativo is not None and dominio == corporativo:
            return None
        return _block(
            Rule.DESTINATARIO_NO_PERMITIDO,
            f"{tool}: el destinatario {correo!r} no es un cliente registrado ni del dominio corporativo",
        )

    def _check_lote(
        self, tool: str, maximo: int, arguments: Mapping[str, Any], solicitud: str | None
    ) -> Decision | None:
        pedidos = _contar_pedidos(arguments)
        if pedidos is None:
            return _block(
                Rule.ARGUMENTO_INVALIDO,
                f"{tool}: los pedidos deben indicarse por identificador, sin comodines ni listas vacías",
            )
        if pedidos > maximo:
            return _block(Rule.LOTE_EXCEDIDO, f"{tool}: {pedidos} pedidos en una llamada; el máximo es {maximo}")
        if solicitud is not None and self._lotes.sumar(solicitud, tool, pedidos, maximo) is None:
            return _block(
                Rule.LOTE_EXCEDIDO,
                f"{tool}: la solicitud {solicitud!r} superaría el máximo de {maximo} pedidos",
            )
        return None


class _ContadorDeLotes:
    """Pedidos acumulados por (solicitud, herramienta). Acotado para no crecer sin límite."""

    def __init__(self) -> None:
        self._conteos: OrderedDict[tuple[str, str], int] = OrderedDict()
        self._lock = threading.Lock()

    def sumar(self, solicitud: str, tool: str, pedidos: int, maximo: int) -> int | None:
        """Suma `pedidos` y devuelve el total, o None (sin sumar) si superaría `maximo`."""
        clave = (solicitud, tool)
        with self._lock:
            total = self._conteos.get(clave, 0) + pedidos
            if total > maximo:
                return None
            self._conteos[clave] = total
            self._conteos.move_to_end(clave)
            while len(self._conteos) > _MAX_SOLICITUDES_EN_MEMORIA:
                self._conteos.popitem(last=False)
            return total


def _contar_pedidos(arguments: Mapping[str, Any]) -> int | None:
    """Cantidad de pedidos que nombra la llamada, o None si falta, es inválida o es ambigua."""
    total, encontrado = 0, False
    for clave in ARG_PEDIDOS:
        if clave not in arguments:
            continue
        encontrado = True
        cantidad = _contar_valor(arguments[clave])
        if cantidad is None:
            return None
        total += cantidad
    return total if encontrado else None


def _contar_valor(valor: Any) -> int | None:
    if isinstance(valor, bool):
        return None
    if isinstance(valor, int):
        return 1
    if isinstance(valor, str):
        trozos = [t for t in _SEPARADORES.split(valor.strip()) if t]
        if not trozos or any(t.lower() in _COMODINES or "*" in t or "%" in t for t in trozos):
            return None
        return len(trozos)
    if isinstance(valor, (list, tuple, set, frozenset)):
        total = 0
        for item in valor:
            cantidad = _contar_valor(item) if isinstance(item, (str, int)) else None
            if cantidad is None:
                return None
            total += cantidad
        return total or None
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
