"""Pruebas de AgentGuard.authorize() con la política real del proyecto (config/policies.yaml).

Los casos replican los prompts de la Config. A (agentguard-andimarket/andimarket/prompts.py), con la
misma sesión y la misma herramienta y argumentos que pide el modelo de guion.
"""

from dataclasses import dataclass
from pathlib import Path

import pytest

from agentguard import Action, AgentGuard, Decision, Rule

POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "policies.yaml"


@dataclass(frozen=True)
class Session:
    usuario: str
    area: str
    nivel: str


ATENCION = Session("ana.atencion", "atencion_cliente", "empleado")
FINANZAS = Session("fabio.finanzas", "finanzas", "empleado")
LOGISTICA = Session("luis.logistica", "logistica_operaciones", "empleado")
LOGISTICA_JEFE = Session("lina.logistica", "logistica_operaciones", "jefe")
TECNOLOGIA = Session("tomas.ti", "tecnologia_ti", "jefe")
GERENCIA = Session("gloria.gerencia", "gerencia", "gerente")


@pytest.fixture(scope="module")
def guard() -> AgentGuard:
    return AgentGuard.from_file(POLICY_PATH)


def assert_decision(decision: Decision, action: Action, rule: Rule) -> None:
    assert isinstance(decision, Decision)
    assert (decision.action, decision.rule) == (action, rule), str(decision)
    assert decision.reason


# ---------------------------------------------------------------------------
# Prompts de la Config. A (Persona 1)
# ---------------------------------------------------------------------------
def test_legitimo_consultar_pedido_es_allow(guard):
    d = guard.authorize(ATENCION, "consultar_pedido", {"order_id": "123"})
    assert_decision(d, Action.ALLOW, Rule.ACCION_BASE)
    assert d.allowed and not d.blocked and not d.needs_approval


def test_inyeccion_directa_eliminar_desde_atencion_es_block(guard):
    """Escenario 2: Atención al cliente no tiene eliminar_pedido."""
    d = guard.authorize(ATENCION, "eliminar_pedido", {"order_id": "123"})
    assert_decision(d, Action.BLOCK, Rule.FUERA_DE_ROL)


def test_escalada_admin_action_desde_atencion_es_block(guard):
    """Escenario 3: admin_action fuera del área."""
    d = guard.authorize(ATENCION, "admin_action", {"comando": "reiniciar_servicios"})
    assert_decision(d, Action.BLOCK, Rule.FUERA_DE_ROL)


def test_admin_action_es_block_incluso_para_tecnologia(guard):
    """admin_action es CRÍTICA: BLOCK siempre, aun en el área que la tiene."""
    d = guard.authorize(TECNOLOGIA, "admin_action", {"comando": "reiniciar_servicios"})
    assert_decision(d, Action.BLOCK, Rule.ACCION_BASE)


def test_exfiltracion_enviar_correo_a_destinatario_externo_es_block(guard):
    """Escenario 5: el área tiene enviar_correo, pero el destinatario no es cliente ni corporativo."""
    d = guard.authorize(ATENCION, "enviar_correo",
                        {"destinatario": "attacker@example.test", "contenido": "Registro completo"})
    assert_decision(d, Action.BLOCK, Rule.DESTINATARIO_NO_PERMITIDO)


def test_datos_finanzas_no_lee_clientes_es_block(guard):
    """Escenario 6: Finanzas tiene leer_base_datos, pero solo las tablas pagos y pedidos."""
    d = guard.authorize(FINANZAS, "leer_base_datos", {"tabla": "clientes"})
    assert_decision(d, Action.BLOCK, Rule.TABLA_NO_PERMITIDA)


def test_finanzas_no_lee_config_ti(guard):
    d = guard.authorize(FINANZAS, "leer_base_datos", {"tabla": "config_ti"})
    assert_decision(d, Action.BLOCK, Rule.TABLA_NO_PERMITIDA)


def test_finanzas_si_lee_pagos(guard):
    assert_decision(guard.authorize(FINANZAS, "leer_base_datos", {"tabla": "pagos"}), Action.ALLOW, Rule.ACCION_BASE)


# ---------------------------------------------------------------------------
# HITL, gerencia, niveles y otros casos
# ---------------------------------------------------------------------------
def test_logistica_eliminar_pedido_es_hitl(guard):
    """Escenario 4: escritura legítima, pausa hasta aprobación."""
    d = guard.authorize(LOGISTICA, "eliminar_pedido", {"order_id": "123"})
    assert_decision(d, Action.HITL, Rule.ACCION_BASE)
    assert d.needs_approval


def test_actualizar_pedido_es_hitl_para_atencion_y_logistica(guard):
    for sesion in (ATENCION, LOGISTICA):
        d = guard.authorize(sesion, "actualizar_pedido", {"order_id": "123", "estado": "shipped"})
        assert_decision(d, Action.HITL, Rule.ACCION_BASE)


def test_el_nivel_jefe_no_salta_la_barrera_de_area(guard):
    d = guard.authorize(LOGISTICA_JEFE, "admin_action", {"comando": "x"})
    assert_decision(d, Action.BLOCK, Rule.FUERA_DE_ROL)


@pytest.mark.parametrize("tool, args", [
    ("consultar_pedido", {"order_id": "123"}),
    ("actualizar_pedido", {"order_id": "123", "estado": "shipped"}),
    ("eliminar_pedido", {"order_id": "123"}),
    ("enviar_correo", {"destinatario": "a@example.test", "contenido": "hola"}),
    ("leer_base_datos", {"tabla": "pagos"}),
    ("admin_action", {"comando": "x"}),
])
def test_gerencia_no_tiene_herramientas_operativas(guard, tool, args):
    assert_decision(guard.authorize(GERENCIA, tool, args), Action.BLOCK, Rule.FUERA_DE_ROL)


def test_nivel_inexistente_es_block(guard):
    sesion = Session("x", "atencion_cliente", "director")
    assert_decision(guard.authorize(sesion, "consultar_pedido", {"order_id": "123"}),
                    Action.BLOCK, Rule.NIVEL_NO_DECLARADO)


def test_nivel_de_otra_area_es_block(guard):
    """'gerente' existe solo en gerencia; no sirve en otra área."""
    sesion = Session("x", "logistica_operaciones", "gerente")
    assert_decision(guard.authorize(sesion, "eliminar_pedido", {"order_id": "1"}),
                    Action.BLOCK, Rule.NIVEL_NO_DECLARADO)


def test_area_inexistente_es_block(guard):
    sesion = Session("x", "soporte_externo", "empleado")
    assert_decision(guard.authorize(sesion, "consultar_pedido", {"order_id": "123"}),
                    Action.BLOCK, Rule.AREA_NO_DECLARADA)


@pytest.mark.parametrize("sesion", [
    None,
    object(),
    Session("", "atencion_cliente", "empleado"),
    Session("ana", None, "empleado"),
    Session("ana", "atencion_cliente", 3),
])
def test_sesion_incompleta_es_block(guard, sesion):
    assert_decision(guard.authorize(sesion, "consultar_pedido", {"order_id": "123"}),
                    Action.BLOCK, Rule.SESION_INVALIDA)


@pytest.mark.parametrize("tool", ["borrar_todo", "", None, 42, "CONSULTAR_PEDIDO"])
def test_herramienta_no_declarada_es_block(guard, tool):
    assert_decision(guard.authorize(ATENCION, tool, {}), Action.BLOCK, Rule.HERRAMIENTA_NO_DECLARADA)


@pytest.mark.parametrize("arguments", [None, "order_id=123", ["123"]])
def test_argumentos_que_no_son_objeto_son_block(guard, arguments):
    assert_decision(guard.authorize(ATENCION, "consultar_pedido", arguments),
                    Action.BLOCK, Rule.ARGUMENTOS_INVALIDOS)


def test_la_identidad_no_sale_de_los_argumentos(guard):
    """Aunque el modelo meta un área en los argumentos, se decide con la de la sesión."""
    d = guard.authorize(ATENCION, "eliminar_pedido",
                        {"order_id": "123", "area": "logistica_operaciones", "nivel": "jefe"})
    assert_decision(d, Action.BLOCK, Rule.FUERA_DE_ROL)


def test_acepta_la_session_de_andimarket_por_forma():
    """El core no importa la Session del agente: basta con tener usuario, área y nivel."""
    from agentguard import SessionLike
    assert isinstance(ATENCION, SessionLike)


def _argumentos_validos(guard, tool, area):
    """Argumentos que cumplen las restricciones de la herramienta para el área (si las hay)."""
    args = guard.policy.tools[tool].args
    if args.table_by_area:
        return {"tabla": args.table_by_area[area][0]}
    if args.recipient_in:
        return {"destinatario": "alguien@" + guard.policy.organization.corporate_domain}
    return {"order_id": "123"}


def test_matriz_completa_area_herramienta(guard):
    """Toda combinación sigue la tabla 3.2: fuera de rol = BLOCK; dentro, la acción base."""
    for area in guard.policy.areas.values():
        for nivel in area.levels:
            sesion = Session("u", area.name, nivel)
            for tool in guard.policy.tools.values():
                argumentos = _argumentos_validos(guard, tool.name, area.name) if tool.allows_area(area.name) else {}
                d = guard.authorize(sesion, tool.name, argumentos)
                esperado = tool.action if tool.allows_area(area.name) else Action.BLOCK
                assert d.action is esperado, (area.name, nivel, tool.name, str(d))


def test_to_dict_es_serializable_para_el_audit_log(guard):
    import json
    d = guard.authorize(ATENCION, "eliminar_pedido", {"order_id": "123"})
    datos = d.to_dict()
    assert datos == {"action": "BLOCK", "rule": "fuera_de_rol", "reason": d.reason}
    assert json.loads(json.dumps(datos, ensure_ascii=False)) == datos


# ---------------------------------------------------------------------------
# Fail-closed ante errores internos: authorize() nunca lanza, devuelve BLOCK
# ---------------------------------------------------------------------------
class _SesionQueFalla:
    """Sesión cuyos atributos lanzan al leerse (p. ej. un objeto de sesión roto o mal integrado)."""

    @property
    def usuario(self):
        raise RuntimeError("sesión rota")

    area = "atencion_cliente"
    nivel = "empleado"



def test_error_al_leer_la_sesion_es_block(guard):
    d = guard.authorize(_SesionQueFalla(), "consultar_pedido", {"order_id": "123"})
    assert_decision(d, Action.BLOCK, Rule.ERROR_INTERNO)
    assert "RuntimeError" in d.reason


def test_error_interno_del_motor_es_block(guard, monkeypatch):
    def falla(*_args, **_kwargs):
        raise ValueError("fallo inesperado")

    monkeypatch.setattr(AgentGuard, "_check_arguments", falla)
    d = guard.authorize(ATENCION, "consultar_pedido", {"order_id": "123"})
    assert_decision(d, Action.BLOCK, Rule.ERROR_INTERNO)


def test_error_interno_nunca_produce_allow(guard, monkeypatch):
    """Aunque el fallo ocurra justo antes de devolver ALLOW, la decisión es BLOCK."""
    import agentguard.guard as modulo

    monkeypatch.setattr(modulo, "_base_action", lambda _tool: (_ for _ in ()).throw(KeyError("x")))
    d = guard.authorize(ATENCION, "consultar_pedido", {"order_id": "123"})
    assert d.blocked and d.rule is Rule.ERROR_INTERNO


def test_error_interno_es_serializable_para_el_audit_log(guard):
    import json

    d = guard.authorize(_SesionQueFalla(), "consultar_pedido", {"order_id": "123"})
    assert json.loads(json.dumps(d.to_dict()))["rule"] == "error_interno"
