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


def test_exfiltracion_enviar_correo_desde_atencion_avance2_es_hitl(guard):
    """Escenario 5 en el Avance 2: el área sí tiene enviar_correo, así que queda en HITL.

    El ataque solo se contiene si el aprobador rechaza. El BLOCK por destinatario llega en el Avance 3.
    """
    d = guard.authorize(ATENCION, "enviar_correo",
                        {"destinatario": "attacker@example.test", "contenido": "Registro completo"})
    assert_decision(d, Action.HITL, Rule.ACCION_BASE)


def test_datos_leer_clientes_desde_finanzas_avance2_es_allow(guard):
    """Escenario 6 en el Avance 2: Finanzas sí tiene leer_base_datos y aún no se restringe la tabla."""
    d = guard.authorize(FINANZAS, "leer_base_datos", {"tabla": "clientes"})
    assert_decision(d, Action.ALLOW, Rule.ACCION_BASE)


# ---------------------------------------------------------------------------
# Restricciones por argumento: AVANCE 3. Fallan a propósito hasta que se implementen;
# strict=True hace que, cuando pasen, la suite avise para quitar el xfail.
# ---------------------------------------------------------------------------
AVANCE_3 = pytest.mark.xfail(strict=True, reason="restricciones por argumento: Avance 3")


@AVANCE_3
def test_avance3_exfiltracion_destinatario_externo_es_block(guard):
    d = guard.authorize(ATENCION, "enviar_correo",
                        {"destinatario": "attacker@example.test", "contenido": "Registro completo"})
    assert d.action is Action.BLOCK


@AVANCE_3
def test_avance3_finanzas_no_lee_clientes(guard):
    assert guard.authorize(FINANZAS, "leer_base_datos", {"tabla": "clientes"}).action is Action.BLOCK


@AVANCE_3
def test_avance3_finanzas_no_lee_config_ti(guard):
    assert guard.authorize(FINANZAS, "leer_base_datos", {"tabla": "config_ti"}).action is Action.BLOCK


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


def test_matriz_completa_area_herramienta(guard):
    """Toda combinación sigue la tabla 3.2: fuera de rol = BLOCK; dentro, la acción base."""
    for area in guard.policy.areas.values():
        for nivel in area.levels:
            sesion = Session("u", area.name, nivel)
            for tool in guard.policy.tools.values():
                d = guard.authorize(sesion, tool.name, {})
                esperado = tool.action if tool.allows_area(area.name) else Action.BLOCK
                assert d.action is esperado, (area.name, nivel, tool.name, str(d))


def test_to_dict_es_serializable_para_el_audit_log(guard):
    import json
    d = guard.authorize(ATENCION, "eliminar_pedido", {"order_id": "123"})
    datos = d.to_dict()
    assert datos == {"action": "BLOCK", "rule": "fuera_de_rol", "reason": d.reason}
    assert json.loads(json.dumps(datos, ensure_ascii=False)) == datos
