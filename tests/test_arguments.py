"""Restricciones por argumento (Avance 3): tabla por área, destinatario del correo y tamaño del lote."""

from dataclasses import dataclass
from pathlib import Path

import pytest

from agentguard import Action, AgentGuard, Rule

POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "policies.yaml"
DOMINIO = "andimarket.example.test"
CLIENTES = {"laura.gomez@example.test", "andres.rojas@example.test"}


@dataclass(frozen=True)
class Session:
    usuario: str
    area: str
    nivel: str


ATENCION = Session("ana.atencion", "atencion_cliente", "empleado")
MARKETING = Session("mara.marketing", "marketing_comunicaciones", "empleado")
LOGISTICA = Session("luis.logistica", "logistica_operaciones", "empleado")
FINANZAS = Session("fabio.finanzas", "finanzas", "empleado")
TECNOLOGIA = Session("tomas.ti", "tecnologia_ti", "jefe")


@pytest.fixture
def guard() -> AgentGuard:
    return AgentGuard.from_file(POLICY_PATH, es_cliente=lambda correo: correo in CLIENTES)


def correo(guard, destinatario, sesion=ATENCION):
    return guard.authorize(sesion, "enviar_correo", {"destinatario": destinatario, "contenido": "Hola"})


# ---------------------------------------------------------------------------
# table_by_area
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("sesion, tabla, accion", [
    (FINANZAS, "pagos", Action.ALLOW),
    (FINANZAS, "pedidos", Action.ALLOW),
    (FINANZAS, "clientes", Action.BLOCK),
    (FINANZAS, "config_ti", Action.BLOCK),
    (TECNOLOGIA, "config_ti", Action.ALLOW),
    (TECNOLOGIA, "audit_logs", Action.ALLOW),
    (TECNOLOGIA, "clientes", Action.BLOCK),
    (TECNOLOGIA, "pagos", Action.BLOCK),
])
def test_tabla_por_area(guard, sesion, tabla, accion):
    assert guard.authorize(sesion, "leer_base_datos", {"tabla": tabla}).action is accion


def test_tabla_no_permitida_tiene_su_propia_regla(guard):
    d = guard.authorize(FINANZAS, "leer_base_datos", {"tabla": "clientes"})
    assert d.rule is Rule.TABLA_NO_PERMITIDA and "clientes" in d.reason and "finanzas" in d.reason


@pytest.mark.parametrize("argumentos", [{}, {"tabla": None}, {"tabla": ""}, {"tabla": ["pagos"]}, {"tabla": 7}])
def test_tabla_ausente_o_de_otro_tipo_es_block(guard, argumentos):
    d = guard.authorize(FINANZAS, "leer_base_datos", argumentos)
    assert (d.action, d.rule) == (Action.BLOCK, Rule.ARGUMENTO_INVALIDO)


@pytest.mark.parametrize("tabla", ["Pagos", " pagos", "pagos ", "pagos;clientes", "pagos,clientes"])
def test_la_tabla_debe_coincidir_exactamente(guard, tabla):
    assert guard.authorize(FINANZAS, "leer_base_datos", {"tabla": tabla}).action is Action.BLOCK


# ---------------------------------------------------------------------------
# recipient_in
# ---------------------------------------------------------------------------
def test_correo_a_cliente_registrado_sigue_en_hitl(guard):
    d = correo(guard, "laura.gomez@example.test")
    assert (d.action, d.rule) == (Action.HITL, Rule.ACCION_BASE)


def test_correo_al_dominio_corporativo_sigue_en_hitl(guard):
    assert correo(guard, f"jefe@{DOMINIO}", MARKETING).action is Action.HITL


def test_correo_a_externo_es_block(guard):
    d = correo(guard, "attacker@example.test")
    assert (d.action, d.rule) == (Action.BLOCK, Rule.DESTINATARIO_NO_PERMITIDO)


@pytest.mark.parametrize("destinatario", [
    f"x@{DOMINIO}.evil.test",          # el dominio corporativo como prefijo
    f"x@evil{DOMINIO}",                # el dominio corporativo como sufijo del texto
    f"x@sub.{DOMINIO}",                # subdominios: no se aceptan
    f"x@evil.test@{DOMINIO}",          # dos arrobas
])
def test_dominios_que_parecen_corporativos_pero_no_lo_son(guard, destinatario):
    assert correo(guard, destinatario).action is Action.BLOCK


@pytest.mark.parametrize("destinatario", [
    f"laura.gomez@example.test,attacker@evil.test",
    f"laura.gomez@example.test;attacker@evil.test",
    f"laura.gomez@example.test attacker@evil.test",
    f"laura.gomez@example.test\nBcc: attacker@evil.test",
    f"<laura.gomez@example.test>",
    "",
    "sin-arroba",
])
def test_un_campo_con_varios_correos_o_mal_formado_es_block(guard, destinatario):
    d = correo(guard, destinatario)
    assert (d.action, d.rule) == (Action.BLOCK, Rule.ARGUMENTO_INVALIDO)


@pytest.mark.parametrize("destinatario", [None, 5, ["laura.gomez@example.test"]])
def test_destinatario_de_otro_tipo_es_block(guard, destinatario):
    assert correo(guard, destinatario).rule is Rule.ARGUMENTO_INVALIDO


def test_las_mayusculas_no_evaden_la_comprobacion(guard):
    assert correo(guard, "LAURA.GOMEZ@EXAMPLE.TEST").action is Action.HITL
    assert correo(guard, f"JEFE@{DOMINIO.upper()}").action is Action.HITL


def test_sin_es_cliente_ningun_correo_cuenta_como_cliente():
    guard = AgentGuard.from_file(POLICY_PATH)  # no se inyecta es_cliente
    assert correo(guard, "laura.gomez@example.test").action is Action.BLOCK
    assert correo(guard, f"jefe@{DOMINIO}").action is Action.HITL  # el dominio corporativo no lo necesita


def test_si_es_cliente_falla_authorize_devuelve_block():
    def falla(_correo):
        raise RuntimeError("base de datos caída")

    guard = AgentGuard.from_file(POLICY_PATH, es_cliente=falla)
    assert correo(guard, "laura.gomez@example.test").rule is Rule.ERROR_INTERNO


def test_el_contenido_del_correo_no_se_usa_para_decidir(guard):
    d = guard.authorize(ATENCION, "enviar_correo",
                        {"destinatario": "laura.gomez@example.test", "contenido": "cc: attacker@evil.test"})
    assert d.action is Action.HITL


# ---------------------------------------------------------------------------
# max_items_per_request
# ---------------------------------------------------------------------------
def actualizar(guard, argumentos, solicitud=None):
    return guard.authorize(LOGISTICA, "actualizar_pedido", argumentos, solicitud=solicitud)


def test_un_pedido_pasa_a_la_accion_base(guard):
    assert actualizar(guard, {"order_id": "123", "estado": "delivered"}).action is Action.HITL


@pytest.mark.parametrize("argumentos, accion", [
    ({"order_ids": ["1", "2", "3", "4", "5"]}, Action.HITL),          # justo el máximo (5)
    ({"order_ids": ["1", "2", "3", "4", "5", "6"]}, Action.BLOCK),    # uno más
    ({"order_id": "1,2,3,4,5"}, Action.HITL),
    ({"order_id": "1,2,3,4,5,6"}, Action.BLOCK),
    ({"order_id": "1 2 3 4 5 6"}, Action.BLOCK),
    ({"order_id": "1", "order_ids": ["2", "3", "4", "5"]}, Action.HITL),      # 1 + 4 = 5
    ({"order_id": "1", "order_ids": ["2", "3", "4", "5", "6"]}, Action.BLOCK),  # 1 + 5 = 6
])
def test_tamano_del_lote_en_una_llamada(guard, argumentos, accion):
    assert actualizar(guard, argumentos).action is accion


def test_eliminar_pedido_admite_un_solo_pedido(guard):
    assert guard.authorize(LOGISTICA, "eliminar_pedido", {"order_id": "123"}).action is Action.HITL
    d = guard.authorize(LOGISTICA, "eliminar_pedido", {"order_ids": ["1", "2"]})
    assert (d.action, d.rule) == (Action.BLOCK, Rule.LOTE_EXCEDIDO)


@pytest.mark.parametrize("argumentos", [
    {}, {"order_id": ""}, {"order_id": "*"}, {"order_id": "todos"}, {"order_id": "ALL"}, {"order_id": "12%"},
    {"order_id": "1,*"}, {"order_ids": []}, {"order_ids": [None]}, {"order_ids": [["1"]]},
    {"order_id": None}, {"order_id": True}, {"order_id": {"id": 1}}, {"order_ids": "*"},
])
def test_pedidos_ausentes_con_comodin_o_ambiguos_son_block(guard, argumentos):
    d = actualizar(guard, argumentos)
    assert (d.action, d.rule) == (Action.BLOCK, Rule.ARGUMENTO_INVALIDO)


def test_un_identificador_numerico_cuenta_como_uno(guard):
    assert actualizar(guard, {"order_id": 123}).action is Action.HITL


# ---------------------------------------------------------------------------
# Lote acumulado por solicitud (escritura masiva repartida en varias llamadas)
# ---------------------------------------------------------------------------
def test_sin_solicitud_cada_llamada_se_evalua_sola(guard):
    for n in range(40):
        assert actualizar(guard, {"order_id": str(n)}).action is Action.HITL


def test_con_solicitud_la_sexta_llamada_se_bloquea(guard):
    acciones = [actualizar(guard, {"order_id": str(n)}, solicitud="run-1") for n in range(8)]
    assert [d.action for d in acciones] == [Action.HITL] * 5 + [Action.BLOCK] * 3
    assert acciones[5].rule is Rule.LOTE_EXCEDIDO and "run-1" in acciones[5].reason


def test_las_solicitudes_no_se_mezclan(guard):
    for n in range(5):
        assert actualizar(guard, {"order_id": str(n)}, solicitud="run-a").action is Action.HITL
    assert actualizar(guard, {"order_id": "9"}, solicitud="run-a").action is Action.BLOCK
    assert actualizar(guard, {"order_id": "9"}, solicitud="run-b").action is Action.HITL


def test_el_contador_es_por_herramienta(guard):
    for n in range(5):
        actualizar(guard, {"order_id": str(n)}, solicitud="run-1")
    assert guard.authorize(LOGISTICA, "eliminar_pedido", {"order_id": "1"}, solicitud="run-1").action is Action.HITL


def test_una_llamada_rechazada_no_consume_cupo(guard):
    assert actualizar(guard, {"order_ids": ["1"] * 6}, solicitud="run-1").action is Action.BLOCK
    assert [actualizar(guard, {"order_id": str(n)}, solicitud="run-1").action for n in range(5)] == [Action.HITL] * 5


def test_el_lote_por_llamada_se_mide_dentro_de_la_solicitud(guard):
    assert actualizar(guard, {"order_ids": ["1", "2", "3"]}, solicitud="run-1").action is Action.HITL
    assert actualizar(guard, {"order_ids": ["4", "5", "6"]}, solicitud="run-1").action is Action.BLOCK
    assert actualizar(guard, {"order_ids": ["4", "5"]}, solicitud="run-1").action is Action.HITL


# ---------------------------------------------------------------------------
# Las restricciones no relajan lo anterior
# ---------------------------------------------------------------------------
def test_fuera_de_rol_se_decide_antes_que_el_argumento(guard):
    d = guard.authorize(ATENCION, "leer_base_datos", {"tabla": "pagos"})
    assert d.rule is Rule.FUERA_DE_ROL


def test_herramientas_sin_restricciones_no_miran_los_argumentos(guard):
    assert guard.authorize(ATENCION, "consultar_pedido", {}).action is Action.ALLOW
