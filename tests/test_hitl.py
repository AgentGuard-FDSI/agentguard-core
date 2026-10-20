"""Aprobación humana con separación de funciones: reglas, cola PENDING, registro y fail-closed."""

import threading
from dataclasses import dataclass
from pathlib import Path

import pytest

from agentguard import (
    Action,
    AgentGuard,
    ApprovalRequest,
    ApprovalRule,
    ApprovalService,
    AuditChain,
    ConsoleApprover,
    FixedApprover,
    InMemoryDirectory,
    ValidatingApprover,
    load_policies,
    puede_aprobar,
)
from agentguard.policy import parse_policies

POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "policies.yaml"


@dataclass(frozen=True)
class P:
    usuario: str
    area: str
    nivel: str


ANA = P("ana.atencion", "atencion_cliente", "empleado")
LAURA = P("laura.atencion", "atencion_cliente", "jefe")
LUIS = P("luis.logistica", "logistica_operaciones", "empleado")
LINA = P("lina.logistica", "logistica_operaciones", "jefe")
LUCAS = P("lucas.logistica", "logistica_operaciones", "jefe")
TOMAS = P("tomas.ti", "tecnologia_ti", "jefe")
GLORIA = P("gloria.gerencia", "gerencia", "gerente")
GABRIEL = P("gabriel.gerencia", "gerencia", "gerente")
FUERA = P("intruso", "area_que_no_existe", "jefe")


@pytest.fixture
def policy():
    return load_policies(POLICY_PATH)


@pytest.fixture
def directorio():
    return InMemoryDirectory([ANA, LAURA, LUIS, LINA, LUCAS, TOMAS, GLORIA, GABRIEL, FUERA])


@pytest.fixture
def servicio(policy, directorio):
    return ApprovalService(policy, directorio)


def solicitud(persona=LUIS, tool="eliminar_pedido", args=None):
    decision = AgentGuard.from_file(POLICY_PATH).authorize(persona, tool, args or {"order_id": "123"})
    return ApprovalRequest.from_decision(persona, tool, args or {"order_id": "123"}, decision)


# ---------------------------------------------------------------------------
# Quién puede aprobar
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("solicitante, aprobador, ok, regla", [
    # Un empleado: lo aprueba el jefe de su área o gerencia.
    (LUIS, LINA, True, None),
    (LUIS, LUCAS, True, None),
    (LUIS, GLORIA, True, None),
    (LUIS, LAURA, False, ApprovalRule.APROBADOR_AJENO_AL_AREA),     # jefe de otra área
    (LUIS, TOMAS, False, ApprovalRule.APROBADOR_AJENO_AL_AREA),
    (LUIS, ANA, False, ApprovalRule.APROBADOR_SIN_RANGO),           # empleado de otra área
    (LUIS, LUIS, False, ApprovalRule.AUTOAPROBACION),
    # Un jefe: otro jefe de su área o gerencia, nunca él mismo.
    (LINA, LINA, False, ApprovalRule.AUTOAPROBACION),
    (LINA, LUCAS, True, None),
    (LINA, GLORIA, True, None),
    (LINA, LUIS, False, ApprovalRule.APROBADOR_SIN_RANGO),          # su subordinado no la aprueba
    (LINA, LAURA, False, ApprovalRule.APROBADOR_AJENO_AL_AREA),
    # Un gerente: otro gerente.
    (GLORIA, GLORIA, False, ApprovalRule.AUTOAPROBACION),
    (GLORIA, GABRIEL, True, None),
    (GLORIA, LINA, False, ApprovalRule.APROBADOR_AJENO_AL_AREA),
    # Personas que no existen o con un área que la política no conoce.
    (LUIS, P("fantasma", "logistica_operaciones", "jefe"), False, ApprovalRule.APROBADOR_DESCONOCIDO),
    (LUIS, FUERA, False, ApprovalRule.APROBADOR_SIN_RANGO),
])
def test_reglas_de_aprobacion(policy, directorio, solicitante, aprobador, ok, regla):
    resultado, codigo, motivo = puede_aprobar(policy, directorio, solicitante, aprobador.usuario)
    assert (resultado, codigo) == (ok, regla), motivo
    assert motivo


@pytest.mark.parametrize("variante", ["LINA.LOGISTICA", " lina.logistica ", "Lina.Logistica\n"])
def test_la_autoaprobacion_no_se_evade_con_mayusculas_ni_espacios(policy, directorio, variante):
    ok, regla, _ = puede_aprobar(policy, directorio, LINA, variante)
    assert not ok and regla is ApprovalRule.AUTOAPROBACION


@pytest.mark.parametrize("aprobador", [None, "", 7, ["lina.logistica"]])
def test_aprobador_de_otro_tipo_no_es_valido(policy, directorio, aprobador):
    ok, regla, _ = puede_aprobar(policy, directorio, LUIS, aprobador)
    assert not ok and regla in {ApprovalRule.APROBADOR_DESCONOCIDO, ApprovalRule.AUTOAPROBACION}


def test_sin_area_de_aprobacion_final_gerencia_no_respalda(directorio):
    texto = POLICY_PATH.read_text(encoding="utf-8").replace("  aprobador_ultima_instancia: gerencia\n", "")
    policy = parse_policies(texto)
    assert policy.organization.final_approver_area is None
    assert puede_aprobar(policy, directorio, LUIS, GLORIA.usuario)[1] is ApprovalRule.APROBADOR_AJENO_AL_AREA
    assert puede_aprobar(policy, directorio, LUIS, LINA.usuario)[0]


# ---------------------------------------------------------------------------
# Cola de solicitudes
# ---------------------------------------------------------------------------
def test_una_solicitud_nueva_queda_pending_con_su_contexto(servicio):
    id_ = servicio.solicitar(solicitud(), run_id="run-7")
    s = servicio.obtener(id_)
    assert (s.estado, s.usuario, s.area, s.nivel, s.tool, s.run_id) == (
        "PENDING", "luis.logistica", "logistica_operaciones", "empleado", "eliminar_pedido", "run-7")
    assert dict(s.arguments) == {"order_id": "123"} and s.reason
    with pytest.raises(TypeError):
        s.arguments["order_id"] = "999"


def test_un_aprobador_valido_aprueba(servicio):
    id_ = servicio.solicitar(solicitud())
    r = servicio.decidir(id_, LINA.usuario, True, "ok")
    assert (r.approved, r.approver, r.rule) == (True, "lina.logistica", "")
    s = servicio.obtener(id_)
    assert (s.estado, s.aprobador, s.comentario) == ("APPROVED", "lina.logistica", "ok") and s.ts_decision


def test_un_aprobador_valido_puede_rechazar(servicio):
    id_ = servicio.solicitar(solicitud())
    r = servicio.decidir(id_, LINA.usuario, False, "no corresponde")
    assert not r.approved and r.rule == "" and r.approver == "lina.logistica"
    assert servicio.obtener(id_).estado == "REJECTED"


def test_un_aprobador_invalido_no_aprueba_y_la_solicitud_sigue_pendiente(servicio):
    id_ = servicio.solicitar(solicitud())
    r = servicio.decidir(id_, LUIS.usuario, True)
    assert not r.approved and r.rule == ApprovalRule.AUTOAPROBACION.value
    assert servicio.obtener(id_).estado == "PENDING"
    assert servicio.decidir(id_, LINA.usuario, True).approved  # luego sí la puede aprobar quien corresponde


def test_el_aprobador_se_guarda_con_el_nombre_del_directorio(servicio):
    id_ = servicio.solicitar(solicitud())
    r = servicio.decidir(id_, " LINA.LOGISTICA ", True)
    assert r.approved and r.approver == "lina.logistica"


def test_una_solicitud_decidida_no_se_puede_volver_a_decidir(servicio):
    id_ = servicio.solicitar(solicitud())
    assert servicio.decidir(id_, LINA.usuario, False).approver
    otra = servicio.decidir(id_, LUCAS.usuario, True)
    assert not otra.approved and otra.rule == ApprovalRule.SOLICITUD_YA_DECIDIDA.value
    assert servicio.obtener(id_).estado == "REJECTED"


def test_decidir_una_solicitud_que_no_existe(servicio):
    r = servicio.decidir(999, LINA.usuario, True)
    assert not r.approved and r.rule == ApprovalRule.SOLICITUD_NO_EXISTE.value


def test_dos_decisiones_simultaneas_solo_las_gana_una(servicio):
    id_ = servicio.solicitar(solicitud())
    resultados = []

    def decidir(aprobador, aprobar):
        resultados.append(servicio.decidir(id_, aprobador, aprobar))

    hilos = [threading.Thread(target=decidir, args=(a, i % 2 == 0))
             for i, a in enumerate([LINA.usuario, LUCAS.usuario, GLORIA.usuario, LINA.usuario])]
    [h.start() for h in hilos]
    [h.join() for h in hilos]
    ganadoras = [r for r in resultados if r.rule == ""]
    assert len(ganadoras) == 1
    assert servicio.obtener(id_).estado in {"APPROVED", "REJECTED"}


def test_pendientes_para_cada_aprobador(servicio):
    de_luis = servicio.solicitar(solicitud(LUIS))
    de_ana = servicio.solicitar(solicitud(ANA, "actualizar_pedido", {"order_id": "130", "estado": "delivered"}))
    de_lina = servicio.solicitar(solicitud(LINA))
    ids = lambda lista: [s.id for s in lista]
    assert ids(servicio.pendientes()) == [de_luis, de_ana, de_lina]
    assert ids(servicio.pendientes(para=LINA.usuario)) == [de_luis]          # no ve la suya
    assert ids(servicio.pendientes(para=LUCAS.usuario)) == [de_luis, de_lina]
    assert ids(servicio.pendientes(para=LAURA.usuario)) == [de_ana]
    assert ids(servicio.pendientes(para=GLORIA.usuario)) == [de_luis, de_ana, de_lina]
    assert ids(servicio.pendientes(para=LUIS.usuario)) == []


def test_anular_cierra_la_solicitud(servicio):
    id_ = servicio.solicitar(solicitud())
    servicio.anular(id_, "sin respuesta")
    s = servicio.obtener(id_)
    assert (s.estado, s.comentario) == ("ANULADA", "sin respuesta")
    assert servicio.decidir(id_, LINA.usuario, True).rule == ApprovalRule.SOLICITUD_YA_DECIDIDA.value


def test_las_solicitudes_persisten_en_el_archivo(policy, directorio, tmp_path):
    ruta = tmp_path / "hitl.db"
    primero = ApprovalService(policy, directorio, ruta)
    id_ = primero.solicitar(solicitud())
    primero.close()
    segundo = ApprovalService(policy, directorio, ruta)
    assert segundo.obtener(id_).estado == "PENDING" and len(segundo.pendientes()) == 1


# ---------------------------------------------------------------------------
# Registro en el log encadenado
# ---------------------------------------------------------------------------
def test_la_solicitud_y_la_decision_quedan_en_el_log_encadenado(policy, directorio):
    cadena = AuditChain()
    servicio = ApprovalService(policy, directorio, chain=cadena)
    id_ = servicio.solicitar(solicitud(), run_id="run-1")
    servicio.decidir(id_, LUIS.usuario, True)          # intento inválido
    servicio.decidir(id_, LINA.usuario, True, "ok")    # decisión válida
    tipos = [e.record["tipo"] for e in cadena.entries()]
    assert tipos == ["hitl_solicitada", "hitl_intento_rechazado", "hitl_decidida"]
    intento, decision = list(cadena.entries())[1:]
    assert intento.record["regla"] == "autoaprobacion" and intento.record["aprobador"] == "luis.logistica"
    assert decision.record["aprobador"] == "lina.logistica" and decision.record["estado"] == "APPROVED"
    assert decision.record["solicitante"] == "luis.logistica" and decision.record["arguments"] == {"order_id": "123"}
    assert cadena.verify().ok


class _CadenaQueFalla:
    def append(self, record):
        raise OSError("disco lleno")


def test_si_no_se_puede_registrar_la_decision_no_se_aprueba(policy, directorio):
    servicio = ApprovalService(policy, directorio, chain=None)
    id_ = servicio.solicitar(solicitud())
    servicio._chain = _CadenaQueFalla()
    with pytest.raises(OSError):
        servicio.decidir(id_, LINA.usuario, True)
    assert servicio.obtener(id_).estado == "PENDING"  # no quedó aprobada a medias


# ---------------------------------------------------------------------------
# ValidatingApprover: el flujo síncrono de la Config. B
# ---------------------------------------------------------------------------
def test_aprobador_valido_aprueba_y_queda_registrado(servicio):
    r = ValidatingApprover(servicio, FixedApprover(True, LINA.usuario)).request(solicitud())
    assert (r.approved, r.approver, r.rule) == (True, "lina.logistica", "")
    assert servicio.obtener(1).estado == "APPROVED"


def test_el_solicitante_no_se_puede_aprobar_a_si_mismo(servicio):
    r = ValidatingApprover(servicio, FixedApprover(True, LUIS.usuario)).request(solicitud())
    assert not r.approved and r.rule == "autoaprobacion"
    assert servicio.obtener(1).estado == "ANULADA" and servicio.pendientes() == []


def test_un_aprobador_automatico_desconocido_no_aprueba(servicio):
    r = ValidatingApprover(servicio, FixedApprover(True)).request(solicitud())  # "aprobador_automatico"
    assert not r.approved and r.rule == "aprobador_desconocido"


def test_el_rechazo_de_un_aprobador_valido_se_respeta(servicio):
    r = ValidatingApprover(servicio, FixedApprover(False, LINA.usuario)).request(solicitud())
    assert not r.approved and r.rule == ""
    assert servicio.obtener(1).estado == "REJECTED"


def test_sin_respuesta_por_consola_se_anula(servicio):
    def sin_stdin(_prompt):
        raise EOFError

    consola = ConsoleApprover(input_fn=sin_stdin, output_fn=lambda _t: None)
    r = ValidatingApprover(servicio, consola).request(solicitud())
    assert not r.approved and servicio.obtener(1).estado == "ANULADA"


def test_por_consola_el_aprobador_se_valida(servicio):
    respuestas = iter(["luis.logistica", "s", "lina.logistica", "s"])
    consola = ConsoleApprover(input_fn=lambda _p: next(respuestas), output_fn=lambda _t: None)
    validador = ValidatingApprover(servicio, consola)
    assert not validador.request(solicitud()).approved   # se quiso autoaprobar
    assert validador.request(solicitud()).approved       # lo aprueba su jefa


def test_si_falla_el_registro_la_solicitud_no_se_aprueba(policy, directorio):
    servicio = ApprovalService(policy, directorio, chain=_CadenaQueFalla())
    r = ValidatingApprover(servicio, FixedApprover(True, LINA.usuario)).request(solicitud())
    assert not r.approved and "no se pudo registrar" in r.comment


def test_el_run_id_se_guarda_en_la_solicitud(servicio):
    ValidatingApprover(servicio, FixedApprover(True, LINA.usuario), run_id="B-inyeccion-1").request(solicitud())
    assert servicio.obtener(1).run_id == "B-inyeccion-1"


# ---------------------------------------------------------------------------
# Escenario 9: un jefe pide eliminar y trata de aprobarlo él mismo
# ---------------------------------------------------------------------------
def test_escenario_9_autoaprobacion_del_jefe(servicio):
    guard = AgentGuard.from_file(POLICY_PATH)
    decision = guard.authorize(LINA, "eliminar_pedido", {"order_id": "123"})
    assert decision.action is Action.HITL
    req = ApprovalRequest.from_decision(LINA, "eliminar_pedido", {"order_id": "123"}, decision)
    propio = ValidatingApprover(servicio, FixedApprover(True, LINA.usuario)).request(req)
    assert not propio.approved and propio.rule == "autoaprobacion"
    otro = ValidatingApprover(servicio, FixedApprover(True, LUCAS.usuario)).request(req)
    assert otro.approved                                                        # otro jefe del área
    gerencia = ValidatingApprover(servicio, FixedApprover(True, GLORIA.usuario)).request(req)
    assert gerencia.approved                                                    # o gerencia, como respaldo
