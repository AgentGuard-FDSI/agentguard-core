from dataclasses import dataclass

import pytest

from agentguard import Action, ApprovalRequest, ConsoleApprover, Decision, FixedApprover, Rule


@dataclass(frozen=True)
class Session:
    usuario: str
    area: str
    nivel: str


SESION = Session("luis.logistica", "logistica_operaciones", "empleado")
DECISION = Decision(Action.HITL, "eliminar_pedido: requiere aprobación humana (riesgo HIGH)", Rule.ACCION_BASE)


def request() -> ApprovalRequest:
    return ApprovalRequest.from_decision(SESION, "eliminar_pedido", {"order_id": "123"}, DECISION)


def console(respuestas):
    it = iter(respuestas)
    salida: list[str] = []
    return ConsoleApprover(input_fn=lambda _prompt: next(it), output_fn=salida.append), salida


def test_la_solicitud_copia_sesion_herramienta_y_motivo():
    req = request()
    assert (req.usuario, req.area, req.nivel, req.tool) == (
        "luis.logistica", "logistica_operaciones", "empleado", "eliminar_pedido")
    assert dict(req.arguments) == {"order_id": "123"}
    assert req.reason == DECISION.reason


def test_los_argumentos_de_la_solicitud_no_se_pueden_modificar():
    args = {"order_id": "123"}
    req = ApprovalRequest.from_decision(SESION, "eliminar_pedido", args, DECISION)
    args["order_id"] = "999"  # cambiar el dict original no altera lo que se aprobó
    assert req.arguments["order_id"] == "123"
    with pytest.raises(TypeError):
        req.arguments["order_id"] = "999"


@pytest.mark.parametrize("respuesta", ["s", "S", "si", "sí", "y"])
def test_consola_aprueba(respuesta):
    aprobador, salida = console(["lina.logistica", respuesta])
    resultado = aprobador.request(request())
    assert resultado.approved and resultado.approver == "lina.logistica"
    assert any("eliminar_pedido" in linea for linea in salida)


@pytest.mark.parametrize("respuesta", ["n", "no", ""])
def test_consola_rechaza_y_vacio_es_no(respuesta):
    aprobador, _ = console(["lina.logistica", respuesta])
    assert not aprobador.request(request()).approved


def test_consola_repite_ante_respuesta_invalida():
    aprobador, salida = console(["lina", "quizas", "s"])
    assert aprobador.request(request()).approved
    assert "Responde 's' o 'n'." in salida


def test_fixed_approver_no_pregunta_y_guarda_las_solicitudes():
    aprobador = FixedApprover(approve=False)
    assert not aprobador.request(request()).approved
    assert len(aprobador.requests) == 1
    assert FixedApprover(approve=True).request(request()).approved


def test_consola_sin_respuesta_rechaza_en_vez_de_fallar():
    """Si stdin se cierra (EOF) o se interrumpe, la solicitud se rechaza: fail-closed."""
    for error in (EOFError, KeyboardInterrupt):
        def sin_respuesta(_prompt, error=error):
            raise error
        salida: list[str] = []
        resultado = ConsoleApprover(input_fn=sin_respuesta, output_fn=salida.append).request(request())
        assert not resultado.approved
        assert resultado.approver == "sin_respuesta"
