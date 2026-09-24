from pathlib import Path

import pytest

from agentguard import AgentGuard, Decision, Session, load_policy

POLICY_PATH = Path(__file__).resolve().parent.parent / "policies.example.yaml"
not_yet = pytest.mark.xfail(raises=NotImplementedError, reason="authorize() se implementa en el Avance 2")


def test_decision_values():
    assert {d.value for d in Decision} == {"ALLOW", "BLOCK", "HITL"}


def test_policy_loads_and_lists_the_six_tools():
    policy = load_policy(str(POLICY_PATH))
    assert set(policy["tools"]) == {
        "consultar_pedido", "actualizar_pedido", "eliminar_pedido",
        "enviar_correo", "leer_base_datos", "admin_action",
    }


@not_yet
def test_allow_read_within_area():
    guard = AgentGuard.from_yaml(str(POLICY_PATH))
    session = Session(user="ana", area="atencion_cliente", level="empleado")
    assert guard.authorize(session, "consultar_pedido", {"order_id": "123"}).decision is Decision.ALLOW


@not_yet
def test_block_tool_outside_area():
    guard = AgentGuard.from_yaml(str(POLICY_PATH))
    session = Session(user="ana", area="atencion_cliente", level="empleado")
    assert guard.authorize(session, "admin_action", {"comando": "reiniciar"}).decision is Decision.BLOCK


@not_yet
def test_hitl_on_write():
    guard = AgentGuard.from_yaml(str(POLICY_PATH))
    session = Session(user="luis", area="logistica_operaciones", level="empleado")
    assert guard.authorize(session, "eliminar_pedido", {"order_id": "123"}).decision is Decision.HITL
