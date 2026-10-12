"""Regla: la política es de solo lectura para el agente (docs/arquitectura.md, "Reglas del motor").

El agente no puede escribir en config/ ni cambiar la política en ejecución:
  1. no existe ninguna herramienta que edite la política, y cualquier herramienta no declarada es BLOCK;
  2. el PolicySet cargado es inmutable;
  3. el AgentGuard no permite reemplazar su política.
"""

import dataclasses
from pathlib import Path

import pytest

from agentguard import Action, AgentGuard, Rule, load_policies

POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "policies.yaml"


@dataclasses.dataclass(frozen=True)
class Session:
    usuario: str
    area: str
    nivel: str


TI_JEFE = Session("tomas.ti", "tecnologia_ti", "jefe")


@pytest.fixture()
def guard() -> AgentGuard:
    return AgentGuard.from_file(POLICY_PATH)


@pytest.mark.parametrize("tool", [
    "editar_politica", "write_file", "escribir_archivo", "actualizar_policies",
    "modificar_config", "update_policy",
])
def test_herramientas_que_tocarian_la_politica_son_block(guard, tool):
    d = guard.authorize(TI_JEFE, tool, {"path": "config/policies.yaml", "contenido": "action: ALLOW"})
    assert (d.action, d.rule) == (Action.BLOCK, Rule.HERRAMIENTA_NO_DECLARADA)


def test_la_politica_no_declara_herramientas_de_archivos_ni_de_politica():
    nombres = set(load_policies(POLICY_PATH).tools)
    prohibidas = ("polic", "config", "file", "archivo", "yaml")
    assert not [n for n in nombres if any(p in n for p in prohibidas)]


def test_policyset_es_inmutable(guard):
    policy = guard.policy
    with pytest.raises(dataclasses.FrozenInstanceError):
        policy.version = 2
    with pytest.raises(TypeError):
        policy.tools["admin_action"] = policy.tools["consultar_pedido"]
    with pytest.raises(dataclasses.FrozenInstanceError):
        policy.tools["admin_action"].action = Action.ALLOW
    with pytest.raises(AttributeError):
        policy.tools["admin_action"].areas.add("atencion_cliente")


def test_agentguard_no_permite_reemplazar_la_politica(guard):
    otra = load_policies(POLICY_PATH)
    with pytest.raises(AttributeError):
        guard.policy = otra
    with pytest.raises(AttributeError):
        guard._policy = otra
    with pytest.raises(AttributeError):
        guard.nuevo_atributo = 1
    with pytest.raises(AttributeError):
        del guard._policy


def test_agentguard_exige_una_politica_validada():
    with pytest.raises(TypeError):
        AgentGuard({"tools": {}})
