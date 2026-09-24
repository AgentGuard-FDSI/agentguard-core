import copy
import dataclasses
from pathlib import Path

import pytest
import yaml

from agentguard.policy import Action, PolicyError, Risk, load_policies, parse_policies

POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "policies.yaml"


def base_policy() -> dict:
    """Política mínima válida para construir casos inválidos a partir de ella."""
    return {
        "version": 1,
        "session": {"identity_source": "session"},
        "areas": {
            "finanzas": {"description": "Finanzas", "levels": ["empleado", "jefe"]},
            "tecnologia_ti": {"levels": ["empleado", "jefe"]},
        },
        "tools": {
            "leer_base_datos": {
                "areas": ["finanzas", "tecnologia_ti"],
                "risk": "MEDIUM",
                "action": "ALLOW",
                "args": {"table_by_area": {"finanzas": ["pagos"], "tecnologia_ti": ["config_ti"]}},
            },
        },
    }


def parse_dict(data: dict):
    return parse_policies(yaml.safe_dump(data, allow_unicode=True))


# ---------------------------------------------------------------------------
# Política real del proyecto
# ---------------------------------------------------------------------------
def test_carga_la_politica_del_proyecto():
    policy = load_policies(POLICY_PATH)
    assert set(policy.tools) == {
        "consultar_pedido", "actualizar_pedido", "eliminar_pedido",
        "enviar_correo", "leer_base_datos", "admin_action",
    }
    assert set(policy.areas) == {
        "atencion_cliente", "logistica_operaciones", "marketing_comunicaciones",
        "tecnologia_ti", "finanzas", "gerencia",
    }
    assert policy.session.identity_source == "session"


def test_valores_de_la_tabla_3_2():
    policy = load_policies(POLICY_PATH)
    admin = policy.get_tool("admin_action")
    assert (admin.risk, admin.action) == (Risk.CRITICAL, Action.BLOCK)
    assert policy.get_tool("consultar_pedido").action is Action.ALLOW
    assert policy.get_tool("actualizar_pedido").args.max_items_per_request == 5
    assert policy.get_tool("eliminar_pedido").args.max_items_per_request == 1
    assert policy.get_tool("eliminar_pedido").areas == {"logistica_operaciones"}
    assert policy.get_tool("enviar_correo").args.recipient_in == (
        "clientes_registrados", "dominio_corporativo",
    )
    tba = policy.get_tool("leer_base_datos").args.table_by_area
    assert tba["finanzas"] == ("pagos", "pedidos")
    assert tba["tecnologia_ti"] == ("config_ti", "audit_logs")


def test_herramientas_por_area():
    policy = load_policies(POLICY_PATH)
    assert policy.tools_for_area("finanzas") == ("leer_base_datos",)
    assert policy.tools_for_area("gerencia") == ()
    assert policy.tools_for_area("area_inexistente") == ()
    assert "admin_action" not in policy.tools_for_area("logistica_operaciones")


def test_herramienta_no_declarada_devuelve_none():
    assert load_policies(POLICY_PATH).get_tool("borrar_todo") is None


def test_la_politica_es_inmutable():
    policy = load_policies(POLICY_PATH)
    with pytest.raises(TypeError):
        policy.tools["admin_action"] = None
    with pytest.raises(dataclasses.FrozenInstanceError):
        policy.get_tool("admin_action").action = Action.ALLOW
    with pytest.raises(TypeError):
        policy.get_tool("leer_base_datos").args.table_by_area["finanzas"] = ("clientes",)


# ---------------------------------------------------------------------------
# Casos inválidos: la política debe rechazarse completa (fail-closed)
# ---------------------------------------------------------------------------
def _mutate(fn):
    data = copy.deepcopy(base_policy())
    fn(data)
    return data


INVALIDOS = {
    "area_desconocida_en_herramienta": lambda d: d["tools"]["leer_base_datos"]["areas"].append("ventas"),
    "accion_en_minusculas": lambda d: d["tools"]["leer_base_datos"].update(action="allow"),
    "riesgo_inexistente": lambda d: d["tools"]["leer_base_datos"].update(risk="EXTREME"),
    "clave_desconocida_en_args": lambda d: d["tools"]["leer_base_datos"]["args"].update(max_item_per_request=5),
    "clave_desconocida_en_herramienta": lambda d: d["tools"]["leer_base_datos"].update(allow_all=True),
    "clave_desconocida_en_raiz": lambda d: d.update(debug=True),
    "falta_action": lambda d: d["tools"]["leer_base_datos"].pop("action"),
    "table_by_area_con_area_sin_la_herramienta": lambda d: d["areas"].update(gerencia={"levels": ["gerente"]})
        or d["tools"]["leer_base_datos"]["args"]["table_by_area"].update(gerencia=["clientes"]),
    "identidad_desde_el_prompt": lambda d: d["session"].update(identity_source="prompt"),
    "version_no_soportada": lambda d: d.update(version=2),
    "max_items_cero": lambda d: d["tools"]["leer_base_datos"]["args"].update(max_items_per_request=0),
    "max_items_booleano": lambda d: d["tools"]["leer_base_datos"]["args"].update(max_items_per_request=True),
    "destinatario_desconocido": lambda d: d["tools"]["leer_base_datos"]["args"].update(recipient_in=["cualquiera"]),
    "areas_vacias_en_herramienta": lambda d: d["tools"]["leer_base_datos"].update(areas=[]),
    "area_repetida": lambda d: d["tools"]["leer_base_datos"].update(areas=["finanzas", "finanzas"]),
    "sin_herramientas": lambda d: d.update(tools={}),
}


@pytest.mark.parametrize("caso", sorted(INVALIDOS))
def test_rechaza_politicas_invalidas(caso):
    with pytest.raises(PolicyError):
        parse_dict(_mutate(INVALIDOS[caso]))


def test_la_base_de_las_pruebas_es_valida():
    assert parse_dict(base_policy()).get_tool("leer_base_datos") is not None


def test_rechaza_claves_duplicadas():
    texto = yaml.safe_dump(base_policy()) + "tools: {}\n"  # 'tools' aparece dos veces
    with pytest.raises(PolicyError, match="duplicada"):
        parse_policies(texto)


def test_no_ejecuta_etiquetas_de_python():
    texto = "version: !!python/object/apply:os.system ['echo pwned']\n"
    with pytest.raises(PolicyError):
        parse_policies(texto)


def test_yaml_mal_formado():
    with pytest.raises(PolicyError, match="YAML inválido"):
        parse_policies("tools: [sin cerrar\n")


def test_archivo_inexistente(tmp_path):
    with pytest.raises(PolicyError, match="No se encontró"):
        load_policies(tmp_path / "no_existe.yaml")
