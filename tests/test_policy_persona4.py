"""Lector de policies.yaml: secciones verificador_entrada y regla_entre_areas (esquema estricto)."""

import copy

import pytest
import yaml

from agentguard.policy import PolicyError, parse_policies

BASE = {
    "version": 1,
    "session": {"identity_source": "session"},
    "areas": {
        "finanzas": {"levels": ["empleado", "jefe"]},
        "tecnologia_ti": {"levels": ["empleado", "jefe"]},
    },
    "tools": {"leer_base_datos": {"areas": ["finanzas", "tecnologia_ti"], "risk": "MEDIUM", "action": "ALLOW"}},
    "verificador_entrada": {
        "habilitado": True,
        "temas": ["pii_masiva", "config_interna"],
        "notificar_area": "tecnologia_ti",
        "area_propietaria": {"config_interna": "tecnologia_ti"},
    },
    "regla_entre_areas": {
        "habilitada": True,
        "alerta_tras": {"intentos": 3, "ventana_minutos": 10},
        "notificar_alerta": "tecnologia_ti",
    },
}


def cargar(cambio=None):
    data = copy.deepcopy(BASE)
    if cambio:
        cambio(data)
    return parse_policies(yaml.safe_dump(data, allow_unicode=True))


def test_politica_base_valida():
    p = cargar()
    assert p.input_guard.enabled and p.input_guard.topics == ("pii_masiva", "config_interna")
    assert p.input_guard.reject_message == "No puedo ayudarte con esta solicitud."
    assert (p.cross_area.attempts, p.cross_area.window_minutes, p.cross_area.alert_area) == (3, 10, "tecnologia_ti")


def test_las_secciones_son_opcionales():
    p = cargar(lambda d: (d.pop("verificador_entrada"), d.pop("regla_entre_areas")))
    assert not p.input_guard.enabled and not p.cross_area.enabled


def test_la_configuracion_es_inmutable():
    p = cargar()
    with pytest.raises(Exception):
        p.input_guard.enabled = False
    with pytest.raises(TypeError):
        p.input_guard.topic_owner["pii_masiva"] = "finanzas"


@pytest.mark.parametrize("cambio, mensaje", [
    (lambda d: d["verificador_entrada"].update(temas=["pii_masiva", "chismes"]), "temas desconocidos"),
    (lambda d: d["verificador_entrada"].update(temas=[]), "lista no vacía"),
    (lambda d: d["verificador_entrada"].update(habilitado="si"), "true o false"),
    (lambda d: d["verificador_entrada"].update(notificar_area="seguridad"), "áreas no declaradas"),
    (lambda d: d["verificador_entrada"].pop("notificar_area"), "faltan claves"),
    (lambda d: d["verificador_entrada"].update(mensaje_rechazo="  "), "texto no vacío"),
    (lambda d: d["verificador_entrada"].update(tema="pii_masiva"), "claves desconocidas"),
    (lambda d: d["verificador_entrada"].update(area_propietaria={"credenciales": "tecnologia_ti"}), "no está en"),
    (lambda d: d["verificador_entrada"].update(area_propietaria={"config_interna": "seguridad"}), "áreas no declaradas"),
    (lambda d: d["regla_entre_areas"].update(habilitada=1), "true o false"),
    (lambda d: d["regla_entre_areas"]["alerta_tras"].update(intentos=0), "mayor o igual a 1"),
    (lambda d: d["regla_entre_areas"]["alerta_tras"].update(ventana_minutos="10"), "mayor o igual a 1"),
    (lambda d: d["regla_entre_areas"]["alerta_tras"].update(minutos=10), "claves desconocidas"),
    (lambda d: d["regla_entre_areas"].update(notificar_alerta="seguridad"), "áreas no declaradas"),
    (lambda d: d["regla_entre_areas"].pop("alerta_tras"), "faltan claves"),
])
def test_rechaza_configuraciones_invalidas(cambio, mensaje):
    with pytest.raises(PolicyError, match=mensaje):
        cargar(cambio)
