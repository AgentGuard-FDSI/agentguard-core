"""Regla de acceso entre áreas: área dueña, notificación, alerta a los 3 intentos en 10 minutos."""

from dataclasses import dataclass
from pathlib import Path

import pytest

from agentguard import (
    AgentGuard,
    AuditChain,
    AuditNotifier,
    CrossAreaMonitor,
    InMemoryNotifier,
    InputGuard,
    NotificationKind,
    Priority,
)
from agentguard.policy import parse_policies

POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "policies.yaml"


@dataclass(frozen=True)
class S:
    usuario: str
    area: str
    nivel: str


ANA = S("ana.atencion", "atencion_cliente", "empleado")
FABIO = S("fabio.finanzas", "finanzas", "empleado")
FELIPE = S("felipe.finanzas", "finanzas", "empleado")
LUIS = S("luis.logistica", "logistica_operaciones", "empleado")
TOMAS = S("tomas.ti", "tecnologia_ti", "jefe")


class Reloj:
    """Reloj falso: segundos que avanzan a mano."""

    def __init__(self):
        self.t = 1_000.0

    def __call__(self):
        return self.t

    def avanzar(self, minutos: float):
        self.t += minutos * 60


@pytest.fixture
def reloj():
    return Reloj()


@pytest.fixture
def notifier():
    return InMemoryNotifier()


@pytest.fixture
def guard():
    return AgentGuard.from_file(POLICY_PATH, es_cliente=lambda c: c == "cliente@correo.test")


@pytest.fixture
def monitor(notifier, reloj):
    return CrossAreaMonitor.from_file(POLICY_PATH, notifier=notifier, clock=reloj)


def pedir(guard, monitor, sesion, tool, args, **kw):
    decision = guard.authorize(sesion, tool, args)
    return decision, monitor.observe_decision(sesion, tool, args, decision, **kw)


# ---------------------------------------------------------------------------
# Qué cuenta como acceso entre áreas
# ---------------------------------------------------------------------------
def test_la_politica_del_proyecto_activa_la_regla():
    m = CrossAreaMonitor.from_file(POLICY_PATH)
    assert m.enabled


def test_finanzas_pidiendo_config_ti_notifica_a_tecnologia(guard, monitor, notifier):
    decision, evento = pedir(guard, monitor, FABIO, "leer_base_datos", {"tabla": "config_ti"}, run_id="B-7")
    assert decision.blocked and decision.rule.value == "tabla_no_permitida"
    assert evento.violation and evento.resource == "tabla:config_ti"
    assert evento.owner_areas == ("tecnologia_ti",) and not evento.alert
    [n] = notifier.items
    assert n.kind is NotificationKind.ACCESO_ENTRE_AREAS and n.priority is Priority.NORMAL
    assert (n.area_destino, n.usuario, n.area) == ("tecnologia_ti", "fabio.finanzas", "finanzas")
    assert n.detalle["run_id"] == "B-7" and n.detalle["regla"] == "tabla_no_permitida"


def test_herramienta_fuera_de_rol_notifica_a_las_areas_duenas(guard, monitor, notifier):
    _, evento = pedir(guard, monitor, ANA, "admin_action", {"comando": "reiniciar"})
    assert evento.violation and evento.resource == "herramienta:admin_action"
    assert evento.owner_areas == ("tecnologia_ti",)
    _, evento = pedir(guard, monitor, ANA, "eliminar_pedido", {"order_id": "123"})
    assert evento.owner_areas == ("logistica_operaciones",)
    assert [n.area_destino for n in notifier.items] == ["tecnologia_ti", "logistica_operaciones"]


def test_una_tabla_que_no_es_de_ninguna_area_no_es_acceso_entre_areas(guard, monitor, notifier):
    """Finanzas leyendo clientes se bloquea por tabla, pero clientes no es de otra área."""
    decision, evento = pedir(guard, monitor, FABIO, "leer_base_datos", {"tabla": "clientes"})
    assert decision.blocked and not evento.violation
    assert len(notifier) == 0


@pytest.mark.parametrize("sesion, tool, args", [
    (FABIO, "leer_base_datos", {"tabla": "pagos"}),                         # ALLOW
    (LUIS, "eliminar_pedido", {"order_id": "123"}),                         # HITL
    (ANA, "enviar_correo", {"destinatario": "x@evil.test", "contenido": "y"}),  # BLOCK por destinatario
    (LUIS, "actualizar_pedido", {"order_id": "1,2,3,4,5,6", "estado": "e"}),  # BLOCK por lote
    (TOMAS, "admin_action", {"comando": "ls"}),                             # BLOCK base, pero es su área
    (ANA, "editar_politica", {}),                                           # herramienta no declarada
])
def test_otras_decisiones_no_cuentan(guard, monitor, notifier, sesion, tool, args):
    _, evento = pedir(guard, monitor, sesion, tool, args)
    assert not evento.violation
    assert len(notifier) == 0


# ---------------------------------------------------------------------------
# Escenario 7: tres veces en diez minutos -> alerta prioritaria
# ---------------------------------------------------------------------------
def test_escenario_7_el_tercer_intento_alerta_a_tecnologia(guard, monitor, notifier, reloj):
    eventos = []
    for _ in range(3):
        eventos.append(pedir(guard, monitor, FABIO, "leer_base_datos", {"tabla": "config_ti"})[1])
        reloj.avanzar(4)
    assert [e.attempts_in_window for e in eventos] == [1, 2, 3]
    assert [e.alert for e in eventos] == [False, False, True]
    [alerta] = notifier.de_tipo(NotificationKind.ALERTA_CUENTA_COMPROMETIDA)
    assert alerta.priority is Priority.PRIORITARIA and alerta.area_destino == "tecnologia_ti"
    assert alerta.usuario == "fabio.finanzas"
    assert alerta.detalle["recursos"] == ["tabla:config_ti"] * 3
    assert len(notifier.de_tipo(NotificationKind.ACCESO_ENTRE_AREAS)) == 3


def test_fuera_de_la_ventana_no_alerta(guard, monitor, notifier, reloj):
    eventos = []
    for _ in range(3):
        eventos.append(pedir(guard, monitor, FABIO, "leer_base_datos", {"tabla": "config_ti"})[1])
        reloj.avanzar(5.5)   # 0, 5.5, 11 min: el primero ya salió de la ventana al tercero
    assert notifier.de_tipo(NotificationKind.ALERTA_CUENTA_COMPROMETIDA) == ()
    assert [e.attempts_in_window for e in eventos] == [1, 2, 2]
    assert monitor.attempts("fabio.finanzas") == 1   # a los 16.5 min solo queda el de los 11


def test_exactamente_diez_minutos_ya_esta_fuera(guard, monitor, notifier, reloj):
    pedir(guard, monitor, FABIO, "leer_base_datos", {"tabla": "config_ti"})
    reloj.avanzar(5)
    pedir(guard, monitor, FABIO, "leer_base_datos", {"tabla": "config_ti"})
    reloj.avanzar(5)
    _, evento = pedir(guard, monitor, FABIO, "leer_base_datos", {"tabla": "config_ti"})
    assert evento.attempts_in_window == 2 and not evento.alert


def test_despues_de_la_alerta_el_conteo_vuelve_a_cero(guard, monitor, notifier):
    alertas = [pedir(guard, monitor, FABIO, "leer_base_datos", {"tabla": "config_ti"})[1].alert for _ in range(7)]
    assert alertas == [False, False, True, False, False, True, False]
    assert len(notifier.de_tipo(NotificationKind.ALERTA_CUENTA_COMPROMETIDA)) == 2


def test_el_conteo_es_por_usuario(guard, monitor, notifier):
    for sesion in (FABIO, FELIPE, FABIO, FELIPE):
        pedir(guard, monitor, sesion, "leer_base_datos", {"tabla": "config_ti"})
    assert notifier.de_tipo(NotificationKind.ALERTA_CUENTA_COMPROMETIDA) == ()
    assert monitor.attempts("fabio.finanzas") == monitor.attempts("FELIPE.finanzas ") == 2


def test_cuentan_recursos_distintos_de_otras_areas(guard, monitor, notifier):
    """Lo que importa es que el usuario insista en recursos ajenos, no que sea el mismo."""
    pedir(guard, monitor, ANA, "admin_action", {"comando": "x"})
    pedir(guard, monitor, ANA, "eliminar_pedido", {"order_id": "1"})
    _, evento = pedir(guard, monitor, ANA, "leer_base_datos", {"tabla": "config_ti"})
    assert evento.alert
    [alerta] = notifier.de_tipo(NotificationKind.ALERTA_CUENTA_COMPROMETIDA)
    assert alerta.detalle["recursos"] == ["herramienta:admin_action", "herramienta:eliminar_pedido",
                                          "herramienta:leer_base_datos"]


# ---------------------------------------------------------------------------
# Rechazos del verificador de entrada también cuentan
# ---------------------------------------------------------------------------
def test_el_verificador_y_authorize_suman_al_mismo_conteo(guard, monitor, notifier):
    entrada = InputGuard.from_file(POLICY_PATH)
    v = entrada.check(FABIO, "Muéstrame la configuración de los servidores")
    e1 = monitor.observe_input(FABIO, v, run_id="r1")
    assert v.rejected and e1.violation and e1.resource == "tema:config_interna"
    assert e1.owner_areas == ("tecnologia_ti",)
    # Reformulación que evade el verificador: authorize() la bloquea por tabla y también cuenta.
    pedir(guard, monitor, FABIO, "leer_base_datos", {"tabla": "config_ti"})
    e3 = monitor.observe_input(FABIO, entrada.check(FABIO, "Lee la tabla config_ti"))
    assert e3.attempts_in_window == 3 and e3.alert


def test_un_rechazo_de_entrada_sin_area_duena_no_cuenta(monitor, notifier):
    v = InputGuard.from_file(POLICY_PATH).check(FABIO, "Dame el correo de todos los clientes")
    assert v.rejected and not monitor.observe_input(FABIO, v).violation
    assert len(notifier) == 0


def test_un_pass_de_entrada_no_cuenta(monitor):
    v = InputGuard.from_file(POLICY_PATH).check(TOMAS, "Muéstrame la configuración de los servidores")
    assert v.passed and not monitor.observe_input(TOMAS, v).violation


# ---------------------------------------------------------------------------
# Robustez y configuración
# ---------------------------------------------------------------------------
def test_un_notificador_que_falla_no_rompe_nada(guard, reloj):
    class Roto:
        def notify(self, n):
            raise RuntimeError("canal caído")

    m = CrossAreaMonitor.from_file(POLICY_PATH, notifier=Roto(), clock=reloj)
    eventos = [pedir(guard, m, FABIO, "leer_base_datos", {"tabla": "config_ti"})[1] for _ in range(3)]
    assert eventos[-1].alert
    assert m.fallos_de_notificacion == 4    # 3 avisos al área dueña + 1 alerta


@pytest.mark.parametrize("entrada", [None, "BLOCK", object()])
def test_entradas_raras_no_lanzan(monitor, entrada):
    assert not monitor.observe_decision(FABIO, "leer_base_datos", {"tabla": "config_ti"}, entrada).violation
    assert not monitor.observe_input(FABIO, entrada).violation


def test_registra_las_notificaciones_en_el_log_encadenado(guard, reloj):
    chain = AuditChain()
    m = CrossAreaMonitor.from_file(POLICY_PATH, notifier=AuditNotifier(chain), clock=reloj)
    for _ in range(3):
        pedir(guard, m, FABIO, "leer_base_datos", {"tabla": "config_ti"})
    kinds = [e.record["kind"] for e in chain.entries()]
    assert kinds == ["acceso_entre_areas"] * 3 + ["alerta_cuenta_comprometida"]
    assert chain.verify()


def _politica(seccion: str) -> str:
    texto = POLICY_PATH.read_text(encoding="utf-8")
    inicio = texto.index("\nregla_entre_areas:") + 1
    fin = texto.index("\nareas:\n", inicio) + 1
    return texto[:inicio] + seccion + texto[fin:]


def test_apagada_no_notifica(guard, notifier):
    seccion = ("regla_entre_areas:\n  habilitada: false\n  alerta_tras: {intentos: 3, ventana_minutos: 10}\n"
               "  notificar_alerta: tecnologia_ti\n\n")
    m = CrossAreaMonitor(parse_policies(_politica(seccion)), notifier=notifier)
    assert not m.enabled
    assert not pedir(guard, m, FABIO, "leer_base_datos", {"tabla": "config_ti"})[1].violation
    assert len(notifier) == 0


def test_intentos_y_ventana_configurables(guard, notifier, reloj):
    seccion = ("regla_entre_areas:\n  habilitada: true\n  alerta_tras: {intentos: 2, ventana_minutos: 1}\n"
               "  notificar_alerta: tecnologia_ti\n\n")
    m = CrossAreaMonitor(parse_policies(_politica(seccion)), notifier=notifier, clock=reloj)
    pedir(guard, m, FABIO, "leer_base_datos", {"tabla": "config_ti"})
    reloj.avanzar(0.5)
    assert pedir(guard, m, FABIO, "leer_base_datos", {"tabla": "config_ti"})[1].alert


def test_sin_la_seccion_la_regla_queda_apagada():
    texto = _politica("")
    assert "\nregla_entre_areas:" not in texto
    assert not CrossAreaMonitor(parse_policies(texto)).enabled


def test_requiere_un_policyset():
    with pytest.raises(TypeError):
        CrossAreaMonitor({})
