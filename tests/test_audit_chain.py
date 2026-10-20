"""Registro de auditoría encadenado: integridad, detección de alteraciones y concurrencia."""

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path

import pytest

from agentguard import Action, AgentGuard, AuditChain
from agentguard.audit import GENESIS_HASH
from agentguard.audit_cli import main as cli

POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "policies.yaml"


@dataclass(frozen=True)
class Session:
    usuario: str
    area: str
    nivel: str


ANA = Session("ana.atencion", "atencion_cliente", "empleado")


def llenar(chain, n=5):
    return [chain.append({"tipo": "decision", "n": i, "texto": f"entrada {i}"}) for i in range(1, n + 1)]


def tocar(db, sql, *params):
    """Altera la base por fuera de AuditChain, como lo haría alguien con acceso al archivo."""
    conn = sqlite3.connect(db)
    conn.execute(sql, params)
    conn.commit()
    conn.close()


@pytest.fixture
def db(tmp_path):
    return tmp_path / "audit.db"


# ---------------------------------------------------------------------------
# Comportamiento normal
# ---------------------------------------------------------------------------
def test_una_cadena_vacia_es_valida():
    r = AuditChain().verify()
    assert r.ok and r.checked == 0 and r.head is None


def test_la_primera_entrada_parte_del_hash_de_genesis():
    e = AuditChain().append({"a": 1})
    assert (e.seq, e.prev_hash) == (1, GENESIS_HASH)


def test_cada_entrada_enlaza_con_el_hash_de_la_anterior():
    entradas = llenar(AuditChain(), 4)
    assert [e.seq for e in entradas] == [1, 2, 3, 4]
    for anterior, actual in zip(entradas, entradas[1:]):
        assert actual.prev_hash == anterior.hash


def test_el_hash_es_sha256_de_seq_ts_prev_y_contenido_canonico():
    chain = AuditChain(clock=lambda: "2026-10-16T00:00:00+00:00")
    e = chain.append({"b": 2, "a": 1})
    esperado = hashlib.sha256(f'1|2026-10-16T00:00:00+00:00|{GENESIS_HASH}|{{"a":1,"b":2}}'.encode()).hexdigest()
    assert e.hash == esperado


def test_el_orden_de_las_claves_no_cambia_el_hash():
    a = AuditChain(clock=lambda: "t").append({"x": 1, "y": 2})
    b = AuditChain(clock=lambda: "t").append({"y": 2, "x": 1})
    assert a.hash == b.hash


def test_una_cadena_integra_verifica(db):
    chain = AuditChain(db)
    llenar(chain, 20)
    r = chain.verify()
    assert r.ok and r.checked == 20 and r.head[0] == 20


def test_la_cadena_persiste_y_se_puede_continuar_tras_reabrir(db):
    chain = AuditChain(db)
    llenar(chain, 3)
    chain.close()
    chain = AuditChain(db)
    nueva = chain.append({"n": 4})
    assert nueva.seq == 4 and chain.verify().ok and len(chain) == 4


def test_los_registros_se_leen_con_su_contenido(db):
    chain = AuditChain(db)
    chain.append({"tipo": "x", "valor": "ñandú"})
    (e,) = list(chain.entries())
    assert e.record == {"tipo": "x", "valor": "ñandú"}


def test_la_entrada_devuelta_no_se_puede_modificar():
    e = AuditChain().append({"a": 1})
    with pytest.raises(TypeError):
        e.record["a"] = 2


def test_un_registro_no_serializable_se_rechaza_y_no_deja_rastro():
    chain = AuditChain()
    with pytest.raises(TypeError):
        chain.append({"objeto": object()})
    with pytest.raises(TypeError):
        chain.append("no es un mapping")
    assert len(chain) == 0 and chain.verify().ok


# ---------------------------------------------------------------------------
# Detección de alteraciones
# ---------------------------------------------------------------------------
def test_modificar_el_contenido_de_una_entrada_se_detecta(db):
    llenar(AuditChain(db), 5)
    tocar(db, "UPDATE audit_chain SET record_json = ? WHERE seq = 3", json.dumps({"n": 3, "texto": "adulterado"}))
    r = AuditChain(db).verify()
    assert not r.ok and r.broken_at == 3 and "modificados" in r.reason and r.checked == 2


def test_modificar_el_hash_de_una_entrada_se_detecta(db):
    llenar(AuditChain(db), 5)
    tocar(db, "UPDATE audit_chain SET hash = ? WHERE seq = 2", "f" * 64)
    assert AuditChain(db).verify().broken_at == 2


def test_borrar_una_entrada_intermedia_se_detecta(db):
    llenar(AuditChain(db), 5)
    tocar(db, "DELETE FROM audit_chain WHERE seq = 3")
    r = AuditChain(db).verify()
    assert not r.ok and r.broken_at == 3 and "falta" in r.reason


def test_borrar_las_primeras_entradas_se_detecta(db):
    llenar(AuditChain(db), 5)
    tocar(db, "DELETE FROM audit_chain WHERE seq <= 2")
    assert AuditChain(db).verify().broken_at == 1


def test_reordenar_entradas_se_detecta(db):
    llenar(AuditChain(db), 5)
    tocar(db, "UPDATE audit_chain SET seq = 99 WHERE seq = 2")
    tocar(db, "UPDATE audit_chain SET seq = 2 WHERE seq = 3")
    tocar(db, "UPDATE audit_chain SET seq = 3 WHERE seq = 99")
    assert not AuditChain(db).verify().ok


def test_insertar_una_entrada_falsa_en_medio_se_detecta(db):
    llenar(AuditChain(db), 3)
    for seq in (3, 2):  # de mayor a menor, para no chocar con la clave primaria
        tocar(db, "UPDATE audit_chain SET seq = ? WHERE seq = ?", seq + 1, seq)
    tocar(db, "INSERT INTO audit_chain VALUES (2, 't', ?, ?, ?)", "0" * 64, "{}", "a" * 64)
    assert not AuditChain(db).verify().ok


def test_reescribir_la_ultima_entrada_con_su_hash_recalculado_no_se_detecta_sin_clave(db):
    """Límite documentado: sin secret ni cabeza guardada, el último eslabón se puede rehacer."""
    chain = AuditChain(db)
    llenar(chain, 3)
    seq, ts, prev = 3, *sqlite3.connect(db).execute("SELECT ts, prev_hash FROM audit_chain WHERE seq=3").fetchone()
    nuevo = json.dumps({"falso": True}, sort_keys=True, separators=(",", ":"))
    h = hashlib.sha256(f"{seq}|{ts}|{prev}|{nuevo}".encode()).hexdigest()
    tocar(db, "UPDATE audit_chain SET record_json = ?, hash = ? WHERE seq = 3", nuevo, h)
    assert AuditChain(db).verify().ok  # no se ve: por eso existe la cabeza guardada y el secret


def test_la_cabeza_guardada_detecta_el_truncamiento(db):
    chain = AuditChain(db)
    llenar(chain, 5)
    cabeza = chain.head()
    tocar(db, "DELETE FROM audit_chain WHERE seq > 3")
    r = AuditChain(db).verify(expected_head=cabeza)
    assert not r.ok and "truncada" in r.reason


def test_la_cabeza_guardada_detecta_la_reescritura_de_esa_entrada(db):
    chain = AuditChain(db)
    llenar(chain, 3)
    cabeza = chain.head()
    seq, ts, prev = 3, *sqlite3.connect(db).execute("SELECT ts, prev_hash FROM audit_chain WHERE seq=3").fetchone()
    nuevo = json.dumps({"falso": True}, sort_keys=True, separators=(",", ":"))
    tocar(db, "UPDATE audit_chain SET record_json = ?, hash = ? WHERE seq = 3", nuevo,
          hashlib.sha256(f"{seq}|{ts}|{prev}|{nuevo}".encode()).hexdigest())
    r = AuditChain(db).verify(expected_head=cabeza)
    assert not r.ok and "cambió" in r.reason


def test_la_cabeza_correcta_no_da_falsos_positivos(db):
    chain = AuditChain(db)
    llenar(chain, 5)
    assert chain.verify(expected_head=chain.head()).ok


# ---------------------------------------------------------------------------
# Con clave (HMAC): rehacer toda la cadena ya no basta
# ---------------------------------------------------------------------------
def test_con_clave_la_cadena_verifica_solo_con_esa_clave(db):
    chain = AuditChain(db, secret=b"clave-de-prueba")
    llenar(chain, 4)
    assert AuditChain(db, secret=b"clave-de-prueba").verify().ok
    assert not AuditChain(db, secret=b"otra-clave").verify().ok
    assert not AuditChain(db).verify().ok


def test_quien_no_tiene_la_clave_no_puede_rehacer_la_cadena(db):
    llenar(AuditChain(db, secret=b"clave"), 3)
    conn = sqlite3.connect(db)
    filas = conn.execute("SELECT seq, ts FROM audit_chain ORDER BY seq").fetchall()
    prev = GENESIS_HASH
    for seq, ts in filas:  # el atacante rehace todos los hashes con SHA-256 simple
        contenido = json.dumps({"falso": seq}, sort_keys=True, separators=(",", ":"))
        h = hashlib.sha256(f"{seq}|{ts}|{prev}|{contenido}".encode()).hexdigest()
        conn.execute("UPDATE audit_chain SET prev_hash=?, record_json=?, hash=? WHERE seq=?", (prev, contenido, h, seq))
        prev = h
    conn.commit()
    conn.close()
    assert not AuditChain(db, secret=b"clave").verify().ok


def test_el_secret_vacio_se_rechaza():
    with pytest.raises(ValueError):
        AuditChain(secret=b"")


# ---------------------------------------------------------------------------
# Concurrencia
# ---------------------------------------------------------------------------
def test_escrituras_concurrentes_producen_una_cadena_valida(db):
    chain = AuditChain(db)

    def escribir(hilo):
        for i in range(15):
            chain.append({"hilo": hilo, "i": i})

    hilos = [threading.Thread(target=escribir, args=(h,)) for h in range(6)]
    [h.start() for h in hilos]
    [h.join() for h in hilos]
    r = chain.verify()
    assert r.ok and r.checked == 90 and r.head[0] == 90


def test_dos_instancias_sobre_el_mismo_archivo_no_se_pisan(db):
    a, b = AuditChain(db), AuditChain(db)
    for i in range(10):
        (a if i % 2 else b).append({"i": i})
    assert a.verify().ok and len(b) == 10


# ---------------------------------------------------------------------------
# Registro de decisiones de authorize()
# ---------------------------------------------------------------------------
def test_registrar_decision_guarda_quien_que_y_la_decision():
    guard = AgentGuard.from_file(POLICY_PATH)
    chain = AuditChain()
    decision = guard.authorize(ANA, "eliminar_pedido", {"order_id": "123"})
    e = chain.registrar_decision(ANA, "eliminar_pedido", {"order_id": "123"}, decision, run_id="run-1")
    assert dict(e.record) == {
        "tipo": "decision", "run_id": "run-1", "usuario": "ana.atencion", "area": "atencion_cliente",
        "nivel": "empleado", "tool": "eliminar_pedido", "arguments": {"order_id": "123"},
        "decision": decision.to_dict(),
    }
    assert decision.action is Action.BLOCK


def test_registrar_decision_admite_campos_extra():
    guard = AgentGuard.from_file(POLICY_PATH)
    d = guard.authorize(ANA, "consultar_pedido", {"order_id": "1"})
    e = AuditChain().registrar_decision(ANA, "consultar_pedido", {"order_id": "1"}, d, extra={"autorizada": True})
    assert e.record["autorizada"] is True


# ---------------------------------------------------------------------------
# Línea de comandos
# ---------------------------------------------------------------------------
def test_cli_verify_de_una_cadena_integra(db, capsys):
    llenar(AuditChain(db), 3)
    assert cli(["verify", str(db)]) == 0
    assert "cadena íntegra: 3 entradas" in capsys.readouterr().out


def test_cli_verify_de_una_cadena_alterada(db, capsys):
    llenar(AuditChain(db), 3)
    tocar(db, "UPDATE audit_chain SET record_json = '{}' WHERE seq = 2")
    assert cli(["verify", str(db)]) == 1
    assert "ALTERADA" in capsys.readouterr().out


def test_cli_verify_con_cabeza(db, capsys):
    chain = AuditChain(db)
    llenar(chain, 4)
    seq, h = chain.head()
    assert cli(["verify", str(db), "--head", f"{seq}:{h}"]) == 0
    tocar(db, "DELETE FROM audit_chain WHERE seq = 4")
    assert cli(["verify", str(db), "--head", f"{seq}:{h}"]) == 1


def test_cli_errores_de_uso(db, tmp_path, capsys, monkeypatch):
    assert cli(["verify", str(tmp_path / "no-existe.db")]) == 2
    llenar(AuditChain(db), 1)
    assert cli(["verify", str(db), "--head", "mal"]) == 2
    monkeypatch.delenv("AUDIT_KEY_DE_PRUEBA", raising=False)
    assert cli(["verify", str(db), "--secret-env", "AUDIT_KEY_DE_PRUEBA"]) == 2


def test_cli_con_clave_desde_el_entorno(db, monkeypatch):
    llenar(AuditChain(db, secret=b"abc"), 2)
    monkeypatch.setenv("AUDIT_KEY_DE_PRUEBA", "abc")
    assert cli(["verify", str(db), "--secret-env", "AUDIT_KEY_DE_PRUEBA"]) == 0
    assert cli(["verify", str(db)]) == 1


def test_cli_show_imprime_las_ultimas_entradas(db, capsys):
    llenar(AuditChain(db), 5)
    assert cli(["show", str(db), "--last", "2"]) == 0
    salida = capsys.readouterr().out.strip().splitlines()
    assert len(salida) == 2 and salida[0].startswith("#4") and salida[1].startswith("#5")
