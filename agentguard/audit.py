"""Registro de auditoría encadenado: cada entrada incluye el hash de la anterior.

Cada fila guarda (seq, ts, prev_hash, record_json, hash) con

    hash = SHA-256( seq | ts | prev_hash | record_json )

y la primera entrada parte de un hash de génesis. Si alguien modifica, borra o reordena una fila
intermedia, la cadena deja de cerrar y verify() indica la primera entrada donde se rompe.

Con `secret` el hash es un HMAC-SHA-256: sin la clave (que se guarda fuera de la base de datos),
quien escriba en el archivo no puede recalcular la cadena completa y que parezca válida.

Límites, dichos con claridad:

  * Borrar las ÚLTIMAS entradas no rompe la cadena. Para detectarlo, guarda la cabeza (head())
    en otro lugar y pásala a verify(expected_head=...).
  * Esto da integridad y detección de alteraciones. El no repudio fuerte (firmas Ed25519 por
    aprobador) es una ampliación.

authorize() no escribe nada: quien llama (el agente de la Config. B) registra cada decisión aquí.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Iterator, Mapping

from .decision import Decision

GENESIS_HASH = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_chain (
    seq         INTEGER PRIMARY KEY,
    ts          TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    record_json TEXT NOT NULL,
    hash        TEXT NOT NULL
)
"""


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    ts: str
    prev_hash: str
    hash: str
    record: Mapping[str, Any]


@dataclass(frozen=True)
class VerifyResult:
    """ok=True si la cadena cierra. Si no, broken_at es el seq de la primera entrada inconsistente."""

    ok: bool
    checked: int
    head: tuple[int, str] | None
    broken_at: int | None = None
    reason: str = ""

    def __bool__(self) -> bool:
        return self.ok


def _canonical(record: Mapping[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class AuditChain:
    """Cadena de auditoría en SQLite. `path` puede ser ":memory:" (pruebas)."""

    def __init__(
        self,
        path: str | Path = ":memory:",
        *,
        secret: bytes | None = None,
        clock: Callable[[], str] = _utc_now,
    ):
        if secret is not None and not secret:
            raise ValueError("secret no puede estar vacío; usa None para hash sin clave")
        self._secret = secret
        self._clock = clock
        self._lock = threading.Lock()
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        # isolation_level=None: las transacciones se controlan a mano (BEGIN IMMEDIATE al agregar).
        self._conn = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False, timeout=10)
        self._conn.execute(_SCHEMA)

    # ------------------------------------------------------------------
    def _hash(self, seq: int, ts: str, prev_hash: str, record_json: str) -> str:
        mensaje = f"{seq}|{ts}|{prev_hash}|{record_json}".encode("utf-8")
        if self._secret is None:
            return hashlib.sha256(mensaje).hexdigest()
        return hmac.new(self._secret, mensaje, hashlib.sha256).hexdigest()

    def append(self, record: Mapping[str, Any]) -> AuditEntry:
        """Agrega una entrada. `record` debe ser un mapping serializable a JSON."""
        if not isinstance(record, Mapping):
            raise TypeError("la entrada de auditoría debe ser un mapping")
        record_json = _canonical(record)  # falla aquí (TypeError) si no es serializable
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                fila = self._conn.execute("SELECT seq, hash FROM audit_chain ORDER BY seq DESC LIMIT 1").fetchone()
                seq, prev_hash = (fila[0] + 1, fila[1]) if fila else (1, GENESIS_HASH)
                ts = self._clock()
                digest = self._hash(seq, ts, prev_hash, record_json)
                self._conn.execute(
                    "INSERT INTO audit_chain (seq, ts, prev_hash, record_json, hash) VALUES (?, ?, ?, ?, ?)",
                    (seq, ts, prev_hash, record_json, digest),
                )
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
        return AuditEntry(seq, ts, prev_hash, digest, MappingProxyType(json.loads(record_json)))

    def entries(self) -> Iterator[AuditEntry]:
        with self._lock:
            filas = self._conn.execute(
                "SELECT seq, ts, prev_hash, record_json, hash FROM audit_chain ORDER BY seq"
            ).fetchall()
        for seq, ts, prev_hash, record_json, digest in filas:
            yield AuditEntry(seq, ts, prev_hash, digest, MappingProxyType(json.loads(record_json)))

    def head(self) -> tuple[int, str] | None:
        """(seq, hash) de la última entrada. Guárdala fuera de la base para detectar truncamientos."""
        with self._lock:
            fila = self._conn.execute("SELECT seq, hash FROM audit_chain ORDER BY seq DESC LIMIT 1").fetchone()
        return (fila[0], fila[1]) if fila else None

    def __len__(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM audit_chain").fetchone()[0]

    # ------------------------------------------------------------------
    def verify(self, expected_head: tuple[int, str] | None = None) -> VerifyResult:
        """Recorre la cadena y comprueba cada hash, cada enlace y la numeración.

        expected_head: (seq, hash) guardado antes; si la cadena es más corta o esa entrada cambió, falla.
        """
        with self._lock:
            filas = self._conn.execute(
                "SELECT seq, ts, prev_hash, record_json, hash FROM audit_chain ORDER BY seq"
            ).fetchall()

        anterior, esperado_seq = GENESIS_HASH, 1
        for seq, ts, prev_hash, record_json, digest in filas:
            if seq != esperado_seq:
                return self._falla(esperado_seq - 1, esperado_seq, f"falta la entrada {esperado_seq} (se encontró {seq})", filas)
            if prev_hash != anterior:
                return self._falla(seq - 1, seq, "el enlace con la entrada anterior no coincide", filas)
            try:
                json.loads(record_json)
            except ValueError:
                return self._falla(seq - 1, seq, "el contenido ya no es JSON válido", filas)
            if not hmac.compare_digest(self._hash(seq, ts, prev_hash, record_json), digest):
                return self._falla(seq - 1, seq, "el contenido o el hash fueron modificados", filas)
            anterior, esperado_seq = digest, seq + 1

        head = (filas[-1][0], filas[-1][4]) if filas else None
        if expected_head is not None:
            seq_esperado, hash_esperado = expected_head
            if head is None or head[0] < seq_esperado:
                return VerifyResult(False, len(filas), head, seq_esperado, "la cadena es más corta que la cabeza guardada (truncada)")
            coincide = next((f[4] for f in filas if f[0] == seq_esperado), None)
            if coincide != hash_esperado:
                return VerifyResult(False, len(filas), head, seq_esperado, "la entrada de la cabeza guardada cambió")
        return VerifyResult(True, len(filas), head)

    @staticmethod
    def _falla(verificadas: int, seq: int, motivo: str, filas: list) -> VerifyResult:
        head = (filas[-1][0], filas[-1][4]) if filas else None
        return VerifyResult(False, max(verificadas, 0), head, seq, motivo)

    # ------------------------------------------------------------------
    def registrar_decision(
        self,
        session: Any,
        tool: str,
        arguments: Mapping[str, Any],
        decision: Decision,
        *,
        run_id: str | None = None,
        extra: Mapping[str, Any] | None = None,
    ) -> AuditEntry:
        """Registra una decisión de authorize() con el contexto de quién y qué."""
        return self.append(decision_record(session, tool, arguments, decision, run_id=run_id, extra=extra))

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def decision_record(
    session: Any,
    tool: str,
    arguments: Mapping[str, Any],
    decision: Decision,
    *,
    run_id: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Entrada estándar para una decisión: identidad de la sesión, herramienta, argumentos y decisión."""
    record: dict[str, Any] = {
        "tipo": "decision",
        "run_id": run_id,
        "usuario": getattr(session, "usuario", None),
        "area": getattr(session, "area", None),
        "nivel": getattr(session, "nivel", None),
        "tool": tool,
        "arguments": dict(arguments) if isinstance(arguments, Mapping) else repr(arguments),
        "decision": decision.to_dict(),
    }
    if extra:
        record.update(extra)
    return record
