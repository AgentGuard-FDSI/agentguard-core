"""Verifica o muestra un registro de auditoría encadenado.

    python -m agentguard.audit_cli verify data/audit.db
    python -m agentguard.audit_cli verify data/audit.db --head 42:ab12...      # detecta truncamientos
    python -m agentguard.audit_cli verify data/audit.db --secret-env AUDIT_KEY  # cadena con HMAC
    python -m agentguard.audit_cli show data/audit.db --last 5

Código de salida: 0 si la cadena es íntegra, 1 si se detectó una alteración, 2 si el uso es inválido.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .audit import AuditChain


def _parse_head(texto: str) -> tuple[int, str]:
    seq, _, digest = texto.partition(":")
    if not seq.isdigit() or not digest:
        raise ValueError("--head debe tener la forma SEQ:HASH")
    return int(seq), digest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m agentguard.audit_cli", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="comando", required=True)
    for nombre in ("verify", "show"):
        p = sub.add_parser(nombre)
        p.add_argument("db", type=Path)
        p.add_argument("--secret-env", help="variable de entorno con la clave HMAC de la cadena")
    sub.choices["verify"].add_argument("--head", help="cabeza esperada, SEQ:HASH")
    sub.choices["show"].add_argument("--last", type=int, default=10)
    opts = parser.parse_args(argv)

    if not opts.db.exists():
        print(f"[ERROR] No existe {opts.db}", file=sys.stderr)
        return 2
    secret = None
    if opts.secret_env:
        valor = os.environ.get(opts.secret_env)
        if not valor:
            print(f"[ERROR] La variable {opts.secret_env} no está definida", file=sys.stderr)
            return 2
        secret = valor.encode("utf-8")

    chain = AuditChain(opts.db, secret=secret)
    try:
        if opts.comando == "show":
            for entrada in list(chain.entries())[-opts.last:]:
                print(f"#{entrada.seq} {entrada.ts} {entrada.hash[:12]}… {json.dumps(dict(entrada.record), ensure_ascii=False)}")
            return 0
        try:
            head = _parse_head(opts.head) if opts.head else None
        except ValueError as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            return 2
        resultado = chain.verify(expected_head=head)
        if resultado:
            cabeza = f"{resultado.head[0]}:{resultado.head[1]}" if resultado.head else "(vacía)"
            print(f"[OK] cadena íntegra: {resultado.checked} entradas. Cabeza: {cabeza}")
            return 0
        print(f"[ALTERADA] entrada {resultado.broken_at}: {resultado.reason} (verificadas antes: {resultado.checked})")
        return 1
    finally:
        chain.close()


if __name__ == "__main__":
    raise SystemExit(main())
