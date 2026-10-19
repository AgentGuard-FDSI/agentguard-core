"""Prueba el verificador de entrada por consola, o mide su precisión sobre un conjunto etiquetado.

    python -m agentguard.input_guard_cli --area finanzas --nivel empleado "Dame el correo de todos los clientes"
    python -m agentguard.input_guard_cli --evaluar evaluacion/verificador_entrada.json
    python -m agentguard.input_guard_cli --evaluar evaluacion/verificador_entrada.json --json

Código de salida: 0 si el prompt pasa (o si la evaluación se completó), 1 si se rechaza, 2 si el uso
es inválido o la política no carga.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from .input_guard import InputGuard, evaluate, load_labeled
from .notify import ConsoleNotifier
from .policy import PolicyError

POLITICA_POR_DEFECTO = Path(__file__).resolve().parents[1] / "config" / "policies.yaml"


@dataclass(frozen=True)
class _Sesion:
    usuario: str
    area: str
    nivel: str


def _pct(valor: float | None) -> str:
    return "n/a" if valor is None else f"{valor * 100:.0f} %"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m agentguard.input_guard_cli", description=__doc__.splitlines()[0])
    parser.add_argument("prompt", nargs="?", help="prompt a revisar")
    parser.add_argument("--area")
    parser.add_argument("--nivel")
    parser.add_argument("--usuario", default="consola")
    parser.add_argument("--politica", type=Path, default=POLITICA_POR_DEFECTO)
    parser.add_argument("--evaluar", type=Path, help="conjunto etiquetado en JSON")
    parser.add_argument("--json", action="store_true", help="imprimir el resultado en JSON")
    opts = parser.parse_args(argv)

    try:
        if opts.evaluar:
            guard = InputGuard.from_file(opts.politica)
        else:
            guard = InputGuard.from_file(opts.politica, notifier=ConsoleNotifier(sys.stdout))
    except PolicyError as exc:
        print(f"[ERROR] política inválida: {exc}", file=sys.stderr)
        return 2

    if opts.evaluar:
        if not opts.evaluar.exists():
            print(f"[ERROR] No existe {opts.evaluar}", file=sys.stderr)
            return 2
        r = evaluate(guard, load_labeled(opts.evaluar))
        if opts.json:
            print(json.dumps(r, ensure_ascii=False, indent=2))
            return 0
        print(f"Casos: {r['total']}  VP {r['verdaderos_positivos']}  FP {r['falsos_positivos']}  "
              f"FN {r['falsos_negativos']}  VN {r['verdaderos_negativos']}")
        print(f"Precisión: {_pct(r['precision'])}   Exhaustividad: {_pct(r['exhaustividad'])}   F1: {_pct(r['f1'])}")
        for e in r["errores"]:
            print(f"  {e['tipo']:15s} {e['id']}: {e['texto']}")
        return 0

    if not (opts.prompt and opts.area and opts.nivel):
        parser.error("indica el prompt, --area y --nivel (o usa --evaluar)")
    veredicto = guard.check(_Sesion(opts.usuario, opts.area, opts.nivel), opts.prompt)
    if opts.json:
        print(json.dumps(veredicto.to_dict(), ensure_ascii=False, indent=2))
    elif veredicto.rejected:
        print(f"REJECT  {veredicto.message}")
        print(f"        temas: {', '.join(veredicto.topics) or '-'}   reglas: {', '.join(veredicto.rules)}")
        if veredicto.owner_areas:
            print(f"        recurso de otra área: {dict(veredicto.owner_areas)}")
    else:
        print(f"PASS    {veredicto.reason}")
    return 1 if veredicto.rejected else 0


if __name__ == "__main__":
    raise SystemExit(main())
