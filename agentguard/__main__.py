"""Prueba de authorize() por consola, sin agente.

    python -m agentguard --area atencion_cliente --nivel empleado --tool consultar_pedido --args '{"order_id": "123"}'
    python -m agentguard --area logistica_operaciones --nivel empleado --tool eliminar_pedido --args '{"order_id": "123"}'

Si la decisión es HITL, pide la aprobación por consola. No ejecuta ninguna herramienta.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass

from . import AgentGuard, ApprovalRequest, ConsoleApprover, PolicyError


@dataclass(frozen=True)
class _Session:
    usuario: str
    area: str
    nivel: str


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m agentguard", description="Evalúa una llamada con authorize().")
    parser.add_argument("--policy", default="config/policies.yaml")
    parser.add_argument("--usuario", default="usuario_demo")
    parser.add_argument("--area", required=True)
    parser.add_argument("--nivel", required=True)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--args", default="{}", help="argumentos en JSON")
    opts = parser.parse_args(argv)

    try:
        guard = AgentGuard.from_file(opts.policy)
        arguments = json.loads(opts.args)
    except PolicyError as exc:
        print(f"[ERROR] Política inválida: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"[ERROR] --args no es JSON válido: {exc}", file=sys.stderr)
        return 2

    session = _Session(opts.usuario, opts.area, opts.nivel)
    decision = guard.authorize(session, opts.tool, arguments)
    print(f"[AgentGuard] {decision}")

    if decision.needs_approval:
        result = ConsoleApprover().request(ApprovalRequest.from_decision(session, opts.tool, arguments, decision))
        estado = "APROBADA" if result.approved else "RECHAZADA"
        print(f"[AgentGuard] solicitud {estado} por {result.approver}")
        return 0 if result.approved else 1
    return 0 if decision.allowed else 1


if __name__ == "__main__":
    raise SystemExit(main())
