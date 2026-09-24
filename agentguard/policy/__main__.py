"""Valida un policies.yaml y muestra un resumen.

Uso:
    python -m agentguard.policy config/policies.yaml
"""

import sys

from . import PolicyError, load_policies


def main(argv: list[str]) -> int:
    path = argv[1] if len(argv) > 1 else "config/policies.yaml"
    try:
        policy = load_policies(path)
    except PolicyError as exc:
        print(f"[ERROR] Política inválida: {exc}", file=sys.stderr)
        return 1

    print(f"[OK] {policy.source} (versión {policy.version}, identidad desde: {policy.session.identity_source})\n")
    print("Herramientas:")
    for tool in policy.tools.values():
        print(f"  {tool.name:<20} {tool.risk.value:<9} {tool.action.value:<6} áreas={sorted(tool.areas)}")
    print("\nHerramientas por área:")
    for area in policy.areas.values():
        tools = ", ".join(policy.tools_for_area(area.name)) or "(ninguna)"
        print(f"  {area.name:<25} niveles={list(area.levels)}  ->  {tools}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
