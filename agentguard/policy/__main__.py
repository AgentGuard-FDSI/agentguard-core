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

    entrada = policy.input_guard
    print("\nVerificador de entrada:", "activo" if entrada.enabled else "apagado")
    if entrada.enabled:
        print(f"  temas={list(entrada.topics)}  notifica a {entrada.notify_area}")
        for tema, area in entrada.topic_owner.items():
            print(f"  {tema} es de {area} (no se rechaza para esa área; para las demás cuenta como acceso entre áreas)")
    regla = policy.cross_area
    print("Regla entre áreas:", "activa" if regla.enabled else "apagada")
    if regla.enabled:
        print(f"  alerta prioritaria a {regla.alert_area} tras {regla.attempts} intentos en {regla.window_minutes} minutos")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
