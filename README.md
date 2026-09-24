# agentguard-core

Interceptor de políticas de mínimo privilegio para agentes LLM. Decide `ALLOW`, `BLOCK` o `HITL`
para cada llamada a una herramienta según el área y el nivel de la sesión, la herramienta y sus
argumentos. Se usa como librería, dentro del mismo proceso del agente.

Este repositorio es el **producto**. El agente y el experimento (Config. A frente a Config. B)
viven en [`agentguard-andimarket`](https://github.com/AgentGuard-FDSI/agentguard-andimarket), que instala este paquete.

## Estructura

```
agentguard/
├── engine.py        # AgentGuard.authorize(session, tool, arguments) -> Verdict
├── policy.py        # lectura de policies.yaml
├── input_guard.py   # verificador de entrada por reglas
├── cross_area.py    # regla de acceso entre áreas
├── approvals.py     # HITL con aprobador distinto del solicitante
└── audit.py         # audit log encadenado
policies.example.yaml
tests/
```

## Estado

| Pieza | Fase |
|---|---|
| Contrato (`Decision`, `Session`, `Verdict`) y lector de políticas | Listo |
| `authorize()` con ALLOW, BLOCK y HITL por consola | Avance 2 |
| Restricciones por argumento, verificador de entrada, regla entre áreas, aprobador distinto, log encadenado | Avance 3 |
| Firmas Ed25519 | Ampliación |

Las pruebas marcadas como `xfail` en `tests/test_contract.py` son el primer objetivo del Avance 2:
cuando `authorize()` funcione, pasan a verde.

## Uso

```bash
pip install -e ".[dev]"
python -m pytest
```
