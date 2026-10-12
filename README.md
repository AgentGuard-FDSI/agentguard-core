# agentguard-core

El producto del proyecto AgentGuard: una librería de mínimo privilegio para agentes LLM. Decide
`ALLOW`, `BLOCK` o `HITL` para cada llamada a una herramienta según el área y el nivel de la
sesión, la herramienta y sus argumentos. Se usa dentro del mismo proceso del agente.

No conoce a ANDIMARKET ni tiene agente propio: el agente y el experimento (Config. A frente a
Config. B) viven en [`agentguard-andimarket`](https://github.com/AgentGuard-FDSI/agentguard-andimarket),
que instala este paquete.

## Qué va en este repositorio

- Motor de políticas: `authorize(session, tool, arguments)` que devuelve la decisión y su motivo.
- Lectura de `policies.yaml`.
- Verificador de entrada por reglas.
- Regla de acceso entre áreas.
- Aprobaciones HITL con aprobador distinto del solicitante.
- Audit log encadenado.
- Pruebas unitarias.

## Uso

```bash
pip install -e .            # desde agentguard-andimarket: pip install -e ../agentguard-core
python -m agentguard.policy config/policies.yaml        # valida la política
python -m agentguard --area atencion_cliente --nivel empleado \
    --tool consultar_pedido --args '{"order_id": "123"}'  # prueba authorize() por consola
pytest
```

```python
from agentguard import AgentGuard, ApprovalRequest, ConsoleApprover

guard = AgentGuard.from_file("config/policies.yaml")
decision = guard.authorize(session, tool, arguments)   # session: usuario, area, nivel
if decision.needs_approval:
    resultado = ConsoleApprover().request(ApprovalRequest.from_decision(session, tool, arguments, decision))
registro = {**decision.to_dict(), "tool": tool, "usuario": session.usuario}  # para el audit log
```

El orden de evaluación, las reglas del motor y lo que queda para el Avance 3 están en
[`docs/arquitectura.md`](docs/arquitectura.md).

## Estado

- Avance 1: lector de `policies.yaml`.
- Avance 2: `authorize()` con ALLOW, BLOCK y HITL por consola, y la regla de que la política es de
  solo lectura para el agente.
- Avance 3: restricciones por argumento, verificador de entrada, regla entre áreas, HITL con
  separación de funciones y log encadenado. El prototipo anterior (Config. A con herramientas de archivos) queda
en la etiqueta `legacy-config-a-archivos`.
