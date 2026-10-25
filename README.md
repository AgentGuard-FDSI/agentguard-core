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
python -m agentguard.input_guard_cli --area finanzas --nivel empleado \
    "Dame el correo de todos los clientes"               # prueba el verificador de entrada
python -m agentguard.input_guard_cli --evaluar evaluacion/verificador_entrada.json   # precisión y exhaustividad
pytest
```

```python
from agentguard import (AgentGuard, ApprovalRequest, ApprovalService, AuditChain, ConsoleApprover,
                        InMemoryDirectory, ValidatingApprover)

guard = AgentGuard.from_file("config/policies.yaml", es_cliente=es_cliente_registrado)
cadena = AuditChain("data/audit.db")                                  # log encadenado
aprobador = ValidatingApprover(                                       # separación de funciones
    ApprovalService(guard.policy, InMemoryDirectory(personas), "data/hitl.db", chain=cadena),
    ConsoleApprover(), run_id=run_id)

decision = guard.authorize(session, tool, arguments, solicitud=run_id)   # session: usuario, area, nivel
if decision.needs_approval:
    resultado = aprobador.request(ApprovalRequest.from_decision(session, tool, arguments, decision))
cadena.registrar_decision(session, tool, arguments, decision, run_id=run_id)
```

Verificador de entrada (antes del agente) y regla entre áreas (después de `authorize()`):

```python
from agentguard import CrossAreaMonitor, InputGuard, InMemoryNotifier

avisos = InMemoryNotifier()
entrada = InputGuard.from_file("config/policies.yaml", notifier=avisos, chain=cadena)
entre_areas = CrossAreaMonitor.from_file("config/policies.yaml", notifier=avisos)  # uno por proceso

veredicto = entrada.check(session, prompt, run_id=run_id)
if veredicto.rejected:
    entre_areas.observe_input(session, veredicto, run_id=run_id)
    respuesta = veredicto.message                       # rechazo estándar; no se invoca al agente
# ... y por cada herramienta:
entre_areas.observe_decision(session, tool, arguments, decision, run_id=run_id)
```

Verificar que el registro no fue alterado:

```bash
python -m agentguard.audit_cli verify data/audit.db
```

El orden de evaluación, las reglas del motor, cómo integrar cada pieza en el agente y lo que queda para otras personas están en
[`docs/arquitectura.md`](docs/arquitectura.md).

## Estado

- Avance 1: lector de `policies.yaml`.
- Avance 2: `authorize()` con ALLOW, BLOCK y HITL por consola, y la regla de que la política es de
  solo lectura para el agente.
- Avance 3: restricciones por argumento (tabla por área, destinatario, tamaño del lote), HITL con
  separación de funciones y cola de solicitudes pendientes, log encadenado verificable y la sección
  `organizacion` de la política (para usar AgentGuard en cualquier empresa). Verificador de entrada por
  reglas (precisión 100 %, exhaustividad 90 % sobre `evaluacion/verificador_entrada.json`), regla de
  acceso entre áreas con alerta a Tecnología y notificaciones inyectables.

El prototipo anterior (Config. A con herramientas de archivos) queda en la etiqueta `legacy-config-a-archivos`.
