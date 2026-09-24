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

## Estado

Repositorio inicializado. El trabajo se reparte por avances: el motor básico en el Avance 2 y el
resto del núcleo en el Avance 3. El prototipo anterior (Config. A con herramientas de archivos) queda
en la etiqueta `legacy-config-a-archivos`.
