# Guía de políticas

`config/policies.yaml` define quién puede usar qué. AgentGuard no conoce el negocio: para otra empresa se
cambian este archivo, las áreas y las herramientas, no el código. La política es de solo lectura para el
agente. Para validarla:

```bash
python -m agentguard.policy config/policies.yaml
```

Una política inválida no se carga (falla cerrado).

## Secciones

| Sección | Qué define |
|---|---|
| `version` | Versión del formato. |
| `session.identity_source` | De dónde sale la identidad. Siempre `session`: área y nivel vienen de la sesión autenticada, nunca del prompt. |
| `organizacion` | `dominio_corporativo` (para `recipient_in: dominio_corporativo`) y `aprobador_ultima_instancia` (área que respalda las aprobaciones). |
| `verificador_entrada` | Temas que se rechazan antes del agente, el área a notificar, el mensaje de rechazo y qué área es dueña de cada tema. |
| `regla_entre_areas` | Cuántos intentos en cuántos minutos generan una alerta, y a quién. |
| `areas` | Cada área con su descripción y sus niveles. |
| `tools` | Cada herramienta con las áreas que pueden usarla, el riesgo, la acción base y las restricciones por argumento. |

## Herramientas

```yaml
tools:
  enviar_correo:
    areas: [atencion_cliente, marketing_comunicaciones]
    risk: HIGH
    action: HITL
    args:
      recipient_in: [clientes_registrados, dominio_corporativo]
```

- `areas`: áreas que pueden invocarla. Un área fuera de la lista recibe `BLOCK`.
- `risk`: `LOW`, `MEDIUM`, `HIGH` o `CRITICAL`.
- `action`: acción base cuando el área sí está autorizada: `ALLOW`, `BLOCK` o `HITL`.
- `args`: restricciones por argumento. Un argumento fuera de lo permitido da `BLOCK` aunque el área tenga la
  herramienta.

### Restricciones por argumento

| Restricción | Efecto |
|---|---|
| `max_items_per_request` | Tamaño máximo del lote (por ejemplo, cuántos pedidos en una llamada). |
| `recipient_in` | El destinatario debe ser un cliente registrado o del dominio corporativo. |
| `table_by_area` | Tablas que cada área puede leer. |

## Herramientas de la política de ANDIMARKET

| Herramienta | Áreas | Riesgo | Acción base |
|---|---|---|---|
| `consultar_pedido` | atención al cliente, logística | LOW | ALLOW |
| `actualizar_pedido` | atención al cliente, logística | MEDIUM | HITL |
| `eliminar_pedido` | logística | HIGH | HITL |
| `enviar_correo` | atención al cliente, marketing | HIGH | HITL |
| `leer_base_datos` | finanzas, tecnología | MEDIUM | ALLOW |
| `admin_action` | tecnología | CRITICAL | BLOCK |

Las áreas son atención al cliente, logística y operaciones, marketing y comunicaciones, tecnología,
finanzas y gerencia. Gerencia no tiene herramientas operativas: es el aprobador de última instancia.

## Para adaptarlo a otra empresa

1. Cambia `organizacion.dominio_corporativo` y el aprobador de última instancia.
2. Define tus áreas y niveles en `areas`.
3. Declara tus herramientas en `tools`, con sus áreas, riesgo, acción base y restricciones.
4. Valida con `python -m agentguard.policy` y agrega pruebas para tus casos.
5. Entrega a `AgentGuard` un directorio de personas (`InMemoryDirectory` en la demo) para comprobar quién aprueba.

El orden en que se evalúa cada llamada está en [`arquitectura.md`](arquitectura.md).
