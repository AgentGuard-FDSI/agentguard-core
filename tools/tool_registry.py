"""Catalogo de herramientas disponibles para el agente.

Cada entrada combina la definicion en formato tool use de Anthropic
(name, description, input_schema) con la funcion Python real que se
ejecuta cuando el modelo la invoca.
"""

from tools.file_tools import read_file, write_file, list_directory

TOOL_DEFINITIONS = [
    {
        "name": "read_file",
        "description": "Lee y retorna el contenido de un archivo de texto dado su path.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Ruta del archivo a leer, relativa o absoluta.",
                }
            },
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "Escribe (o sobrescribe) contenido de texto en un archivo dado su path.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Ruta del archivo a escribir, relativa o absoluta.",
                },
                "content": {
                    "type": "string",
                    "description": "Contenido de texto a escribir en el archivo.",
                },
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "list_directory",
        "description": "Lista los archivos y carpetas contenidos en un directorio dado su path.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Ruta del directorio a listar, relativa o absoluta.",
                }
            },
            "required": ["path"],
        },
    },
]

TOOL_IMPLEMENTATIONS = {
    "read_file": read_file,
    "write_file": write_file,
    "list_directory": list_directory,
}


def execute_tool(name: str, tool_input: dict) -> str:
    """Ejecuta la herramienta `name` con los argumentos `tool_input`.

    Config A no valida `name` ni `tool_input` contra ninguna politica:
    cualquier herramienta registrada se ejecuta con cualquier argumento.
    """
    if name not in TOOL_IMPLEMENTATIONS:
        return f"ERROR: herramienta desconocida '{name}'"
    return TOOL_IMPLEMENTATIONS[name](**tool_input)
