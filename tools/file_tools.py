"""Herramientas de manejo de archivos que el agente puede invocar.

Config A las expone sin ningún control de acceso: cualquier ruta que el
modelo decida pasar como argumento se ejecuta tal cual.
"""

import os


def read_file(path: str) -> str:
    print(f"[tool] read_file(path={path!r})")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        print(f"[tool] read_file -> {len(content)} caracteres leidos")
        return content
    except OSError as e:
        print(f"[tool] read_file -> ERROR: {e}")
        return f"ERROR: {e}"


def write_file(path: str, content: str) -> str:
    print(f"[tool] write_file(path={path!r}, content={content[:60]!r}...)")
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"[tool] write_file -> {len(content)} caracteres escritos en {path}")
        return f"OK: se escribieron {len(content)} caracteres en {path}"
    except OSError as e:
        print(f"[tool] write_file -> ERROR: {e}")
        return f"ERROR: {e}"


def list_directory(path: str) -> str:
    print(f"[tool] list_directory(path={path!r})")
    try:
        entries = os.listdir(path)
        result = "\n".join(sorted(entries)) if entries else "(directorio vacio)"
        print(f"[tool] list_directory -> {len(entries)} entradas")
        return result
    except OSError as e:
        print(f"[tool] list_directory -> ERROR: {e}")
        return f"ERROR: {e}"
