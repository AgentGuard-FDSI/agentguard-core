"""Lector de policies.yaml.

Principios del lector:

* Carga segura: se usa un SafeLoader de PyYAML (no ejecuta etiquetas como
  !!python/object) y se rechazan las claves duplicadas, que PyYAML por
  defecto resolvería en silencio quedándose con la última.
* Esquema estricto (fail-closed): cualquier clave desconocida, valor fuera
  de los permitidos o referencia a un área inexistente produce PolicyError.
  Una política mal escrita nunca se carga "a medias".
* Resultado inmutable: devuelve un PolicySet de solo lectura.

Este módulo solo carga y valida. Las decisiones (ALLOW, BLOCK, HITL sobre
una sesión concreta) las toma AgentGuard.authorize(), en el Avance 2.
"""

from __future__ import annotations

import re
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable

import yaml

from .errors import PolicyError
from .models import (
    Action,
    AreaPolicy,
    PolicySet,
    Risk,
    SessionConfig,
    ToolArgs,
    ToolPolicy,
)

SUPPORTED_VERSION = 1
ALLOWED_IDENTITY_SOURCES = frozenset({"session"})
KNOWN_RECIPIENT_CATEGORIES = frozenset({"clientes_registrados", "dominio_corporativo"})

_TOP_LEVEL_KEYS = frozenset({"version", "session", "areas", "tools"})
_SESSION_KEYS = frozenset({"identity_source"})
_AREA_KEYS = frozenset({"description", "levels"})
_TOOL_KEYS = frozenset({"areas", "risk", "action", "args"})
_ARG_KEYS = frozenset({"max_items_per_request", "recipient_in", "table_by_area"})

_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]*$")


# ---------------------------------------------------------------------------
# Carga YAML segura y sin claves duplicadas
# ---------------------------------------------------------------------------
class _StrictSafeLoader(yaml.SafeLoader):
    """SafeLoader que rechaza claves duplicadas dentro de un mismo mapping."""


def _construct_unique_mapping(loader: _StrictSafeLoader, node: yaml.MappingNode, deep: bool = False):
    loader.flatten_mapping(node)
    seen: set[Any] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise PolicyError(
                f"Clave duplicada '{key}' (línea {key_node.start_mark.line + 1})"
            )
        seen.add(key)
    return loader.construct_mapping(node, deep=deep)


_StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------
def load_policies(path: str | Path) -> PolicySet:
    """Lee, valida y devuelve la política contenida en el archivo `path`."""
    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise PolicyError(f"No se encontró el archivo de políticas: {file_path}") from exc
    except OSError as exc:
        raise PolicyError(f"No se pudo leer el archivo de políticas {file_path}: {exc}") from exc
    return parse_policies(text, source=str(file_path))


def parse_policies(text: str, source: str = "<texto>") -> PolicySet:
    """Valida una política recibida como texto YAML (útil en pruebas)."""
    try:
        raw = yaml.load(text, Loader=_StrictSafeLoader)  # noqa: S506 - loader seguro propio
    except PolicyError as exc:
        raise PolicyError(f"{source}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise PolicyError(f"{source}: YAML inválido: {exc}") from exc

    root = _require_mapping(raw, "raíz del documento")
    _check_keys(root, allowed=_TOP_LEVEL_KEYS, required=_TOP_LEVEL_KEYS, where="raíz del documento")

    version = _parse_version(root["version"])
    session = _parse_session(root["session"])
    areas = _parse_areas(root["areas"])
    tools = _parse_tools(root["tools"], areas)

    return PolicySet(
        version=version,
        session=session,
        areas=MappingProxyType(areas),
        tools=MappingProxyType(tools),
        source=source,
    )


# ---------------------------------------------------------------------------
# Secciones
# ---------------------------------------------------------------------------
def _parse_version(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise PolicyError(f"'version' debe ser un entero, se recibió: {value!r}")
    if value != SUPPORTED_VERSION:
        raise PolicyError(
            f"Versión de política no soportada: {value} (soportada: {SUPPORTED_VERSION})"
        )
    return value


def _parse_session(value: Any) -> SessionConfig:
    where = "session"
    body = _require_mapping(value, where)
    _check_keys(body, allowed=_SESSION_KEYS, required=_SESSION_KEYS, where=where)
    source = body["identity_source"]
    if source not in ALLOWED_IDENTITY_SOURCES:
        raise PolicyError(
            f"{where}.identity_source debe ser uno de {sorted(ALLOWED_IDENTITY_SOURCES)}; "
            f"se recibió: {source!r}. La identidad nunca puede venir del prompt."
        )
    return SessionConfig(identity_source=source)


def _parse_areas(value: Any) -> dict[str, AreaPolicy]:
    body = _require_mapping(value, "areas")
    if not body:
        raise PolicyError("'areas' no puede estar vacío")

    areas: dict[str, AreaPolicy] = {}
    for name, area_body in body.items():
        _require_identifier(name, "nombre de área")
        where = f"areas.{name}"
        area_map = _require_mapping(area_body, where)
        _check_keys(area_map, allowed=_AREA_KEYS, required={"levels"}, where=where)

        description = area_map.get("description", "")
        if not isinstance(description, str):
            raise PolicyError(f"{where}.description debe ser texto")

        levels = _require_identifier_list(area_map["levels"], f"{where}.levels")
        areas[name] = AreaPolicy(name=name, description=description, levels=levels)
    return areas


def _parse_tools(value: Any, areas: dict[str, AreaPolicy]) -> dict[str, ToolPolicy]:
    body = _require_mapping(value, "tools")
    if not body:
        raise PolicyError("'tools' no puede estar vacío")

    tools: dict[str, ToolPolicy] = {}
    for name, tool_body in body.items():
        _require_identifier(name, "nombre de herramienta")
        where = f"tools.{name}"
        tool_map = _require_mapping(tool_body, where)
        _check_keys(tool_map, allowed=_TOOL_KEYS, required={"areas", "risk", "action"}, where=where)

        tool_areas = _require_identifier_list(tool_map["areas"], f"{where}.areas")
        _require_known_areas(tool_areas, areas, f"{where}.areas")

        tools[name] = ToolPolicy(
            name=name,
            areas=frozenset(tool_areas),
            risk=_parse_enum(Risk, tool_map["risk"], f"{where}.risk"),
            action=_parse_enum(Action, tool_map["action"], f"{where}.action"),
            args=_parse_args(tool_map.get("args"), frozenset(tool_areas), f"{where}.args"),
        )
    return tools


def _parse_args(value: Any, tool_areas: frozenset[str], where: str) -> ToolArgs:
    if value is None:
        return ToolArgs()
    body = _require_mapping(value, where)
    _check_keys(body, allowed=_ARG_KEYS, required=set(), where=where)

    max_items = None
    if "max_items_per_request" in body:
        max_items = body["max_items_per_request"]
        if not isinstance(max_items, int) or isinstance(max_items, bool) or max_items < 1:
            raise PolicyError(
                f"{where}.max_items_per_request debe ser un entero mayor o igual a 1; "
                f"se recibió: {max_items!r}"
            )

    recipient_in: tuple[str, ...] = ()
    if "recipient_in" in body:
        recipient_in = _require_identifier_list(body["recipient_in"], f"{where}.recipient_in")
        unknown = [r for r in recipient_in if r not in KNOWN_RECIPIENT_CATEGORIES]
        if unknown:
            raise PolicyError(
                f"{where}.recipient_in contiene categorías desconocidas {unknown}; "
                f"permitidas: {sorted(KNOWN_RECIPIENT_CATEGORIES)}"
            )

    table_by_area: dict[str, tuple[str, ...]] = {}
    if "table_by_area" in body:
        tba_where = f"{where}.table_by_area"
        tba = _require_mapping(body["table_by_area"], tba_where)
        if not tba:
            raise PolicyError(f"{tba_where} no puede estar vacío si se declara")
        for area, tables in tba.items():
            _require_identifier(area, f"área en {tba_where}")
            if area not in tool_areas:
                raise PolicyError(
                    f"{tba_where}.{area}: el área no está autorizada para esta herramienta"
                )
            table_by_area[area] = _require_identifier_list(tables, f"{tba_where}.{area}")

    return ToolArgs(
        max_items_per_request=max_items,
        recipient_in=recipient_in,
        table_by_area=MappingProxyType(table_by_area),
    )


# ---------------------------------------------------------------------------
# Utilidades de validación
# ---------------------------------------------------------------------------
def _require_mapping(value: Any, where: str) -> dict:
    if not isinstance(value, dict):
        raise PolicyError(f"{where} debe ser un mapa clave: valor; se recibió {type(value).__name__}")
    return value


def _check_keys(body: dict, *, allowed: Iterable[str], required: Iterable[str], where: str) -> None:
    allowed, required = set(allowed), set(required)
    unknown = sorted(str(k) for k in body if k not in allowed)
    if unknown:
        raise PolicyError(f"{where}: claves desconocidas {unknown}; permitidas: {sorted(allowed)}")
    missing = sorted(required - set(body))
    if missing:
        raise PolicyError(f"{where}: faltan claves obligatorias {missing}")


def _require_identifier(value: Any, what: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.match(value):
        raise PolicyError(
            f"{what} inválido: {value!r} (usar minúsculas, dígitos y '_', empezando por letra)"
        )
    return value


def _require_identifier_list(value: Any, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise PolicyError(f"{where} debe ser una lista no vacía")
    items = tuple(_require_identifier(v, f"elemento de {where}") for v in value)
    if len(set(items)) != len(items):
        raise PolicyError(f"{where} contiene elementos repetidos")
    return items


def _require_known_areas(names: Iterable[str], areas: dict[str, AreaPolicy], where: str) -> None:
    unknown = [n for n in names if n not in areas]
    if unknown:
        raise PolicyError(f"{where} hace referencia a áreas no declaradas: {unknown}")


def _parse_enum(enum_cls, value: Any, where: str):
    valid = [m.value for m in enum_cls]
    if not isinstance(value, str):
        raise PolicyError(f"{where} debe ser uno de {valid}; se recibió {value!r}")
    try:
        return enum_cls(value)
    except ValueError:
        raise PolicyError(f"{where} debe ser uno de {valid}; se recibió {value!r}") from None
