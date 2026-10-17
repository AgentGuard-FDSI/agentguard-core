"""Modelos inmutables que representan una política ya validada.

Todos los objetos son de solo lectura (dataclasses congeladas, tuplas,
frozensets y MappingProxyType): una vez cargada, la política no puede
modificarse en tiempo de ejecución, ni por error ni desde el agente.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Mapping


class Risk(str, Enum):
    """Nivel de riesgo declarado para una herramienta."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Action(str, Enum):
    """Acción base que la política asigna a una herramienta."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    HITL = "HITL"


def _empty_mapping() -> Mapping[str, tuple[str, ...]]:
    return MappingProxyType({})


@dataclass(frozen=True)
class ToolArgs:
    """Restricciones por argumento de una herramienta.

    Un valor vacío (None, tupla vacía o mapping vacío) significa que esa
    restricción no aplica a la herramienta.
    """

    max_items_per_request: int | None = None
    recipient_in: tuple[str, ...] = ()
    table_by_area: Mapping[str, tuple[str, ...]] = field(default_factory=_empty_mapping)


@dataclass(frozen=True)
class AreaPolicy:
    """Área de la empresa y los niveles jerárquicos que existen en ella."""

    name: str
    description: str
    levels: tuple[str, ...]


@dataclass(frozen=True)
class ToolPolicy:
    """Política declarada para una herramienta."""

    name: str
    areas: frozenset[str]
    risk: Risk
    action: Action
    args: ToolArgs

    def allows_area(self, area: str) -> bool:
        """Indica si el área figura entre las autorizadas para la herramienta."""
        return area in self.areas


@dataclass(frozen=True)
class SessionConfig:
    """Configuración de dónde proviene la identidad (área y nivel)."""

    identity_source: str


@dataclass(frozen=True)
class Organization:
    """Datos propios de la organización que usa AgentGuard (ninguno es obligatorio).

    corporate_domain:    dominio de correo de la empresa; lo usa la restricción recipient_in
                         (categoría dominio_corporativo) de enviar_correo.
    final_approver_area: área que respalda las aprobaciones humanas cuando el solicitante es jefe
                         o cuando no hay otro aprobador en su área (por ejemplo gerencia).
    """

    corporate_domain: str | None = None
    final_approver_area: str | None = None


@dataclass(frozen=True)
class PolicySet:
    """Política completa, validada e inmutable."""

    version: int
    session: SessionConfig
    areas: Mapping[str, AreaPolicy]
    tools: Mapping[str, ToolPolicy]
    source: str
    organization: Organization = field(default_factory=Organization)

    def get_tool(self, name: str) -> ToolPolicy | None:
        """Devuelve la política de la herramienta, o None si no está declarada."""
        return self.tools.get(name)

    def get_area(self, name: str) -> AreaPolicy | None:
        """Devuelve el área, o None si no está declarada."""
        return self.areas.get(name)

    def top_level(self, area: str) -> str | None:
        """Nivel más alto del área (el último de `levels`), o None si el área no existe."""
        area_policy = self.areas.get(area)
        return area_policy.levels[-1] if area_policy else None

    def tools_for_area(self, area: str) -> tuple[str, ...]:
        """Nombres (ordenados) de las herramientas que el área puede invocar."""
        return tuple(sorted(t.name for t in self.tools.values() if t.allows_area(area)))
