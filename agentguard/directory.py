"""Directorio de personas: quién es cada usuario (área y nivel).

AgentGuard no administra usuarios. La organización le da un directorio (su sistema de identidad, o
uno de demostración en memoria) para poder comprobar quién aprueba una solicitud HITL.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Protocol


def normalizar_usuario(usuario: Any) -> str:
    """Forma comparable de un identificador de usuario (sin mayúsculas ni espacios en los extremos)."""
    return usuario.strip().casefold() if isinstance(usuario, str) else ""


@dataclass(frozen=True)
class Person:
    usuario: str
    area: str
    nivel: str


class Directory(Protocol):
    def lookup(self, usuario: str) -> Person | None:
        """La persona con ese usuario, o None si no existe."""
        ...


class InMemoryDirectory:
    """Directorio en memoria, para pruebas y demostraciones. Acepta Person o cualquier objeto con
    usuario, área y nivel (por ejemplo la Session del agente)."""

    def __init__(self, personas: Iterable[Any] = ()):
        self._personas: dict[str, Person] = {}
        for persona in personas:
            self.add(persona)

    def add(self, persona: Any) -> None:
        nueva = Person(persona.usuario, persona.area, persona.nivel)
        clave = normalizar_usuario(nueva.usuario)
        if not clave:
            raise ValueError("el usuario no puede estar vacío")
        if clave in self._personas and self._personas[clave] != nueva:
            raise ValueError(f"el usuario {nueva.usuario!r} ya existe con otra área o nivel")
        self._personas[clave] = nueva

    def lookup(self, usuario: str) -> Person | None:
        return self._personas.get(normalizar_usuario(usuario))

    def __len__(self) -> int:
        return len(self._personas)
