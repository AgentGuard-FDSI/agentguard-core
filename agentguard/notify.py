"""Notificaciones de seguridad: a quién se avisa cuando el verificador de entrada rechaza un prompt
o cuando la regla entre áreas detecta un acceso a un recurso de otra área.

AgentGuard no envía correos ni mensajes: produce `Notification` y se las entrega a un `Notifier`
que inyecta quien lo usa. Así el core no depende de ningún canal y las pruebas no tocan la red.

    InMemoryNotifier   guarda las notificaciones en una lista (pruebas, experimento, dashboard).
    ConsoleNotifier    las imprime (demostración por consola).
    AuditNotifier      las agrega al log encadenado (agentguard.audit), con tipo "notificacion".
    MultiNotifier      reparte la misma notificación a varios notificadores.

Prioridad: NORMAL para el aviso de cada evento; PRIORITARIA para la alerta de posible cuenta
comprometida (regla entre áreas repetida). Un notificador que falla nunca cambia la decisión: el
rechazo o el BLOCK ya se tomaron; el fallo se cuenta en `fallos` de quien notificó.
"""

from __future__ import annotations

import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Protocol, TextIO


class Priority(str, Enum):
    NORMAL = "NORMAL"
    PRIORITARIA = "PRIORITARIA"


class NotificationKind(str, Enum):
    """Qué produjo la notificación. Código estable para el dashboard y las métricas."""

    ENTRADA_RECHAZADA = "entrada_rechazada"          # el verificador de entrada rechazó un prompt
    ACCESO_ENTRE_AREAS = "acceso_entre_areas"        # se pidió un recurso propio de otra área
    ALERTA_CUENTA_COMPROMETIDA = "alerta_cuenta_comprometida"  # acceso entre áreas repetido


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


@dataclass(frozen=True)
class Notification:
    kind: NotificationKind
    priority: Priority
    area_destino: str                  # área que recibe el aviso (Tecnología o el área propietaria)
    usuario: str | None                # quién originó el evento (de la sesión)
    area: str | None
    nivel: str | None
    motivo: str
    ts: str = field(default_factory=_utc_now)
    detalle: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    def to_dict(self) -> dict[str, Any]:
        """Forma serializable (JSON) para el log de auditoría o la API del frontend."""
        return {
            "tipo": "notificacion",
            "kind": self.kind.value,
            "prioridad": self.priority.value,
            "area_destino": self.area_destino,
            "usuario": self.usuario,
            "area": self.area,
            "nivel": self.nivel,
            "motivo": self.motivo,
            "ts": self.ts,
            "detalle": dict(self.detalle),
        }


class Notifier(Protocol):
    def notify(self, notification: Notification) -> None:
        """Entrega la notificación. Puede lanzar excepciones: quien llama las contiene."""
        ...


class InMemoryNotifier:
    """Guarda las notificaciones en memoria, en orden. Seguro entre hilos."""

    def __init__(self) -> None:
        self._items: list[Notification] = []
        self._lock = threading.Lock()

    def notify(self, notification: Notification) -> None:
        with self._lock:
            self._items.append(notification)

    @property
    def items(self) -> tuple[Notification, ...]:
        with self._lock:
            return tuple(self._items)

    def para(self, area: str) -> tuple[Notification, ...]:
        """Notificaciones dirigidas a un área."""
        return tuple(n for n in self.items if n.area_destino == area)

    def de_tipo(self, kind: NotificationKind) -> tuple[Notification, ...]:
        return tuple(n for n in self.items if n.kind is kind)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


class ConsoleNotifier:
    """Imprime cada notificación en una línea (por defecto en stderr, para no mezclarla con el chat)."""

    def __init__(self, stream: TextIO | None = None):
        self._stream = stream

    def notify(self, notification: Notification) -> None:
        stream = self._stream or sys.stderr
        marca = "[ALERTA]" if notification.priority is Priority.PRIORITARIA else "[aviso]"
        print(
            f"{marca} {notification.kind.value} -> {notification.area_destino}: {notification.motivo} "
            f"(usuario {notification.usuario}, área {notification.area})",
            file=stream,
        )


class AuditNotifier:
    """Registra la notificación en el log encadenado, para que quede con no repudio."""

    def __init__(self, chain: Any):  # AuditChain; se tipa como Any para no importar sqlite aquí
        self._chain = chain

    def notify(self, notification: Notification) -> None:
        self._chain.append(notification.to_dict())


class MultiNotifier:
    """Entrega a todos los notificadores; si uno falla, sigue con los demás y relanza al final."""

    def __init__(self, notifiers: Iterable[Notifier]):
        self._notifiers = tuple(notifiers)

    def notify(self, notification: Notification) -> None:
        error: Exception | None = None
        for notifier in self._notifiers:
            try:
                notifier.notify(notification)
            except Exception as exc:  # noqa: BLE001 - se entrega a los demás antes de fallar
                error = error or exc
        if error is not None:
            raise error


def entregar(notifier: Notifier | None, notification: Notification, on_error: Callable[[Exception], None]) -> bool:
    """Entrega sin dejar que un fallo del canal cambie la decisión. True si se entregó."""
    if notifier is None:
        return False
    try:
        notifier.notify(notification)
        return True
    except Exception as exc:  # noqa: BLE001
        on_error(exc)
        return False
