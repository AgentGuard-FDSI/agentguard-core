"""Errores del módulo de políticas."""


class PolicyError(Exception):
    """La política no se pudo cargar o no cumple el esquema esperado.

    Se lanza siempre que el archivo es inválido: AgentGuard nunca arranca
    con una política parcial (fail-closed).
    """
