"""Reglas del verificador de entrada: patrones y diccionarios por tema, sin LLM.

Cada regla pertenece a un tema y coincide si TODOS sus patrones `all_of` aparecen en el prompt
normalizado y NINGUNO de sus patrones `none_of` aparece. Un tema coincide si coincide al menos una
de sus reglas. Las decisiones son deterministas: el mismo prompt da siempre el mismo resultado.

Normalización (normalize): minúsculas, sin tildes ni diéresis (contraseña -> contrasena), sin
caracteres invisibles y con la puntuación convertida en espacios. Así "CONTRASEÑA", "contraseña"
y "contrasena" se tratan igual.

Limitación declarada: son reglas. Una paráfrasis que no use estas palabras ("pásame cómo contactar
a la gente que compró") las evade. Por eso el verificador se mide con precisión y exhaustividad
(agentguard.input_guard.evaluate) y no se presenta como garantía; detrás están las restricciones
por argumento y el HITL (defensa en profundidad).

Para ajustar el verificador se editan los diccionarios de este archivo y se corre la suite: las
pruebas tests/test_input_guard.py y el conjunto etiquetado evaluacion/verificador_entrada.json
muestran el efecto en falsos positivos y negativos.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Normalización
# ---------------------------------------------------------------------------
_INVISIBLES = re.compile("[­​-‏⁠-⁤﻿]")
_NO_PERMITIDOS = re.compile(r"[^a-z0-9_@.\-\s]")
_ESPACIOS = re.compile(r"\s+")


def normalize(text: str) -> str:
    """Forma comparable del prompt (ver el docstring del módulo)."""
    sin_invisibles = _INVISIBLES.sub("", text)
    descompuesto = unicodedata.normalize("NFKD", sin_invisibles)
    sin_marcas = "".join(c for c in descompuesto if not unicodedata.combining(c))
    limpio = _NO_PERMITIDOS.sub(" ", sin_marcas.casefold())
    return _ESPACIOS.sub(" ", limpio).strip()


# ---------------------------------------------------------------------------
# Diccionarios (sobre texto ya normalizado)
# ---------------------------------------------------------------------------
_PERSONAS_PL = r"(?:clientes|usuarios|compradores|consumidores|customers|users)"
_PERSONAS = r"(?:clientes?|usuarios?|compradores?|consumidores?|customers?|users?)"

# Un campo de datos personales. Se escriben en plural o con "de" para no confundir el canal
# ("envía un correo a ...") con el dato ("el correo de ...").
_CAMPO_PII = (
    r"\b(?:nombres|nombres?\s+complet[oa]s?|nombres?\s+(?:y\s+apellidos?\s+)?(?:de|del)\b|apellidos"
    r"|telefonos?|celular(?:es)?|numeros?\s+de\s+(?:telefono|celular|contacto|whatsapp)"
    r"|correos?\s+(?:electronicos?\s+)?(?:de|del|y)\b|correos\s+electronicos|emails?\s+(?:de|del)\b|e-?mails\b"
    r"|direccion(?:es)?|domicilios?|cedulas?|documentos?\s+de\s+identidad|numeros?\s+de\s+documento"
    r"|datos\s+personales|datos\s+de\s+contacto|informacion\s+(?:personal|de\s+contacto)|pii"
    r"|fechas?\s+de\s+nacimiento)"
)

# Un conjunto masivo de personas: todos los clientes, la base o la lista de clientes, etc.
_TODOS_LOS_CLIENTES = (
    rf"\btod[oa]s\s+(?:l[oa]s\s+|nuestr[oa]s\s+)?{_PERSONAS_PL}\b"
    rf"|\bcada\s+(?:uno\s+de\s+l[oa]s\s+)?{_PERSONAS}\b"
    r"|\ball\s+(?:the\s+|our\s+)?(?:customers|users)\b"
)
_BASE_DE_CLIENTES = (
    r"\b(?:lista(?:do)?|base(?:\s+de\s+datos)?|bd|tabla|registros?|export\w*|volcado|dump|archivo|excel|csv)"
    rf"\s+(?:complet[oa]\s+)?(?:de\s+|con\s+)?(?:l[oa]s\s+|tod[oa]s\s+l[oa]s\s+)?{_PERSONAS_PL}\b"
    rf"|\b{_PERSONAS_PL}\s+(?:registrad[oa]s|activ[oa]s|de\s+la\s+(?:base|plataforma|tienda))\b"
    r"|\bcustomer\s+(?:list|database|records|data)\b"
)
_MASIVO = rf"(?:{_TODOS_LOS_CLIENTES}|{_BASE_DE_CLIENTES})"

# Verbos de extracción ("dame", "exporta", "necesito"...). No incluye "envía" ni "manda", que son el
# canal de una campaña ("envía la promoción a todos los clientes"), sino "envíame" y "mándame".
_EXTRAER = (
    r"\b(?:dame|deme|denme|damelos|damelas|muestr\w*|ensen\w*|lista|listar|listame|listen|export\w*"
    r"|extrae\w*|extraer|descarg\w*|pasame|pasar|pasalos|mandame|enviame|enviarme|comparte\w*|compartir"
    r"|saca|sacar|sacame|obten\w*|consigue\w*|necesito|quiero|requiero|copia\w*|vuelca\w*|imprim\w*"
    r"|recopila\w*|dump|give\s+me|show\s+me|send\s+me|export|get\s+me)\b"
)
# "... a todos los clientes": los clientes son los destinatarios, no los datos que se piden.
_A_TODOS_LOS_CLIENTES = rf"\ba\s+(?:tod[oa]s\s+)?(?:l[oa]s\s+|nuestr[oa]s\s+)?{_PERSONAS_PL}\b"

_DETALLE_TARJETA = (
    r"\b(?:(?:numeros?|digitos)\s+(?:complet[oa]s?\s+)?(?:de\s+)?(?:la\s+|las\s+|sus\s+|su\s+)?tarjetas?"
    r"|tarjetas?\s+complet[oa]s?|cvv2?|cvc2?|codigos?\s+de\s+seguridad"
    r"|fechas?\s+de\s+(?:vencimiento|expiracion|caducidad)|pan\s+de\s+(?:la\s+)?tarjeta"
    r"|(?:credit\s+)?card\s+numbers?|datos\s+(?:de\s+)?(?:la\s+|las\s+|sus\s+)?tarjetas?)\b"
)
_DATO_BANCARIO = (
    r"\b(?:cuentas?\s+bancarias?|numeros?\s+de\s+(?:la\s+)?cuenta|datos\s+bancarios|informacion\s+bancaria"
    r"|pin\s+de\s+(?:la\s+)?tarjeta|claves?\s+de\s+(?:la\s+)?tarjeta|iban|swift)\b"
)
_DATOS_DE_PAGO = r"\b(?:datos|informacion)\s+(?:de\s+)?(?:pago|pagos|facturacion)\b"
_DE_PERSONAS = rf"\b(?:{_PERSONAS_PL}|cada\s+{_PERSONAS}|tod[oa]s)\b"

_CREDENCIAL = (
    r"\b(?:contrasenas?|password\w*|passwd|pwd|credencial\w*|api[\s_-]?keys?"
    r"|claves?\s+(?:de\s+)?(?:acceso|api|admin\w*|root|ssh|privadas?|maestras?|del\s+servidor"
    r"|de\s+la\s+base(?:\s+de\s+datos)?|de\s+la\s+bd)"
    r"|tokens?\s+(?:de\s+)?(?:acceso|api|sesion|jwt|autenticacion|bearer)|jwt\s+secret"
    r"|secret[\s_-]?keys?|secretos?\s+(?:de\s+)?(?:la\s+)?(?:aplicacion|app|api|servidor)"
    r"|llaves?\s+privadas?|private\s+keys?|ssh\s+keys?|claves?\s+ssh|usuario\s+y\s+clave"
    r"|hash(?:es)?\s+de\s+(?:las\s+)?contrasenas?)\b"
)
# Autoservicio de la propia cuenta ("cómo cambio mi contraseña"): no es pedir credenciales ajenas.
_MI_PROPIA_CLAVE = (
    r"\b(?:cambiar|cambio|cambio\s+de|restablec\w*|recuper\w*|olvide|resetear|reset)\s+"
    r"(?:de\s+|la\s+)?(?:mi|mis)\s+(?:propia\s+)?(?:contrasena|clave|password)\b"
)

_CONFIG_TI = r"\bconfig_ti\b|\bconfig\s+ti\b|\bconfiguracion\s+de\s+ti\b"
_CONFIG_INFRA = (
    r"\b(?:configuracion(?:es)?|config|parametros|ajustes)\s+(?:de\s+|del\s+)?(?:l[oa]s\s+|la\s+|el\s+)?"
    r"(?:servidor(?:es)?|infraestructura|red(?:es)?|base\s+de\s+datos|bd|firewall|balanceador\w*"
    r"|nube|cloud|kubernetes|cluster|vpn|dns)\b"
)
_DETALLE_RED = (
    r"\b(?:(?:direcciones?|ips?)\s+(?:ip\s+)?(?:internas?|privadas?|de\s+(?:l[oa]s\s+|el\s+)?servidor(?:es)?)"
    r"|direccion(?:es)?\s+ip|topologia\s+(?:de\s+)?(?:la\s+)?red|puertos?\s+(?:abiertos|expuestos|del\s+servidor)"
    r"|cadenas?\s+de\s+conexion|connection\s+strings?|variables?\s+de\s+entorno|archivo\s+env"
    r"|nombres?\s+de\s+host|hostnames?|servidor(?:es)?\s+(?:internos?|de\s+produccion)"
    r"|infraestructura\s+(?:interna|de\s+ti|tecnologica))\b"
    r"|(?:^|\s)\.env\b"
)


# ---------------------------------------------------------------------------
# Reglas
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class TopicRule:
    id: str
    topic: str
    description: str
    all_of: tuple[re.Pattern[str], ...]
    none_of: tuple[re.Pattern[str], ...] = ()

    def matches(self, normalized_text: str) -> bool:
        return all(p.search(normalized_text) for p in self.all_of) and not any(
            p.search(normalized_text) for p in self.none_of
        )


def _r(rule_id: str, topic: str, description: str, all_of: tuple[str, ...], none_of: tuple[str, ...] = ()) -> TopicRule:
    return TopicRule(
        rule_id, topic, description,
        tuple(re.compile(p) for p in all_of), tuple(re.compile(p) for p in none_of),
    )


RULES: tuple[TopicRule, ...] = (
    # --- Datos personales masivos ---------------------------------------------------------
    _r("pii.campo_masivo", "pii_masiva",
       "pide un dato personal (nombre, teléfono, correo, dirección...) de un conjunto masivo de clientes",
       (_CAMPO_PII, _MASIVO)),
    _r("pii.extraer_base", "pii_masiva",
       "pide extraer la base, la lista o a todos los clientes (no como destinatarios de un envío)",
       (_EXTRAER, _MASIVO), (_A_TODOS_LOS_CLIENTES,)),
    # --- Datos de pago --------------------------------------------------------------------
    _r("pago.tarjeta", "datos_de_pago",
       "pide número de tarjeta, CVV, fecha de vencimiento u otro detalle de la tarjeta", (_DETALLE_TARJETA,)),
    _r("pago.bancario", "datos_de_pago", "pide cuentas bancarias, PIN u otro dato bancario", (_DATO_BANCARIO,)),
    _r("pago.masivo", "datos_de_pago", "pide los datos de pago de los clientes", (_DATOS_DE_PAGO, _DE_PERSONAS)),
    # --- Credenciales ---------------------------------------------------------------------
    _r("cred.secreto", "credenciales",
       "pide contraseñas, claves de acceso, tokens, llaves privadas u otras credenciales",
       (_CREDENCIAL,), (_MI_PROPIA_CLAVE,)),
    # --- Configuración interna ------------------------------------------------------------
    _r("conf.config_ti", "config_interna", "pide la tabla config_ti", (_CONFIG_TI,)),
    _r("conf.infraestructura", "config_interna",
       "pide la configuración de servidores, red, base de datos u otra infraestructura", (_CONFIG_INFRA,)),
    _r("conf.red", "config_interna",
       "pide IP internas, puertos, cadenas de conexión, variables de entorno u otros detalles de la red",
       (_DETALLE_RED,)),
)

TOPICS: frozenset[str] = frozenset(r.topic for r in RULES)


def match_rules(normalized_text: str, topics: frozenset[str] | tuple[str, ...]) -> tuple[TopicRule, ...]:
    """Reglas de los temas indicados que coinciden con el texto (ya normalizado), en orden."""
    return tuple(r for r in RULES if r.topic in topics and r.matches(normalized_text))
