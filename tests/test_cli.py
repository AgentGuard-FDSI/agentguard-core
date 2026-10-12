"""Pruebas del comando `python -m agentguard` (authorize() por consola)."""

import json
from pathlib import Path

from agentguard.__main__ import main

POLICY = str(Path(__file__).resolve().parents[1] / "config" / "policies.yaml")


def run(capsys, area, nivel, tool, args=None, extra=()):
    codigo = main(["--policy", POLICY, "--area", area, "--nivel", nivel, "--tool", tool,
                   "--args", json.dumps(args or {}), *extra])
    return codigo, capsys.readouterr()


def test_allow_sale_con_codigo_0(capsys):
    codigo, out = run(capsys, "atencion_cliente", "empleado", "consultar_pedido", {"order_id": "123"})
    assert codigo == 0 and "ALLOW" in out.out


def test_block_sale_con_codigo_1(capsys):
    codigo, out = run(capsys, "atencion_cliente", "empleado", "eliminar_pedido", {"order_id": "123"})
    assert codigo == 1 and "BLOCK" in out.out and "fuera_de_rol" in out.out


def test_hitl_aprobado_sale_con_codigo_0(capsys, monkeypatch):
    respuestas = iter(["lina.logistica", "s"])
    monkeypatch.setattr("builtins.input", lambda _p="": next(respuestas))
    codigo, out = run(capsys, "logistica_operaciones", "empleado", "eliminar_pedido", {"order_id": "123"})
    assert codigo == 0 and "HITL" in out.out and "APROBADA" in out.out


def test_hitl_rechazado_sale_con_codigo_1(capsys, monkeypatch):
    respuestas = iter(["lina.logistica", "n"])
    monkeypatch.setattr("builtins.input", lambda _p="": next(respuestas))
    codigo, out = run(capsys, "logistica_operaciones", "empleado", "eliminar_pedido", {"order_id": "123"})
    assert codigo == 1 and "RECHAZADA" in out.out


def test_json_invalido_es_error_de_uso(capsys):
    codigo = main(["--policy", POLICY, "--area", "finanzas", "--nivel", "empleado",
                   "--tool", "leer_base_datos", "--args", "{no es json"])
    assert codigo == 2 and "JSON" in capsys.readouterr().err


def test_politica_inexistente_es_error(capsys):
    codigo = main(["--policy", "no_existe.yaml", "--area", "finanzas", "--nivel", "empleado", "--tool", "x"])
    assert codigo == 2 and "Política inválida" in capsys.readouterr().err
