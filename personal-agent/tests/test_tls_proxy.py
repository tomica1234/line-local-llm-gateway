from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


def load_proxy_module():
    script = Path(__file__).parents[1] / "scripts" / "windows-tls-proxy.py"
    spec = importlib.util.spec_from_file_location("windows_tls_proxy", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_parse_proxy_v1_tcp4_source() -> None:
    proxy = load_proxy_module()
    assert proxy.parse_proxy_v1_line(
        b"PROXY TCP4 100.64.0.10 100.64.0.11 54321 9443\r\n"
    ) == ("100.64.0.10", 54321)


@pytest.mark.parametrize(
    "line",
    [
        b"GET / HTTP/1.1\r\n",
        b"PROXY UNKNOWN\r\n",
        b"PROXY TCP4 100.64.0.10 100.64.0.11 0 9443\r\n",
        b"PROXY TCP4 100.64.0.10 100.64.0.11 54321 9443\n",
        b"PROXY TCP6 100.64.0.10 100.64.0.11 54321 9443\r\n",
    ],
)
def test_parse_proxy_v1_rejects_malformed_input(line: bytes) -> None:
    proxy = load_proxy_module()
    with pytest.raises(ValueError, match="PROXY"):
        proxy.parse_proxy_v1_line(line)
