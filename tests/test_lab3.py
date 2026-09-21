"""Unit tests for opt-in hybrid TLS evidence helpers."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from labs.lab3_tls_migration import (
    HYBRID_GROUP,
    extract_client_hello_size,
    verify_hybrid_connection,
)


def test_client_hello_size_parser_handles_hex_length():
    output = ">>> TLS 1.3, Handshake [length 02f0]"
    assert extract_client_hello_size(output) == 752


def test_hybrid_verification_reports_negotiated_group(monkeypatch):
    class Result:
        returncode = 0
        stdout = f"CONNECTION ESTABLISHED\nServer Temp Key: {HYBRID_GROUP}, 2432 bits"

    monkeypatch.setattr("labs.lab3_tls_migration.run_cmd", lambda *args, **kwargs: Result())
    result = verify_hybrid_connection("example.test")
    assert result["status"] == "verified"
    assert result["negotiated_group"] == HYBRID_GROUP
