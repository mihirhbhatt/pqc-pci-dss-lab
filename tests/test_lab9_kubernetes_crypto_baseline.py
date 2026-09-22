"""Tests for the offline Kubernetes cryptographic service policy."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from labs.lab9_kubernetes_crypto_baseline import (  # noqa: E402
    SECURE_CRYPTO_SERVICE,
    build_evidence,
    validate_crypto_service,
)


def test_reference_service_passes_policy():
    assert validate_crypto_service(SECURE_CRYPTO_SERVICE) == []
    assert build_evidence()["status"] == "PASS"


def test_policy_rejects_unpinned_privileged_service():
    insecure = dict(SECURE_CRYPTO_SERVICE)
    insecure.update(
        {
            "image": "registry.example/pqc-key-service:latest",
            "run_as_non_root": False,
            "allow_privilege_escalation": True,
        }
    )

    violations = validate_crypto_service(insecure)

    assert "container image must be pinned by digest" in violations
    assert "workload must run as non-root" in violations
    assert "privilege escalation must be disabled" in violations


def test_policy_requires_hybrid_tls_and_restricted_network():
    insecure = dict(SECURE_CRYPTO_SERVICE)
    insecure["network_policy"] = {"ingress_from": [], "egress_to": []}
    insecure["crypto_policy"] = {
        "tls_min_version": "TLSv1.2",
        "key_exchange": "X25519",
        "fallback_allowed": True,
    }

    violations = validate_crypto_service(insecure)

    assert "network policy must restrict ingress sources" in violations
    assert "network policy must restrict egress destinations" in violations
    assert "TLS 1.3 must be the minimum protocol version" in violations
    assert "hybrid X25519MLKEM768 key exchange is required" in violations
    assert "unapproved classical fallback must be disabled" in violations
