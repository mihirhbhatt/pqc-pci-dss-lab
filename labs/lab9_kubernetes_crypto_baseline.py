#!/usr/bin/env python3
"""Lab 9: Offline policy validation for a Kubernetes cryptographic service.

This lab models the security properties from the enterprise orchestration
material without requiring a Kubernetes cluster. It validates a normalized
workload specification before deployment and emits auditable evidence.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "evidence"))
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


SECURE_CRYPTO_SERVICE: dict[str, Any] = {
    "name": "pqc-key-service",
    "namespace": "payments-security",
    "image": "registry.example/pqc-key-service@sha256:training-digest",
    "run_as_non_root": True,
    "read_only_root_filesystem": True,
    "allow_privilege_escalation": False,
    "dropped_capabilities": ["ALL"],
    "secret_refs": ["pqc-key-service-tls", "pqc-key-service-kek"],
    "network_policy": {
        "ingress_from": ["payment-api"],
        "egress_to": ["vault", "dns"],
    },
    "crypto_policy": {
        "tls_min_version": "TLSv1.3",
        "key_exchange": "X25519MLKEM768",
        "fallback_allowed": False,
    },
}


def validate_crypto_service(spec: dict[str, Any]) -> list[str]:
    """Return policy violations; an empty list means the spec is compliant."""
    violations: list[str] = []
    required_true = {
        "run_as_non_root": "workload must run as non-root",
        "read_only_root_filesystem": "root filesystem must be read-only",
    }
    for field, message in required_true.items():
        if spec.get(field) is not True:
            violations.append(message)

    if spec.get("allow_privilege_escalation") is not False:
        violations.append("privilege escalation must be disabled")
    if "ALL" not in spec.get("dropped_capabilities", []):
        violations.append("all Linux capabilities must be dropped")
    if "@sha256:" not in spec.get("image", ""):
        violations.append("container image must be pinned by digest")
    if not spec.get("secret_refs"):
        violations.append("cryptographic material must use secret references")

    network_policy = spec.get("network_policy", {})
    if not network_policy.get("ingress_from"):
        violations.append("network policy must restrict ingress sources")
    if not network_policy.get("egress_to"):
        violations.append("network policy must restrict egress destinations")

    crypto_policy = spec.get("crypto_policy", {})
    if crypto_policy.get("tls_min_version") != "TLSv1.3":
        violations.append("TLS 1.3 must be the minimum protocol version")
    if crypto_policy.get("key_exchange") != "X25519MLKEM768":
        violations.append("hybrid X25519MLKEM768 key exchange is required")
    if crypto_policy.get("fallback_allowed") is not False:
        violations.append("unapproved classical fallback must be disabled")
    return violations


def build_evidence(
    spec: dict[str, Any] = SECURE_CRYPTO_SERVICE,
) -> dict[str, Any]:
    violations = validate_crypto_service(spec)
    return {
        "lab": "Lab 9: Kubernetes Cryptographic Service Baseline",
        "generated": datetime.now(timezone.utc).isoformat(),
        "status": "PASS" if not violations else "FAIL",
        "service": spec["name"],
        "policy_checks": {
            "checks_run": 11,
            "violations": violations,
        },
        "deployment_scope": "offline manifest validation; no cluster access",
        "crypto_policy": spec["crypto_policy"],
    }


def main() -> None:
    evidence = build_evidence()
    path = EVIDENCE_DIR / "lab9_kubernetes_crypto_baseline.json"
    path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
