# flake8: noqa: E501
"""Lab 12: Validate a PQC service-mesh mTLS policy offline."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "evidence"))
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

MESH_POLICY: dict[str, Any] = {
    "trust_domain": "payments.example",
    "mode": "STRICT",
    "peer_groups": {"payment-api": ["vault", "pqc-key-service"]},
    "tls_min_version": "TLSv1.3",
    "key_exchange": "X25519MLKEM768",
    "classical_fallback": False,
}


def validate_mesh_policy(policy: dict[str, Any]) -> list[str]:
    violations = []
    if not policy.get("trust_domain"):
        violations.append("trust domain is required")
    if policy.get("mode") != "STRICT":
        violations.append("mesh mTLS mode must be STRICT")
    if policy.get("tls_min_version") != "TLSv1.3":
        violations.append("mesh TLS minimum must be TLS 1.3")
    if policy.get("key_exchange") != "X25519MLKEM768":
        violations.append("mesh must require the approved hybrid key exchange")
    if policy.get("classical_fallback") is not False:
        violations.append("classical fallback must be explicitly disabled")
    if not policy.get("peer_groups"):
        violations.append("at least one authorized peer group is required")
    return violations


def main() -> None:
    violations = validate_mesh_policy(MESH_POLICY)
    evidence = {"lab": "Lab 12: PQC Service-Mesh mTLS", "generated": datetime.now(timezone.utc).isoformat(), "status": "PASS" if not violations else "FAIL", "policy": MESH_POLICY, "violations": violations}
    (EVIDENCE_DIR / "lab12_service_mesh_mtls.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
