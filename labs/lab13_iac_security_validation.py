# flake8: noqa: E501
"""Lab 13: Validate infrastructure-as-code security controls offline."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "evidence"))
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

IAC_PLAN: dict[str, Any] = {
    "state_encrypted": True,
    "state_locking": True,
    "resources": [
        {"name": "pqc-key-service", "image": "registry/pqc@sha256:digest", "public": False, "encrypted_storage": True},
        {"name": "vault", "image": "hashicorp/vault@sha256:digest", "public": False, "encrypted_storage": True},
    ],
}


def validate_iac_plan(plan: dict[str, Any]) -> list[str]:
    violations = []
    if plan.get("state_encrypted") is not True:
        violations.append("IaC state must be encrypted")
    if plan.get("state_locking") is not True:
        violations.append("IaC state locking must be enabled")
    for resource in plan.get("resources", []):
        name = resource.get("name", "unnamed")
        if "@sha256:" not in resource.get("image", ""):
            violations.append(f"{name}: image must be digest pinned")
        if resource.get("public") is not False:
            violations.append(f"{name}: public exposure is prohibited")
        if resource.get("encrypted_storage") is not True:
            violations.append(f"{name}: encrypted storage is required")
    if not plan.get("resources"):
        violations.append("IaC plan must contain resources")
    return violations


def main() -> None:
    violations = validate_iac_plan(IAC_PLAN)
    evidence = {"lab": "Lab 13: Infrastructure-as-Code Security Validation", "generated": datetime.now(timezone.utc).isoformat(), "status": "PASS" if not violations else "FAIL", "resources": len(IAC_PLAN["resources"]), "violations": violations}
    (EVIDENCE_DIR / "lab13_iac_security_validation.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
