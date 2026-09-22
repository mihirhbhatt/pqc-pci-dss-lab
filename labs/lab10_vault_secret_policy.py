# flake8: noqa: E501
"""Lab 10: Validate a Vault-style secret-management policy offline."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "evidence"))
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

SECRET_POLICY: dict[str, Any] = {
    "mount": "kv-payments",
    "path": "prod/payment-gateway",
    "allowed_readers": ["payment-api"],
    "allowed_writers": ["rotation-controller"],
    "lease_ttl_hours": 24,
    "max_ttl_hours": 168,
    "plaintext_logging": False,
    "audit_enabled": True,
}


def validate_secret_policy(policy: dict[str, Any]) -> list[str]:
    violations = []
    if not policy.get("mount") or not policy.get("path"):
        violations.append("secret mount and path are required")
    if not policy.get("allowed_readers"):
        violations.append("at least one explicit reader is required")
    if not policy.get("allowed_writers"):
        violations.append("at least one explicit writer is required")
    if policy.get("lease_ttl_hours", 0) <= 0:
        violations.append("lease TTL must be positive")
    if policy.get("lease_ttl_hours", 0) > policy.get("max_ttl_hours", 0):
        violations.append("lease TTL cannot exceed max TTL")
    if policy.get("plaintext_logging") is not False:
        violations.append("plaintext secret logging must be disabled")
    if policy.get("audit_enabled") is not True:
        violations.append("secret access auditing must be enabled")
    return violations


def main() -> None:
    violations = validate_secret_policy(SECRET_POLICY)
    evidence = {"lab": "Lab 10: Vault Secret-Management Policy", "generated": datetime.now(timezone.utc).isoformat(), "status": "PASS" if not violations else "FAIL", "policy": SECRET_POLICY, "violations": violations}
    (EVIDENCE_DIR / "lab10_vault_secret_policy.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
