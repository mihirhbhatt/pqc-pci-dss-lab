# flake8: noqa: E501
"""Lab 17: Evaluate default-deny zero-trust authorization decisions."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "evidence"))
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

AUTHORIZED_REQUESTS = {
    ("payment-api", "read", "pqc-key-service"),
    ("rotation-controller", "rotate", "pqc-key-service"),
}


def authorize(identity: str, action: str, resource: str, policies: Iterable[tuple[str, str, str]] = AUTHORIZED_REQUESTS) -> bool:
    return (identity, action, resource) in set(policies)


def main() -> None:
    allowed = authorize("payment-api", "read", "pqc-key-service")
    denied = authorize("payment-api", "admin", "vault")
    evidence = {"lab": "Lab 17: Zero-Trust Policy Decisions", "generated": datetime.now(timezone.utc).isoformat(), "status": "PASS" if allowed and not denied else "FAIL", "default_deny": True, "allowed_request": allowed, "unauthorized_request_denied": not denied}
    (EVIDENCE_DIR / "lab17_zero_trust_policy.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
