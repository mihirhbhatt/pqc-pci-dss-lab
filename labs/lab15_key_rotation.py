# flake8: noqa: E501
"""Lab 15: Model safe automated cryptographic key rotation."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "evidence"))
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def rotate_key_state(state: dict[str, Any], new_version: int) -> dict[str, Any]:
    """Create a rotation state with an overlap window for existing readers."""
    current = state.get("active_version", 0)
    if new_version != current + 1:
        raise ValueError("key versions must increase by exactly one")
    if state.get("status") != "ACTIVE":
        raise ValueError("only an active key can be rotated")
    return {"active_version": new_version, "previous_version": current, "status": "OVERLAP", "rollback_version": current}


def validate_rotation_state(state: dict[str, Any]) -> list[str]:
    violations = []
    if state.get("status") not in {"ACTIVE", "OVERLAP"}:
        violations.append("key state must be ACTIVE or OVERLAP")
    if state.get("active_version", 0) <= 0:
        violations.append("active key version must be positive")
    if state.get("status") == "OVERLAP" and state.get("previous_version", 0) <= 0:
        violations.append("overlap state requires a previous version")
    if state.get("status") == "OVERLAP" and state.get("rollback_version") != state.get("previous_version"):
        violations.append("rollback version must match previous version")
    return violations


def main() -> None:
    state = rotate_key_state({"active_version": 1, "status": "ACTIVE"}, 2)
    evidence = {"lab": "Lab 15: Automated Key Rotation", "generated": datetime.now(timezone.utc).isoformat(), "status": "PASS" if not validate_rotation_state(state) else "FAIL", "rotation": state}
    (EVIDENCE_DIR / "lab15_key_rotation.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
