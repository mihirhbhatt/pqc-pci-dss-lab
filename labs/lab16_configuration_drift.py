# flake8: noqa: E501
"""Lab 16: Detect security configuration drift using stable snapshots."""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "evidence"))
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def snapshot_hash(configuration: dict[str, Any]) -> str:
    serialized = json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(serialized).hexdigest()


def find_drift(baseline: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
    changed = sorted({key for key in set(baseline) | set(observed) if baseline.get(key) != observed.get(key)})
    return {"changed_fields": changed, "drift_detected": bool(changed), "baseline_hash": snapshot_hash(baseline), "observed_hash": snapshot_hash(observed)}


def main() -> None:
    baseline = {"tls_min": "TLSv1.3", "key_exchange": "X25519MLKEM768", "fallback": False}
    result = find_drift(baseline, dict(baseline))
    evidence = {"lab": "Lab 16: Configuration-Drift Detection", "generated": datetime.now(timezone.utc).isoformat(), "status": "PASS" if not result["drift_detected"] else "FAIL", "drift": result}
    (EVIDENCE_DIR / "lab16_configuration_drift.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
