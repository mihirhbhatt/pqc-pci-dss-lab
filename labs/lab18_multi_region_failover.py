# flake8: noqa: E501
"""Lab 18: Select a healthy region for cryptographic failover."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "evidence"))
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def choose_failover_region(regions: list[dict[str, Any]], max_replication_lag_seconds: int = 30) -> str:
    candidates = [region for region in regions if region.get("healthy") and region.get("quorum") and region.get("replication_lag_seconds", 9999) <= max_replication_lag_seconds]
    if not candidates:
        raise RuntimeError("no region satisfies failover safety requirements")
    return min(candidates, key=lambda region: (region.get("replication_lag_seconds", 9999), region["name"]))["name"]


def main() -> None:
    regions = [{"name": "us-east", "healthy": False, "quorum": True, "replication_lag_seconds": 0}, {"name": "eu-west", "healthy": True, "quorum": True, "replication_lag_seconds": 8}]
    selected = choose_failover_region(regions)
    evidence = {"lab": "Lab 18: Multi-Region Cryptographic Failover", "generated": datetime.now(timezone.utc).isoformat(), "status": "PASS", "selected_region": selected, "max_replication_lag_seconds": 30}
    (EVIDENCE_DIR / "lab18_multi_region_failover.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
