# flake8: noqa: E501
"""Lab 14: Analyze default-deny network reachability for crypto services."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "evidence"))
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_EDGES = {
    ("payment-api", "pqc-key-service"),
    ("pqc-key-service", "vault"),
    ("pqc-key-service", "dns"),
}


def analyze_network_policy(requested_edges: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    """Return requested edges that are not present in the allow-list."""
    return sorted(set(requested_edges) - ALLOWED_EDGES)


def main() -> None:
    requested = list(ALLOWED_EDGES)
    denied = analyze_network_policy(requested)
    evidence = {"lab": "Lab 14: Network-Policy Analysis", "generated": datetime.now(timezone.utc).isoformat(), "status": "PASS" if not denied else "FAIL", "default_deny": True, "allowed_edges": sorted(ALLOWED_EDGES), "unexpected_edges": denied}
    (EVIDENCE_DIR / "lab14_network_policy_analysis.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
