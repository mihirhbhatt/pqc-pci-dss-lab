# flake8: noqa: E501
"""Lab 11: Validate a Vault PKI certificate profile offline."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "evidence"))
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

CERTIFICATE_PROFILE: dict[str, Any] = {
    "role": "payment-api",
    "allowed_domains": ["payments.internal"],
    "allow_subdomains": False,
    "max_ttl_hours": 24,
    "key_usage": ["Digital Signature", "Key Encipherment"],
    "pqc_group": "X25519MLKEM768",
    "renew_before_hours": 6,
}


def validate_certificate_profile(profile: dict[str, Any]) -> list[str]:
    violations = []
    if not profile.get("role") or not profile.get("allowed_domains"):
        violations.append("certificate role and allowed domains are required")
    if profile.get("max_ttl_hours", 0) <= 0 or profile.get("max_ttl_hours", 0) > 168:
        violations.append("certificate TTL must be between 1 and 168 hours")
    if "Digital Signature" not in profile.get("key_usage", []):
        violations.append("certificate must allow digital signatures")
    if profile.get("pqc_group") != "X25519MLKEM768":
        violations.append("certificate profile must require the approved hybrid group")
    if profile.get("renew_before_hours", 0) >= profile.get("max_ttl_hours", 0):
        violations.append("renewal window must precede certificate expiry")
    return violations


def main() -> None:
    violations = validate_certificate_profile(CERTIFICATE_PROFILE)
    evidence = {"lab": "Lab 11: Vault PKI Certificate Issuance", "generated": datetime.now(timezone.utc).isoformat(), "status": "PASS" if not violations else "FAIL", "profile": CERTIFICATE_PROFILE, "violations": violations}
    (EVIDENCE_DIR / "lab11_vault_pki_issuance.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
