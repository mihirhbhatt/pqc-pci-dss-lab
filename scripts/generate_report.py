#!/usr/bin/env python3
"""
Aggregates all lab evidence into a consolidated migration report.
"""

import json
import os
from datetime import datetime
from pathlib import Path

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "evidence"))
REPORTS_DIR = Path(os.environ.get("REPORTS_DIR", "reports"))
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def load_evidence(filename):
    """Load a JSON evidence file if it exists."""
    path = EVIDENCE_DIR / filename
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return None


def main():
    print("=" * 60)
    print("Generating Consolidated PQC-PCI-DSS Migration Report")
    print("=" * 60)

    report = {
        "title": "PQC-PCI-DSS Migration Pack — Consolidated Evidence Report",
        "generated": datetime.now().isoformat(),
        "compliance_standards": ["NIST FIPS 203/204/205", "PCI-DSS v4.0"],
        "lab_results": {},
        "overall_status": "COMPLETE"
    }

    labs = {
        "lab1": {"file": "lab1_pqc_pcidss_alignment.json", "name": "Standards Mapping"},
        "lab2": {"file": "lab2_algorithm_test_evidence.json", "name": "Algorithm Testing"},
        "lab3": {"file": "lab3_tls_evidence.json", "name": "TLS Configuration"},
        "lab4": {"file": "lab4_crypto_inventory.json", "name": "Crypto Inventory"},
        "lab5": {"file": "lab5_bb84_evidence.json", "name": "BB84 Simulation"},
        "lab6": {"file": "lab6_qkd_attack_detection.json", "name": "QKD Attack Detection"},
        "lab7": {"file": "lab7_migration_roadmap.json", "name": "Migration Roadmap"},
        "lab8": {"file": "lab8_pqc_envelope_evidence.json", "name": "ML-KEM Envelope Encryption"},
        "lab9": {"file": "lab9_kubernetes_crypto_baseline.json", "name": "Kubernetes Crypto Baseline"},
        "lab10": {"file": "lab10_vault_secret_policy.json", "name": "Vault Secret Policy"},
        "lab11": {"file": "lab11_vault_pki_issuance.json", "name": "Vault PKI Issuance"},
        "lab12": {"file": "lab12_service_mesh_mtls.json", "name": "Service-Mesh mTLS"},
        "lab13": {"file": "lab13_iac_security_validation.json", "name": "IaC Security Validation"},
        "lab14": {"file": "lab14_network_policy_analysis.json", "name": "Network-Policy Analysis"},
        "lab15": {"file": "lab15_key_rotation.json", "name": "Automated Key Rotation"},
        "lab16": {"file": "lab16_configuration_drift.json", "name": "Configuration Drift"},
        "lab17": {"file": "lab17_zero_trust_policy.json", "name": "Zero-Trust Policy"},
        "lab18": {"file": "lab18_multi_region_failover.json", "name": "Multi-Region Failover"},
    }

    for lab_id, lab_info in labs.items():
        data = load_evidence(lab_info["file"])
        if data:
            report["lab_results"][lab_id] = {
                "name": lab_info["name"],
                "status": "COMPLETE",
                "evidence_file": lab_info["file"],
                "summary": extract_summary(lab_id, data)
            }
            print(f"  [PASS] {lab_id}: {lab_info['name']} - COMPLETE")
        else:
            report["lab_results"][lab_id] = {
                "name": lab_info["name"],
                "status": "MISSING",
                "evidence_file": lab_info["file"]
            }
            report["overall_status"] = "PARTIAL"
            print(f"  [MISS] {lab_id}: {lab_info['name']} - MISSING")

    # Write consolidated report
    report_path = REPORTS_DIR / "consolidated_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    # Write markdown summary
    md_path = REPORTS_DIR / "REPORT.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# PQC-PCI-DSS Migration Report\n\n")
        f.write(f"**Generated:** {report['generated']}\n\n")
        f.write(f"**Status:** {report['overall_status']}\n\n")
        f.write("## Lab Results\n\n")
        f.write("| Lab | Name | Status |\n")
        f.write("|-----|------|--------|\n")
        for lab_id, result in report["lab_results"].items():
            status_icon = "✅" if result["status"] == "COMPLETE" else "❌"
            f.write(f"| {lab_id} | {result['name']} | {status_icon} {result['status']} |\n")

    print(f"\nReport: {report_path}")
    print(f"Summary: {md_path}")


def extract_summary(lab_id, data):
    """Extract key metrics from lab data."""
    if lab_id == "lab1":
        return {
            "alignments": len(data.get("alignments", [])),
            "decisions": len(data.get("algorithm_decisions", []))
        }
    elif lab_id == "lab2":
        s = data.get("summary", {})
        return {"passed": s.get("passed", 0), "failed": s.get("failed", 0)}
    elif lab_id == "lab4":
        return {
            "total_assets": data.get("total_assets", 0),
            "vulnerable": data.get("quantum_vulnerable_assets", 0)
        }
    elif lab_id == "lab5":
        return {"experiments": len(data.get("experiments", []))}
    elif lab_id == "lab6":
        trials = data.get("trials", [])
        attacks = [trial for trial in trials if "ATTACK_SUSPECTED" in trial.get("classification", "")]
        return {"trials": len(trials), "attack_indicators": len(attacks)}
    elif lab_id == "lab7":
        phases = data.get("phases", [])
        milestones = sum(len(p.get("milestones", [])) for p in phases)
        return {"phases": len(phases), "milestones": milestones}
    elif lab_id == "lab8":
        return {
            "kem": data.get("result", {}).get("kem", "ML-KEM-768"),
            "status": data.get("status", "UNKNOWN"),
        }
    elif lab_id == "lab9":
        return {
            "service": data.get("service", "unknown"),
            "checks_run": data.get("policy_checks", {}).get("checks_run", 0),
            "violations": len(data.get("policy_checks", {}).get("violations", [])),
        }
    elif lab_id in {"lab10", "lab11", "lab12", "lab13", "lab14", "lab15", "lab16", "lab17", "lab18"}:
        return {"status": data.get("status", "UNKNOWN"), "violations": len(data.get("violations", []))}
    return {}


if __name__ == "__main__":
    main()