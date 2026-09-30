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
    }

    for lab_id, lab_info in labs.items():
        data = load_evidence(lab_info["file"])
        if data:
            evidence_status = data.get("status", "COMPLETE")
            status = "SKIPPED" if evidence_status == "SKIPPED" else (
                "FAILED" if evidence_status in {"FAIL", "FAILED", "ERROR"} else "COMPLETE"
            )
            report["lab_results"][lab_id] = {
                "name": lab_info["name"],
                "status": status,
                "evidence_file": lab_info["file"],
                "summary": extract_summary(lab_id, data)
            }
            if status != "COMPLETE":
                report["overall_status"] = "PARTIAL"
            print(f"  [{status}] {lab_id}: {lab_info['name']} - {status}")
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
            status_icon = "✅" if result["status"] == "COMPLETE" else (
                "⏭️" if result["status"] == "SKIPPED" else "❌"
            )
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
    return {}


if __name__ == "__main__":
    main()