#!/usr/bin/env python3
"""
Lab 6: 90-Day PQC Migration Roadmap for PCI-DSS Compliance

Integrates all previous lab outputs into an actionable migration plan
with three phases, milestones, owners, acceptance criteria, and
rollback conditions.

No PQC library required - pure planning and documentation.
"""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "evidence"))
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

START_DATE = datetime(2025, 7, 1)


def build_migration_roadmap():
    """Build the complete 90-day migration roadmap."""

    roadmap = {
        "title": "90-Day Post-Quantum Cryptography Migration Roadmap",
        "organization": "Payment Processing Organization (Template)",
        "compliance_standards": ["PCI-DSS v4.0", "NIST FIPS 203/204/205"],
        "start_date": START_DATE.strftime("%Y-%m-%d"),
        "end_date": (START_DATE + timedelta(days=90)).strftime("%Y-%m-%d"),
        "executive_summary": (
            "This roadmap addresses the quantum threat to PCI-DSS cryptographic "
            "controls by migrating public-key cryptography to NIST-standardized "
            "post-quantum algorithms. The plan prioritizes harvest-now-decrypt-later "
            "risks to cardholder data, aligns with PCI-DSS v4.0 Requirements 3, 4, "
            "and 12, and establishes crypto-agility for future transitions."
        ),
        "phases": [
            # ================================================================
            # PHASE 1: Discovery and Planning (Days 1-30)
            # ================================================================
            {
                "phase": 1,
                "name": "Discovery, Inventory, and Planning",
                "start_day": 1,
                "end_day": 30,
                "objective": (
                    "Complete cryptographic inventory (PCI-DSS 12.3.3), assess "
                    "quantum risk, select target algorithms, secure approvals."
                ),
                "milestones": [
                    {
                        "milestone_id": "M1.1",
                        "name": "Cryptographic Inventory Complete",
                        "due_day": 14,
                        "due_date": (START_DATE + timedelta(days=14)).strftime("%Y-%m-%d"),
                        "owner": "Security Architecture Team",
                        "description": (
                            "All cryptographic assets in PCI-DSS scope identified "
                            "and tagged with algorithm, purpose, data lifetime, "
                            "quantum vulnerability, and owner."
                        ),
                        "deliverables": [
                            "Complete asset inventory (Lab 4 output)",
                            "Quantum vulnerability assessment per asset",
                            "PCI-DSS requirement mapping per asset"
                        ],
                        "acceptance_criteria": [
                            "Minimum 10 assets documented",
                            "Each asset has owner, algorithm, purpose, quantum risk",
                            "Covers TLS, PKI, key mgmt, VPN, code signing, backups",
                            "Satisfies PCI-DSS Requirement 12.3.3"
                        ],
                        "status": "NOT_STARTED"
                    },
                    {
                        "milestone_id": "M1.2",
                        "name": "Algorithm Selection Documented",
                        "due_day": 21,
                        "due_date": (START_DATE + timedelta(days=21)).strftime("%Y-%m-%d"),
                        "owner": "Security Architecture Team",
                        "description": (
                            "Target PQC algorithm selected for each asset category "
                            "based on NIST standards and interoperability."
                        ),
                        "deliverables": [
                            "Algorithm selection matrix (Lab 1 output)",
                            "NIST FIPS 203/204/205 mapping per asset",
                            "Hybrid transition strategy document"
                        ],
                        "acceptance_criteria": [
                            "ML-KEM parameter set selected for key exchange",
                            "ML-DSA or SLH-DSA selected for signatures",
                            "Hybrid approach documented for transition",
                            "Size and interop risks documented"
                        ],
                        "status": "NOT_STARTED"
                    },
                    {
                        "milestone_id": "M1.3",
                        "name": "Vendor and HSM PQC Readiness",
                        "due_day": 28,
                        "due_date": (START_DATE + timedelta(days=28)).strftime("%Y-%m-%d"),
                        "owner": "Security Architecture + Vendor Management",
                        "description": "Assess PQC support for all vendors and HSMs.",
                        "deliverables": [
                            "Vendor PQC readiness matrix",
                            "HSM firmware upgrade requirements",
                            "Gap analysis for vendors without PQC roadmaps"
                        ],
                        "acceptance_criteria": [
                            "Every vendor has documented PQC support status",
                            "HSM PQC capabilities confirmed or upgrade path identified",
                            "Compensating controls for unsupported vendors"
                        ],
                        "status": "NOT_STARTED"
                    },
                    {
                        "milestone_id": "M1.4",
                        "name": "Migration Plan Approved",
                        "due_day": 30,
                        "due_date": (START_DATE + timedelta(days=30)).strftime("%Y-%m-%d"),
                        "owner": "CISO / Security Leadership",
                        "description": "Phase 2 and 3 plan reviewed and approved.",
                        "deliverables": [
                            "Migration plan with phases, owners, timelines",
                            "Budget request for HSM upgrades",
                            "Risk acceptance for deferred assets"
                        ],
                        "acceptance_criteria": [
                            "Plan approved by CISO",
                            "Resources allocated for Phase 2",
                            "QSA informed of PQC migration initiative"
                        ],
                        "status": "NOT_STARTED"
                    }
                ]
            },
            # ================================================================
            # PHASE 2: Lab Testing (Days 31-60)
            # ================================================================
            {
                "phase": 2,
                "name": "Lab Testing, Validation, and Proof of Concept",
                "start_day": 31,
                "end_day": 60,
                "objective": (
                    "Test PQC algorithms in lab, validate interoperability, "
                    "measure performance, demonstrate PCI-DSS control effectiveness."
                ),
                "milestones": [
                    {
                        "milestone_id": "M2.1",
                        "name": "PQC Algorithm Validation",
                        "due_day": 38,
                        "due_date": (START_DATE + timedelta(days=38)).strftime("%Y-%m-%d"),
                        "owner": "Security Engineering Team",
                        "description": "ML-KEM and ML-DSA tested for correctness.",
                        "deliverables": [
                            "Algorithm test evidence (Lab 2 output)",
                            "Positive and negative test results",
                            "Performance benchmarks"
                        ],
                        "acceptance_criteria": [
                            "All positive tests pass for ML-KEM-768 and ML-DSA-65",
                            "Negative tests correctly reject invalid inputs",
                            "Performance within payment processing latency bounds",
                            "Evidence documented in auditable format"
                        ],
                        "status": "NOT_STARTED"
                    },
                    {
                        "milestone_id": "M2.2",
                        "name": "Hybrid TLS Proof of Concept",
                        "due_day": 45,
                        "due_date": (START_DATE + timedelta(days=45)).strftime("%Y-%m-%d"),
                        "owner": "Network Security Team",
                        "description": "Deploy hybrid TLS in lab environment.",
                        "deliverables": [
                            "TLS configuration evidence (Lab 3 output)",
                            "Hybrid handshake capture",
                            "Certificate chain size measurement",
                            "Client compatibility results"
                        ],
                        "acceptance_criteria": [
                            "Hybrid TLS 1.3 handshake completes",
                            "PAN test data transmitted correctly",
                            "No MTU fragmentation issues",
                            "Rollback to classical TLS verified"
                        ],
                        "status": "NOT_STARTED"
                    },
                    {
                        "milestone_id": "M2.3",
                        "name": "Key Management PQC Integration",
                        "due_day": 52,
                        "due_date": (START_DATE + timedelta(days=52)).strftime("%Y-%m-%d"),
                        "owner": "Application Security Team",
                        "description": "Test ML-KEM key wrapping for PAN encryption.",
                        "deliverables": [
                            "Key wrapping test with ML-KEM-1024",
                            "Key rotation procedure with PQC KEK",
                            "Dual-KEK compatibility validation"
                        ],
                        "acceptance_criteria": [
                            "PAN encrypted with AES-256 using ML-KEM-derived DEK",
                            "PAN decrypted successfully",
                            "Old PAN (classical KEK) remains decryptable"
                        ],
                        "status": "NOT_STARTED"
                    },
                    {
                        "milestone_id": "M2.4",
                        "name": "QKD Suitability Assessment",
                        "due_day": 55,
                        "due_date": (START_DATE + timedelta(days=55)).strftime("%Y-%m-%d"),
                        "owner": "Security Architecture Team",
                        "description": "Document QKD suitability for PCI-DSS.",
                        "deliverables": [
                            "BB84 simulation results (Lab 5 output)",
                            "QKD vs PQC suitability matrix",
                            "Recommendation document"
                        ],
                        "acceptance_criteria": [
                            "BB84 QBER thresholds demonstrated",
                            "QKD authentication requirement documented",
                            "QKD limitations documented",
                            "Clear recommendation on QKD role"
                        ],
                        "status": "NOT_STARTED"
                    },
                    {
                        "milestone_id": "M2.5",
                        "name": "Go/No-Go for Pilot",
                        "due_day": 60,
                        "due_date": (START_DATE + timedelta(days=60)).strftime("%Y-%m-%d"),
                        "owner": "CISO / Security Leadership",
                        "description": "Review Phase 2 results; approve pilot.",
                        "deliverables": [
                            "Phase 2 test summary",
                            "Pilot deployment plan with rollback triggers",
                            "Change management approval"
                        ],
                        "acceptance_criteria": [
                            "All Phase 2 acceptance criteria met",
                            "No blocking issues identified",
                            "Pilot scope defined with limited traffic",
                            "Rollback procedure documented and tested"
                        ],
                        "status": "NOT_STARTED"
                    }
                ]
            },
            # ================================================================
            # PHASE 3: Pilot Deployment (Days 61-90)
            # ================================================================
            {
                "phase": 3,
                "name": "Pilot Deployment and Operational Validation",
                "start_day": 61,
                "end_day": 90,
                "objective": (
                    "Deploy PQC in controlled production pilot, monitor for issues, "
                    "establish operational procedures for full migration."
                ),
                "milestones": [
                    {
                        "milestone_id": "M3.1",
                        "name": "Hybrid TLS Pilot Deployed",
                        "due_day": 68,
                        "due_date": (START_DATE + timedelta(days=68)).strftime("%Y-%m-%d"),
                        "owner": "Network Security + Operations",
                        "description": (
                            "Enable hybrid TLS on one payment gateway for limited traffic."
                        ),
                        "deliverables": [
                            "Pilot deployment evidence",
                            "Traffic monitoring dashboard",
                            "Error rate baseline comparison"
                        ],
                        "acceptance_criteria": [
                            "Hybrid TLS active on designated gateway",
                            "No increase in connection failures above 0.1 percent",
                            "No increase in transaction latency p99 above 50ms",
                            "Rollback tested and verified within 5 minutes"
                        ],
                        "rollback_trigger": [
                            "Connection failure rate exceeds 0.5 percent",
                            "Transaction latency p99 increases above 100ms",
                            "Any payment processing error attributed to PQC change"
                        ],
                        "status": "NOT_STARTED"
                    },
                    {
                        "milestone_id": "M3.2",
                        "name": "PQC Key Management Pilot",
                        "due_day": 75,
                        "due_date": (START_DATE + timedelta(days=75)).strftime("%Y-%m-%d"),
                        "owner": "Application Security Team",
                        "description": (
                            "Enable ML-KEM key wrapping for new PAN encryption keys."
                        ),
                        "deliverables": [
                            "New PAN encrypted with PQC-wrapped DEK",
                            "Operational monitoring for key management errors",
                            "Dual-KEK operational procedures"
                        ],
                        "acceptance_criteria": [
                            "New PAN encrypted and decrypted with PQC KEK",
                            "Key rotation executed without errors",
                            "Existing PAN (classical KEK) access unaffected"
                        ],
                        "rollback_trigger": [
                            "Any PAN decryption failure",
                            "Key rotation error",
                            "HSM performance degradation"
                        ],
                        "status": "NOT_STARTED"
                    },
                    {
                        "milestone_id": "M3.3",
                        "name": "PCI-DSS Documentation Updated",
                        "due_day": 82,
                        "due_date": (START_DATE + timedelta(days=82)).strftime("%Y-%m-%d"),
                        "owner": "Compliance / GRC Team",
                        "description": (
                            "Update PCI-DSS compliance docs to reflect PQC migration."
                        ),
                        "deliverables": [
                            "Updated cryptographic inventory (Req 12.3.3)",
                            "Updated cipher suite documentation (Req 2.2.7)",
                            "Updated key management procedures (Req 3.6.1, 3.7.1)",
                            "Updated data transmission docs (Req 4.2.1)",
                            "PQC migration plan for QSA review"
                        ],
                        "acceptance_criteria": [
                            "All PCI-DSS cryptographic requirements updated",
                            "Quantum risk assessment documented",
                            "Migration timeline and compensating controls documented",
                            "QSA pre-review scheduled"
                        ],
                        "status": "NOT_STARTED"
                    },
                    {
                        "milestone_id": "M3.4",
                        "name": "Crypto-Agility Framework Established",
                        "due_day": 85,
                        "due_date": (START_DATE + timedelta(days=85)).strftime("%Y-%m-%d"),
                        "owner": "Security Architecture Team",
                        "description": (
                            "Establish ongoing crypto-agility for future transitions."
                        ),
                        "deliverables": [
                            "Crypto-agility design principles document",
                            "Algorithm configuration externalization standard",
                            "Automated crypto inventory scanning if feasible",
                            "Annual quantum readiness review procedure (Req 12.3.4)"
                        ],
                        "acceptance_criteria": [
                            "New systems support algorithm config without code changes",
                            "Cryptographic library abstraction layer defined",
                            "Annual review checklist includes quantum assessment"
                        ],
                        "status": "NOT_STARTED"
                    },
                    {
                        "milestone_id": "M3.5",
                        "name": "90-Day Review and Next Phase Planning",
                        "due_day": 90,
                        "due_date": (START_DATE + timedelta(days=90)).strftime("%Y-%m-%d"),
                        "owner": "CISO / Security Leadership",
                        "description": (
                            "Review 90-day outcomes, document lessons learned, "
                            "plan next migration phase."
                        ),
                        "deliverables": [
                            "90-day migration summary report",
                            "Lessons learned document",
                            "Next phase plan (91-180 day roadmap)",
                            "Updated risk register with quantum risk entries"
                        ],
                        "acceptance_criteria": [
                            "All P1 assets have migration in progress or completed",
                            "Pilot deployment stable for minimum 14 days",
                            "PCI-DSS documentation updated",
                            "Next phase resourced and scheduled"
                        ],
                        "status": "NOT_STARTED"
                    }
                ]
            }
        ]
    }

    return roadmap


def print_roadmap(roadmap):
    """Print formatted roadmap to console."""

    print("\n" + "=" * 70)
    print(roadmap["title"])
    print(f"Start: {roadmap['start_date']} | End: {roadmap['end_date']}")
    print("=" * 70)
    print(f"\n{roadmap['executive_summary']}")

    for phase in roadmap["phases"]:
        print(f"\n{'=' * 70}")
        print(f"PHASE {phase['phase']}: {phase['name']} "
              f"(Days {phase['start_day']}-{phase['end_day']})")
        print(f"{'=' * 70}")
        print(f"Objective: {phase['objective']}")

        for m in phase["milestones"]:
            print(f"\n  [{m['milestone_id']}] {m['name']}")
            print(f"  Due: Day {m['due_day']} ({m['due_date']}) | "
                  f"Owner: {m['owner']}")
            print(f"  Description: {m['description']}")
            print(f"  Acceptance Criteria:")
            for ac in m["acceptance_criteria"]:
                print(f"    [ ] {ac}")
            if "rollback_trigger" in m:
                print(f"  Rollback Triggers:")
                for rt in m["rollback_trigger"]:
                    print(f"    [!] {rt}")

    # Timeline
    print(f"\n{'=' * 70}")
    print("TIMELINE")
    print(f"{'=' * 70}")
    print(f"\n  Day 1-------14------21------30-------38------45------60"
          f"-------68------75------90")
    print(f"      |--------|-------|-------|--------|-------|-------|"
          f"--------|-------|-------|")
    print(f"      [--- PHASE 1: DISCOVERY ---][--- PHASE 2: TESTING ---]"
          f"[--- PHASE 3: PILOT ---]")
    print(f"      M1.1    M1.2   M1.3  M1.4  M2.1   M2.2  M2.5  M3.1  "
          f"M3.2  M3.5")

    # Summary stats
    total_milestones = sum(len(p["milestones"]) for p in roadmap["phases"])
    total_criteria = sum(
        len(m["acceptance_criteria"])
        for p in roadmap["phases"]
        for m in p["milestones"]
    )
    print(f"\n  Total Phases: {len(roadmap['phases'])}")
    print(f"  Total Milestones: {total_milestones}")
    print(f"  Total Acceptance Criteria: {total_criteria}")


def export_roadmap_evidence(roadmap):
    """Export roadmap as auditable evidence files."""

    # JSON export
    json_path = EVIDENCE_DIR / "lab6_migration_roadmap.json"
    with open(json_path, "w") as f:
        json.dump(roadmap, f, indent=2)

    # Checklist export
    checklist_path = EVIDENCE_DIR / "lab6_milestone_checklist.txt"
    with open(checklist_path, "w") as f:
        f.write("PQC MIGRATION MILESTONE CHECKLIST\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write("=" * 60 + "\n\n")

        for phase in roadmap["phases"]:
            f.write(f"PHASE {phase['phase']}: {phase['name']}\n")
            f.write("-" * 40 + "\n")
            for m in phase["milestones"]:
                f.write(f"\n[ ] {m['milestone_id']}: {m['name']}\n")
                f.write(f"    Due: {m['due_date']} | Owner: {m['owner']}\n")
                for ac in m["acceptance_criteria"]:
                    f.write(f"    [ ] {ac}\n")
                if "rollback_trigger" in m:
                    f.write(f"    Rollback Triggers:\n")
                    for rt in m["rollback_trigger"]:
                        f.write(f"    [!] {rt}\n")
            f.write("\n")

    print(f"\nEvidence exported:")
    print(f"  JSON:      {json_path}")
    print(f"  Checklist: {checklist_path}")


# =============================================================================
# MAIN
# =============================================================================

def main():
    print("=" * 70)
    print("LAB 6: 90-DAY PQC MIGRATION ROADMAP")
    print("NIST FIPS 203/204/205 + PCI-DSS v4.0")
    print("=" * 70)

    roadmap = build_migration_roadmap()
    print_roadmap(roadmap)
    export_roadmap_evidence(roadmap)

    print("\n" + "=" * 70)
    print("LAB 6 COMPLETE")
    print("Review milestone owners, acceptance criteria, and rollback triggers.")
    print("Present to security leadership for approval.")
    print("=" * 70)


if __name__ == "__main__":
    main()