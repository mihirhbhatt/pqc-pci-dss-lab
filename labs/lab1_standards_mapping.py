#!/usr/bin/env python3
"""
Lab 1: NIST PQC Standards to PCI-DSS v4.0 Control Mapping
Produces alignment matrix and decision framework.

Can run without any PQC library — pure data mapping.
"""

import json
import csv
import os
from datetime import datetime
from pathlib import Path

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "evidence"))
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def get_nist_standards():
    """Define NIST PQC standards reference data."""
    return {
        "FIPS_203": {
            "standard": "FIPS 203",
            "name": "ML-KEM",
            "full_name": "Module-Lattice-Based Key-Encapsulation Mechanism",
            "previous_name": "CRYSTALS-Kyber",
            "type": "KEM",
            "parameter_sets": {
                "ML-KEM-512": {"level": 1, "pk_bytes": 800, "ct_bytes": 768, "ss_bytes": 32},
                "ML-KEM-768": {"level": 3, "pk_bytes": 1184, "ct_bytes": 1088, "ss_bytes": 32},
                "ML-KEM-1024": {"level": 5, "pk_bytes": 1568, "ct_bytes": 1568, "ss_bytes": 32},
            },
            "replaces": ["RSA key exchange", "ECDH key agreement", "DH key exchange"]
        },
        "FIPS_204": {
            "standard": "FIPS 204",
            "name": "ML-DSA",
            "full_name": "Module-Lattice-Based Digital Signature Algorithm",
            "previous_name": "CRYSTALS-Dilithium",
            "type": "Digital Signature",
            "parameter_sets": {
                "ML-DSA-44": {"level": 2, "pk_bytes": 1312, "sig_bytes": 2420},
                "ML-DSA-65": {"level": 3, "pk_bytes": 1952, "sig_bytes": 3293},
                "ML-DSA-87": {"level": 5, "pk_bytes": 2592, "sig_bytes": 4595},
            },
            "replaces": ["RSA signatures", "ECDSA", "EdDSA"]
        },
        "FIPS_205": {
            "standard": "FIPS 205",
            "name": "SLH-DSA",
            "full_name": "Stateless Hash-Based Digital Signature Algorithm",
            "previous_name": "SPHINCS+",
            "type": "Digital Signature (Hash-Based)",
            "parameter_sets": {
                "SLH-DSA-SHA2-128s": {"level": 1, "pk_bytes": 32, "sig_bytes": 7856},
                "SLH-DSA-SHA2-128f": {"level": 1, "pk_bytes": 32, "sig_bytes": 17088},
                "SLH-DSA-SHA2-256s": {"level": 5, "pk_bytes": 64, "sig_bytes": 29792},
            },
            "replaces": ["RSA signatures (conservative alternative)"]
        }
    }


def get_pcidss_requirements():
    """Define PCI-DSS v4.0 cryptographic requirements."""
    return {
        "2.2.7": {
            "title": "System Configuration — Cryptographic Protocols",
            "quantum_risk": "HIGH",
            "pqc_action": "Identify quantum-vulnerable protocols; plan migration"
        },
        "3.5.1": {
            "title": "PAN Rendered Unreadable with Strong Cryptography",
            "quantum_risk": "MEDIUM",
            "pqc_action": "Audit key management chain; replace RSA/ECDH key wrapping with ML-KEM"
        },
        "3.6.1": {
            "title": "Key Management — Generation, Distribution, Storage",
            "quantum_risk": "HIGH",
            "pqc_action": "Update key generation and distribution to ML-KEM"
        },
        "3.7.1": {
            "title": "Key Management — Cryptoperiod Definition",
            "quantum_risk": "CRITICAL",
            "pqc_action": "Align cryptoperiods with quantum threat timeline"
        },
        "4.2.1": {
            "title": "Strong Cryptography for PAN Transmission",
            "quantum_risk": "CRITICAL",
            "pqc_action": "Deploy hybrid TLS with ML-KEM key exchange and ML-DSA certificates"
        },
        "4.2.2": {
            "title": "PAN Secured in End-User Messaging",
            "quantum_risk": "HIGH",
            "pqc_action": "Verify messaging encryption providers' PQC roadmaps"
        },
        "12.3.3": {
            "title": "Cryptographic Cipher Suite and Protocol Inventory",
            "quantum_risk": "CRITICAL",
            "pqc_action": "Build inventory with quantum vulnerability tagging"
        },
        "12.3.4": {
            "title": "Annual Technology Review",
            "quantum_risk": "HIGH",
            "pqc_action": "Add quantum vulnerability to annual review checklist"
        }
    }


def build_alignments():
    """Build the cross-reference alignments."""
    return [
        {
            "pci_req": "3.5.1",
            "nist_standard": "FIPS 203",
            "algorithm": "ML-KEM-768 or ML-KEM-1024",
            "use_case": "Key wrapping for PAN encryption keys",
            "replaces": "RSA-2048/4096 key wrapping, ECDH key agreement",
            "migration_priority": "HIGH",
            "rationale": "Symmetric PAN encryption is quantum-safe but key management chain is not."
        },
        {
            "pci_req": "3.6.1",
            "nist_standard": "FIPS 203",
            "algorithm": "ML-KEM-768",
            "use_case": "Key distribution and establishment",
            "replaces": "RSA key transport, DH key agreement",
            "migration_priority": "HIGH",
            "rationale": "Key management procedures must use quantum-safe key encapsulation."
        },
        {
            "pci_req": "3.7.1",
            "nist_standard": "FIPS 203 + FIPS 204",
            "algorithm": "ML-KEM + ML-DSA",
            "use_case": "Cryptoperiod-aware key lifecycle management",
            "replaces": "RSA/ECDH + RSA/ECDSA",
            "migration_priority": "CRITICAL",
            "rationale": "Keys with long cryptoperiods must use quantum-safe algorithms."
        },
        {
            "pci_req": "4.2.1",
            "nist_standard": "FIPS 203 + FIPS 204",
            "algorithm": "ML-KEM-768 + ML-DSA-65",
            "use_case": "TLS protection for PAN in transit",
            "replaces": "ECDHE + RSA/ECDSA certificates",
            "migration_priority": "CRITICAL",
            "rationale": "Recorded TLS sessions are vulnerable to harvest-now-decrypt-later."
        },
        {
            "pci_req": "4.2.1",
            "nist_standard": "FIPS 204",
            "algorithm": "ML-DSA-65 or ML-DSA-87",
            "use_case": "TLS certificate authentication",
            "replaces": "RSA/ECDSA certificate signatures",
            "migration_priority": "HIGH",
            "rationale": "Certificate signatures must resist quantum forgery."
        },
        {
            "pci_req": "4.2.2",
            "nist_standard": "FIPS 203",
            "algorithm": "ML-KEM-768",
            "use_case": "Messaging encryption key exchange",
            "replaces": "ECDH in messaging protocols",
            "migration_priority": "HIGH",
            "rationale": "PAN in messaging requires quantum-safe key exchange."
        },
        {
            "pci_req": "12.3.3",
            "nist_standard": "All (FIPS 203, 204, 205)",
            "algorithm": "Inventory requirement",
            "use_case": "Cryptographic inventory with quantum vulnerability tagging",
            "replaces": "Static cipher suite lists",
            "migration_priority": "CRITICAL",
            "rationale": "Inventory is the prerequisite for all PQC migration."
        },
        {
            "pci_req": "12.3.4",
            "nist_standard": "All",
            "algorithm": "Review requirement",
            "use_case": "Annual quantum readiness review",
            "replaces": "Reviews without quantum risk assessment",
            "migration_priority": "HIGH",
            "rationale": "Annual reviews must confirm PQC migration progress."
        },
        {
            "pci_req": "2.2.7",
            "nist_standard": "FIPS 203 + FIPS 204",
            "algorithm": "ML-KEM + ML-DSA",
            "use_case": "System hardening against quantum-vulnerable protocols",
            "replaces": "Configurations using RSA/DH/ECDH/ECDSA without quantum risk documentation",
            "migration_priority": "MEDIUM",
            "rationale": "System hardening must address quantum-vulnerable cryptography."
        }
    ]


def build_algorithm_decisions():
    """Build algorithm selection decision matrix."""
    return [
        {
            "use_case": "TLS key exchange protecting PAN",
            "current": "ECDHE-P256",
            "recommended": "ML-KEM-768 (hybrid with ECDHE)",
            "nist": "FIPS 203",
            "pci_req": "4.2.1",
            "priority": "P1"
        },
        {
            "use_case": "TLS server certificate",
            "current": "RSA-2048 / ECDSA-P256",
            "recommended": "ML-DSA-65 (hybrid during transition)",
            "nist": "FIPS 204",
            "pci_req": "4.2.1",
            "priority": "P1"
        },
        {
            "use_case": "PAN encryption key wrapping",
            "current": "RSA-2048 OAEP",
            "recommended": "ML-KEM-1024",
            "nist": "FIPS 203",
            "pci_req": "3.5.1, 3.6.1",
            "priority": "P1"
        },
        {
            "use_case": "Code signing for payment apps",
            "current": "RSA-4096",
            "recommended": "ML-DSA-87 or SLH-DSA-SHA2-256s",
            "nist": "FIPS 204 / FIPS 205",
            "pci_req": "6.2",
            "priority": "P2"
        },
        {
            "use_case": "Root CA certificate",
            "current": "RSA-4096",
            "recommended": "ML-DSA-87 or SLH-DSA-SHA2-256s",
            "nist": "FIPS 204 / FIPS 205",
            "pci_req": "4.2.1",
            "priority": "P1"
        },
        {
            "use_case": "Audit log integrity",
            "current": "HMAC-SHA256",
            "recommended": "No change needed (already quantum-safe)",
            "nist": "N/A",
            "pci_req": "10.3",
            "priority": "P4"
        },
        {
            "use_case": "VPN key exchange (CDE segmentation)",
            "current": "ECDH-P384",
            "recommended": "ML-KEM-768 hybrid",
            "nist": "FIPS 203",
            "pci_req": "4.2.1",
            "priority": "P2"
        }
    ]


def main():
    """Execute Lab 1."""
    print("=" * 70)
    print("LAB 1: NIST PQC to PCI-DSS v4.0 Control Mapping")
    print("=" * 70)

    standards = get_nist_standards()
    requirements = get_pcidss_requirements()
    alignments = build_alignments()
    decisions = build_algorithm_decisions()

    # Print summary
    print(f"\nNIST PQC Standards: {len(standards)}")
    for key, std in standards.items():
        print(f"  {std['standard']}: {std['name']} ({std['type']})")
        for ps, info in std['parameter_sets'].items():
            print(f"    {ps}: Level {info['level']}")

    print(f"\nPCI-DSS Requirements: {len(requirements)}")
    for req_id, req in requirements.items():
        print(f"  {req_id}: {req['title']} [{req['quantum_risk']}]")

    print(f"\nAlignments: {len(alignments)}")
    for a in alignments:
        print(f"  PCI {a['pci_req']} → {a['nist_standard']}: {a['algorithm']} [{a['migration_priority']}]")

    print(f"\nDecisions: {len(decisions)}")
    for d in decisions:
        print(f"  {d['use_case']}: {d['current']} → {d['recommended']} [{d['priority']}]")

    # Export evidence
    evidence = {
        "report_type": "NIST PQC to PCI-DSS v4.0 Alignment",
        "generated": datetime.now().isoformat(),
        "nist_standards": standards,
        "pci_dss_requirements": requirements,
        "alignments": alignments,
        "algorithm_decisions": decisions,
        "pci_dss_version": "4.0",
        "nist_standards_referenced": ["FIPS 203", "FIPS 204", "FIPS 205"]
    }

    json_path = EVIDENCE_DIR / "lab1_pqc_pcidss_alignment.json"
    with open(json_path, "w") as f:
        json.dump(evidence, f, indent=2)

    csv_path = EVIDENCE_DIR / "lab1_pqc_pcidss_alignment.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "pci_req", "nist_standard", "algorithm",
            "use_case", "replaces", "migration_priority", "rationale"
        ])
        writer.writeheader()
        writer.writerows(alignments)

    print(f"\n✓ Evidence: {json_path}")
    print(f"✓ Evidence: {csv_path}")
    print("LAB 1 COMPLETE")


if __name__ == "__main__":
    main()