#!/usr/bin/env python3
"""
Lab 4: Cryptographic Asset Inventory for PCI-DSS 12.3.3 + PQC Migration

Builds a complete cryptographic inventory covering 10 assets across a
representative payment processing environment. Each asset is tagged with
quantum vulnerability, PCI-DSS requirement mapping, priority score,
migration target, owner, test gate, and rollback plan.

No PQC library required — pure data analysis.
"""

import json
import csv
import os
from datetime import datetime
from pathlib import Path

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "evidence"))
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


# =============================================================================
# CRYPTOGRAPHIC ASSET INVENTORY
# Represents a realistic payment processing environment
# =============================================================================

CRYPTO_INVENTORY = [
    {
        "asset_id": "CRYPTO-001",
        "system_name": "Payment Gateway TLS Termination",
        "component": "NGINX reverse proxy",
        "location": "DMZ - payment-gw-01.prod",
        "algorithm": "ECDHE-ECDSA-AES256-GCM-SHA384",
        "key_exchange": "ECDHE-P256",
        "authentication": "ECDSA-P256",
        "encryption": "AES-256-GCM",
        "key_size_bits": 256,
        "protocol": "TLS 1.3",
        "purpose": "Encrypt PAN in transit from merchant to processor",
        "data_type": "Primary Account Number (PAN), Track Data",
        "data_classification": "PCI-DSS Cardholder Data",
        "data_lifetime_years": 0.01,
        "harvest_now_risk": "HIGH - Recorded sessions decryptable by quantum computer",
        "quantum_vulnerable_components": ["ECDHE key exchange", "ECDSA certificate"],
        "quantum_safe_components": ["AES-256-GCM symmetric encryption"],
        "pci_dss_requirements": ["4.2.1", "2.2.7"],
        "migration_target": "ML-KEM-768 key exchange + ML-DSA-65 certificate",
        "migration_approach": "Hybrid ECDHE+ML-KEM, then dual-certificate deployment",
        "owner": "Network Security Team",
        "vendor": "NGINX Inc.",
        "vendor_pqc_support": "Pending - depends on OpenSSL 3.x PQC provider",
        "hsm_dependency": True,
        "hsm_pqc_ready": False,
        "priority_score": None,
        "estimated_effort_days": 15,
        "test_gate": "Successful hybrid TLS handshake with all merchant clients",
        "rollback_plan": "Revert NGINX config to ECDHE-only cipher suite"
    },
    {
        "asset_id": "CRYPTO-002",
        "system_name": "Card Vault Encryption",
        "component": "Application-level encryption (Java Bouncy Castle)",
        "location": "Secure Zone - card-vault-01.prod",
        "algorithm": "AES-256-CBC with RSA-2048-OAEP key wrapping",
        "key_exchange": "RSA-2048 OAEP (key wrapping)",
        "authentication": "N/A (symmetric after unwrap)",
        "encryption": "AES-256-CBC",
        "key_size_bits": 256,
        "protocol": "Application-level",
        "purpose": "Encrypt stored PAN at rest",
        "data_type": "Primary Account Number (PAN)",
        "data_classification": "PCI-DSS Cardholder Data",
        "data_lifetime_years": 7,
        "harvest_now_risk": "CRITICAL - PAN stored long-term; RSA key wrapping breakable",
        "quantum_vulnerable_components": ["RSA-2048 key wrapping"],
        "quantum_safe_components": ["AES-256 data encryption"],
        "pci_dss_requirements": ["3.5.1", "3.6.1", "3.7.1"],
        "migration_target": "ML-KEM-1024 key encapsulation for KEK distribution",
        "migration_approach": "Replace RSA key transport with ML-KEM; retain AES-256 for DEK",
        "owner": "Application Security Team",
        "vendor": "In-house + Bouncy Castle",
        "vendor_pqc_support": "Bouncy Castle has PQC support in development builds",
        "hsm_dependency": True,
        "hsm_pqc_ready": False,
        "priority_score": None,
        "estimated_effort_days": 25,
        "test_gate": "Decrypt existing PAN with old KEK; encrypt new PAN with PQC KEK",
        "rollback_plan": "Maintain dual KEK (classical + PQC) during transition"
    },
    {
        "asset_id": "CRYPTO-003",
        "system_name": "Internal PKI - Root CA",
        "component": "EJBCA / Microsoft AD CS",
        "location": "HSM - offline root CA",
        "algorithm": "RSA-4096 SHA-256",
        "key_exchange": "N/A",
        "authentication": "RSA-4096 signature",
        "encryption": "N/A",
        "key_size_bits": 4096,
        "protocol": "X.509v3",
        "purpose": "Root trust anchor for all internal certificates",
        "data_type": "Trust anchor for certificate hierarchy",
        "data_classification": "Critical Infrastructure",
        "data_lifetime_years": 20,
        "harvest_now_risk": "CRITICAL - Root CA compromise allows impersonation of any service",
        "quantum_vulnerable_components": ["RSA-4096 signature"],
        "quantum_safe_components": [],
        "pci_dss_requirements": ["4.2.1", "3.6.1", "8.2"],
        "migration_target": "ML-DSA-87 or SLH-DSA-SHA2-256s for root CA signatures",
        "migration_approach": "Issue new PQC root CA; cross-sign with existing RSA root",
        "owner": "PKI Team / Security Architecture",
        "vendor": "In-house PKI",
        "vendor_pqc_support": "Requires PKI software and HSM firmware update",
        "hsm_dependency": True,
        "hsm_pqc_ready": False,
        "priority_score": None,
        "estimated_effort_days": 40,
        "test_gate": "New PQC root CA issues intermediate; full chain validates on test clients",
        "rollback_plan": "Classical RSA root CA remains active; PQC root is additive"
    },
    {
        "asset_id": "CRYPTO-004",
        "system_name": "API Gateway - OAuth2 JWT Signing",
        "component": "Kong API Gateway / Auth0",
        "location": "Application Zone - api-gw-01.prod",
        "algorithm": "RS256 (RSA-2048 PKCS#1 v1.5 with SHA-256)",
        "key_exchange": "N/A",
        "authentication": "RSA-2048 JWT signature",
        "encryption": "N/A (JWT is signed, not encrypted)",
        "key_size_bits": 2048,
        "protocol": "OAuth 2.0 / OIDC / JWT",
        "purpose": "Sign and verify API access tokens for payment services",
        "data_type": "Authentication tokens with PAN-adjacent claims",
        "data_classification": "Authentication / Authorization",
        "data_lifetime_years": 0.003,
        "harvest_now_risk": "MEDIUM - Token lifetime short but key forgery allows arbitrary tokens",
        "quantum_vulnerable_components": ["RSA-2048 JWT signature"],
        "quantum_safe_components": [],
        "pci_dss_requirements": ["8.2", "4.2.1"],
        "migration_target": "ML-DSA-44 for JWT signing",
        "migration_approach": "Update JWT library; support both RS256 and ML-DSA during transition",
        "owner": "Identity & Access Management Team",
        "vendor": "Auth0 / Kong",
        "vendor_pqc_support": "Not yet announced",
        "hsm_dependency": False,
        "hsm_pqc_ready": "N/A",
        "priority_score": None,
        "estimated_effort_days": 20,
        "test_gate": "All API consumers verify ML-DSA signed JWTs; RS256 fallback works",
        "rollback_plan": "Revert JWT signing key to RSA-2048; update JWKS endpoint"
    },
    {
        "asset_id": "CRYPTO-005",
        "system_name": "Database Backup Encryption",
        "component": "PostgreSQL pgcrypto + AWS KMS",
        "location": "Backup Zone - S3 encrypted backups",
        "algorithm": "AES-256-GCM with RSA-2048 envelope encryption (KMS)",
        "key_exchange": "RSA-2048 (KMS envelope encryption)",
        "authentication": "N/A",
        "encryption": "AES-256-GCM",
        "key_size_bits": 256,
        "protocol": "AWS KMS envelope encryption",
        "purpose": "Encrypt database backups containing cardholder data",
        "data_type": "PAN, cardholder name, expiration date",
        "data_classification": "PCI-DSS Cardholder Data",
        "data_lifetime_years": 7,
        "harvest_now_risk": "CRITICAL - Backups are long-lived; RSA envelope key breakable",
        "quantum_vulnerable_components": ["RSA-2048 envelope encryption key"],
        "quantum_safe_components": ["AES-256-GCM data encryption"],
        "pci_dss_requirements": ["3.5.1", "3.6.1", "3.7.1"],
        "migration_target": "AWS KMS PQC key type when available; or ML-KEM-1024 wrapping",
        "migration_approach": "Monitor AWS KMS PQC roadmap; re-encrypt backup KEKs with PQC",
        "owner": "Database Administration + Cloud Security",
        "vendor": "AWS",
        "vendor_pqc_support": "AWS announced PQC TLS; KMS PQC timeline TBD",
        "hsm_dependency": True,
        "hsm_pqc_ready": False,
        "priority_score": None,
        "estimated_effort_days": 10,
        "test_gate": "New backup encrypted with PQC envelope; restored successfully",
        "rollback_plan": "Classical KMS keys retained; new backups fall back to RSA envelope"
    },
    {
        "asset_id": "CRYPTO-006",
        "system_name": "POS Terminal Communication",
        "component": "Verifone/Ingenico terminal TLS client",
        "location": "Retail stores - 500+ terminals",
        "algorithm": "TLS 1.2 RSA-2048 key exchange",
        "key_exchange": "RSA-2048 key transport",
        "authentication": "RSA-2048 server certificate",
        "encryption": "AES-128-GCM",
        "key_size_bits": 128,
        "protocol": "TLS 1.2",
        "purpose": "Encrypt PAN from terminal to payment gateway",
        "data_type": "PAN, Track Data, PIN block",
        "data_classification": "PCI-DSS Cardholder Data + Sensitive Authentication Data",
        "data_lifetime_years": 0.01,
        "harvest_now_risk": "HIGH - RSA key transport lacks forward secrecy; sessions fully decryptable",
        "quantum_vulnerable_components": [
            "RSA-2048 key transport (no PFS)",
            "RSA-2048 server certificate"
        ],
        "quantum_safe_components": ["AES-128-GCM (should upgrade to AES-256)"],
        "pci_dss_requirements": ["4.2.1", "9.5", "2.2.7"],
        "migration_target": "TLS 1.3 with hybrid ECDHE+ML-KEM-768",
        "migration_approach": "Terminal firmware update; coordinate with vendor; phase by region",
        "owner": "Terminal Management Team",
        "vendor": "Verifone / Ingenico",
        "vendor_pqc_support": "Under evaluation - firmware updates expected 2026+",
        "hsm_dependency": True,
        "hsm_pqc_ready": False,
        "priority_score": None,
        "estimated_effort_days": 60,
        "test_gate": "Lab terminal completes TLS 1.3 PQC handshake; transaction processes end-to-end",
        "rollback_plan": "Terminal firmware rollback to current TLS 1.2 version"
    },
    {
        "asset_id": "CRYPTO-007",
        "system_name": "Code Signing - Payment Application",
        "component": "CI/CD pipeline signing (Jenkins + GPG)",
        "location": "Build Zone - ci-server-01.prod",
        "algorithm": "RSA-4096 SHA-256 (GPG signing key)",
        "key_exchange": "N/A",
        "authentication": "RSA-4096 signature",
        "encryption": "N/A",
        "key_size_bits": 4096,
        "protocol": "GPG / Sigstore",
        "purpose": "Sign payment application binaries and container images",
        "data_type": "Software integrity verification",
        "data_classification": "Software Supply Chain Security",
        "data_lifetime_years": 5,
        "harvest_now_risk": "HIGH - Forged signatures allow malicious payment app deployment",
        "quantum_vulnerable_components": ["RSA-4096 GPG signature"],
        "quantum_safe_components": [],
        "pci_dss_requirements": ["6.2", "6.3"],
        "migration_target": "ML-DSA-87 or SLH-DSA-SHA2-256s for code signing",
        "migration_approach": "Dual-sign binaries (RSA + PQC) during transition",
        "owner": "DevSecOps Team",
        "vendor": "In-house CI/CD",
        "vendor_pqc_support": "GPG PQC support in development; sigstore tracking",
        "hsm_dependency": False,
        "hsm_pqc_ready": "N/A",
        "priority_score": None,
        "estimated_effort_days": 15,
        "test_gate": "Dual-signed binary verifies with both classical and PQC keys",
        "rollback_plan": "Revert to RSA-only signing; remove PQC verification from pipeline"
    },
    {
        "asset_id": "CRYPTO-008",
        "system_name": "VPN - CDE Segmentation",
        "component": "strongSwan IPsec",
        "location": "Network boundary - vpn-concentrator-01.prod",
        "algorithm": "IKEv2 with ECDH-P384 + RSA-2048 authentication",
        "key_exchange": "ECDH-P384",
        "authentication": "RSA-2048 certificate",
        "encryption": "AES-256-GCM",
        "key_size_bits": 256,
        "protocol": "IKEv2 / IPsec",
        "purpose": "Segment and encrypt cardholder data environment access",
        "data_type": "All CDE traffic",
        "data_classification": "PCI-DSS Cardholder Data Environment",
        "data_lifetime_years": 0.01,
        "harvest_now_risk": "HIGH - Recorded VPN sessions could contain PAN traffic",
        "quantum_vulnerable_components": ["ECDH-P384 key exchange", "RSA-2048 authentication"],
        "quantum_safe_components": ["AES-256-GCM"],
        "pci_dss_requirements": ["4.2.1", "1.3"],
        "migration_target": "ML-KEM-768 hybrid key exchange + ML-DSA-65 authentication",
        "migration_approach": "Update VPN concentrator firmware; test with all CDE clients",
        "owner": "Network Security Team",
        "vendor": "strongSwan",
        "vendor_pqc_support": "strongSwan has PQC plugin available",
        "hsm_dependency": False,
        "hsm_pqc_ready": "N/A",
        "priority_score": None,
        "estimated_effort_days": 20,
        "test_gate": "VPN tunnel establishes with PQC; CDE access normal; throughput degradation <5%",
        "rollback_plan": "Revert VPN config to classical IKEv2 parameters"
    },
    {
        "asset_id": "CRYPTO-009",
        "system_name": "Email Encryption - PCI Reports",
        "component": "S/MIME on Exchange/Outlook",
        "location": "Corporate Zone - mail-server-01.prod",
        "algorithm": "S/MIME with RSA-2048 encryption + RSA-2048 signing",
        "key_exchange": "RSA-2048 key transport",
        "authentication": "RSA-2048 signature",
        "encryption": "AES-256-CBC",
        "key_size_bits": 256,
        "protocol": "S/MIME",
        "purpose": "Encrypt PCI compliance reports and audit findings",
        "data_type": "PCI-DSS compliance documentation",
        "data_classification": "Confidential - Compliance",
        "data_lifetime_years": 3,
        "harvest_now_risk": "MEDIUM - Compliance reports may reveal security architecture",
        "quantum_vulnerable_components": ["RSA-2048 key transport", "RSA-2048 signature"],
        "quantum_safe_components": ["AES-256-CBC"],
        "pci_dss_requirements": ["4.2.2", "12.3.3"],
        "migration_target": "ML-KEM-768 for key exchange + ML-DSA-65 for signing",
        "migration_approach": "Depends on email client and CA support for PQC S/MIME",
        "owner": "IT Operations / Compliance Team",
        "vendor": "Microsoft",
        "vendor_pqc_support": "Microsoft tracking PQC; S/MIME PQC timeline TBD",
        "hsm_dependency": False,
        "hsm_pqc_ready": "N/A",
        "priority_score": None,
        "estimated_effort_days": 5,
        "test_gate": "PQC-encrypted email sent and received between test accounts",
        "rollback_plan": "Revert to RSA-based S/MIME certificates"
    },
    {
        "asset_id": "CRYPTO-010",
        "system_name": "Audit Log Integrity",
        "component": "SIEM log signing (Splunk / Wazuh)",
        "location": "Monitoring Zone - siem-01.prod",
        "algorithm": "HMAC-SHA256 for log integrity",
        "key_exchange": "N/A (pre-shared HMAC key)",
        "authentication": "HMAC-SHA256",
        "encryption": "N/A (logs encrypted by storage layer)",
        "key_size_bits": 256,
        "protocol": "HMAC",
        "purpose": "Ensure integrity of security audit logs",
        "data_type": "Security events, access logs, transaction logs",
        "data_classification": "PCI-DSS Audit Records",
        "data_lifetime_years": 1,
        "harvest_now_risk": "LOW - HMAC-SHA256 is symmetric and quantum-resistant",
        "quantum_vulnerable_components": [],
        "quantum_safe_components": ["HMAC-SHA256"],
        "pci_dss_requirements": ["10.3", "10.5", "12.3.3"],
        "migration_target": "No migration needed - already quantum-safe",
        "migration_approach": "Document quantum safety; consider upgrade to HMAC-SHA384",
        "owner": "Security Operations Team",
        "vendor": "Splunk / Wazuh",
        "vendor_pqc_support": "N/A - already quantum-safe",
        "hsm_dependency": False,
        "hsm_pqc_ready": "N/A",
        "priority_score": None,
        "estimated_effort_days": 1,
        "test_gate": "Document current HMAC-SHA256 use as quantum-safe; no action needed",
        "rollback_plan": "N/A"
    }
]


# =============================================================================
# PRIORITY SCORING
# =============================================================================

def calculate_priority_score(asset):
    """
    Calculate migration priority score (0-100) based on:
    - Data lifetime (longer = higher risk)
    - Quantum vulnerability count (more = higher risk)
    - Business criticality (cardholder data = highest)
    - Harvest-now risk level
    """
    score = 0

    # Factor 1: Data Lifetime (0-25 points)
    lifetime = asset["data_lifetime_years"]
    if lifetime >= 10:
        score += 25
    elif lifetime >= 5:
        score += 20
    elif lifetime >= 1:
        score += 15
    elif lifetime >= 0.1:
        score += 10
    else:
        score += 5

    # Factor 2: Quantum Vulnerability Count (0-25 points)
    vuln_count = len(asset["quantum_vulnerable_components"])
    score += min(vuln_count * 12, 25)

    # Factor 3: Business Criticality (0-25 points)
    criticality_scores = {
        "PCI-DSS Cardholder Data": 25,
        "PCI-DSS Cardholder Data + Sensitive Authentication Data": 25,
        "Critical Infrastructure": 25,
        "PCI-DSS Cardholder Data Environment": 20,
        "Authentication / Authorization": 20,
        "Software Supply Chain Security": 20,
        "Confidential - Compliance": 15,
        "PCI-DSS Audit Records": 10
    }
    score += criticality_scores.get(asset["data_classification"], 10)

    # Factor 4: Harvest-Now Risk (0-25 points)
    risk = asset["harvest_now_risk"].split(" - ")[0].strip()
    risk_scores = {"CRITICAL": 25, "HIGH": 20, "MEDIUM": 15, "LOW": 5}
    score += risk_scores.get(risk, 10)

    return score


def assign_priority_tier(score):
    """Assign migration priority tier based on score."""
    if score >= 80:
        return "P1 - CRITICAL (migrate within 90 days)"
    elif score >= 60:
        return "P2 - HIGH (migrate within 180 days)"
    elif score >= 40:
        return "P3 - MEDIUM (migrate within 365 days)"
    else:
        return "P4 - LOW (monitor and plan)"


# =============================================================================
# REPORT GENERATION
# =============================================================================

def generate_inventory_report():
    """Generate the complete cryptographic inventory report."""

    print("=" * 70)
    print("LAB 4: CRYPTOGRAPHIC ASSET INVENTORY")
    print("PCI-DSS 12.3.3 + NIST PQC Migration")
    print("=" * 70)

    # Calculate priority scores
    for asset in CRYPTO_INVENTORY:
        asset["priority_score"] = calculate_priority_score(asset)
        asset["priority_tier"] = assign_priority_tier(asset["priority_score"])

    # Sort by priority score (highest first)
    sorted_assets = sorted(
        CRYPTO_INVENTORY,
        key=lambda x: x["priority_score"],
        reverse=True
    )

    # Print summary
    print(f"\nTotal assets inventoried: {len(sorted_assets)}")
    print(f"\n--- PRIORITY SUMMARY ---\n")

    for asset in sorted_assets:
        vuln_str = ", ".join(asset["quantum_vulnerable_components"]) or "None"
        print(f"  [{asset['priority_tier'].split(' ')[0]}] "
              f"{asset['asset_id']} {asset['system_name']:<40} "
              f"Score: {asset['priority_score']:>3} | "
              f"Vulnerable: {vuln_str}")

    # Quantum risk distribution
    print(f"\n--- QUANTUM RISK DISTRIBUTION ---\n")
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for asset in CRYPTO_INVENTORY:
        risk_level = asset["harvest_now_risk"].split(" - ")[0].strip()
        risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1

    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = risk_counts.get(level, 0)
        bar = "#" * (count * 5)
        print(f"  {level:10s}: {count} assets {bar}")

    # PCI-DSS requirement coverage
    print(f"\n--- PCI-DSS REQUIREMENT COVERAGE ---\n")
    req_coverage = {}
    for asset in CRYPTO_INVENTORY:
        for req in asset["pci_dss_requirements"]:
            if req not in req_coverage:
                req_coverage[req] = []
            req_coverage[req].append(asset["asset_id"])

    for req in sorted(req_coverage.keys()):
        assets = req_coverage[req]
        print(f"  Requirement {req}: {', '.join(assets)}")

    # Detailed asset report
    print(f"\n--- DETAILED ASSET INVENTORY ---\n")
    for asset in sorted_assets:
        print(f"  {'=' * 60}")
        print(f"  Asset ID:          {asset['asset_id']}")
        print(f"  System:            {asset['system_name']}")
        print(f"  Component:         {asset['component']}")
        print(f"  Algorithm:         {asset['algorithm']}")
        print(f"  Data Type:         {asset['data_type']}")
        print(f"  Data Lifetime:     {asset['data_lifetime_years']} years")
        print(f"  Harvest-Now Risk:  {asset['harvest_now_risk']}")
        print(f"  Quantum Vulnerable:{', '.join(asset['quantum_vulnerable_components']) or 'None'}")
        print(f"  Quantum Safe:      {', '.join(asset['quantum_safe_components']) or 'None'}")
        print(f"  Migration Target:  {asset['migration_target']}")
        print(f"  PCI-DSS Reqs:      {', '.join(asset['pci_dss_requirements'])}")
        print(f"  Priority Score:    {asset['priority_score']}/100")
        print(f"  Priority Tier:     {asset['priority_tier']}")
        print(f"  Effort:            {asset['estimated_effort_days']} days")
        print(f"  Owner:             {asset['owner']}")
        print(f"  Test Gate:         {asset['test_gate']}")
        print(f"  Rollback:          {asset['rollback_plan']}")
        print()

    return sorted_assets


def export_inventory_evidence(sorted_assets):
    """Export inventory as auditable evidence."""

    evidence = {
        "report_type": "Cryptographic Asset Inventory",
        "compliance_standards": [
            "PCI-DSS v4.0 Requirement 12.3.3",
            "NIST PQC Migration"
        ],
        "generated": datetime.now().isoformat(),
        "total_assets": len(sorted_assets),
        "quantum_vulnerable_assets": sum(
            1 for a in sorted_assets if len(a["quantum_vulnerable_components"]) > 0
        ),
        "quantum_safe_assets": sum(
            1 for a in sorted_assets if len(a["quantum_vulnerable_components"]) == 0
        ),
        "priority_distribution": {
            "P1_CRITICAL": sum(1 for a in sorted_assets if a["priority_score"] >= 80),
            "P2_HIGH": sum(1 for a in sorted_assets if 60 <= a["priority_score"] < 80),
            "P3_MEDIUM": sum(1 for a in sorted_assets if 40 <= a["priority_score"] < 60),
            "P4_LOW": sum(1 for a in sorted_assets if a["priority_score"] < 40),
        },
        "total_migration_effort_days": sum(
            a["estimated_effort_days"] for a in sorted_assets
            if len(a["quantum_vulnerable_components"]) > 0
        ),
        "assets": sorted_assets
    }

    # JSON export
    json_path = EVIDENCE_DIR / "lab4_crypto_inventory.json"
    with open(json_path, "w") as f:
        json.dump(evidence, f, indent=2, default=str)

    # CSV export
    csv_path = EVIDENCE_DIR / "lab4_crypto_inventory.csv"
    csv_fields = [
        "asset_id", "system_name", "algorithm", "key_exchange",
        "data_type", "data_lifetime_years", "harvest_now_risk",
        "migration_target", "priority_score", "priority_tier",
        "estimated_effort_days", "owner", "test_gate"
    ]
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=csv_fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(sorted_assets)

    print(f"\nEvidence exported:")
    print(f"  JSON: {json_path}")
    print(f"  CSV:  {csv_path}")


# =============================================================================
# MAIN
# =============================================================================

def main():
    sorted_assets = generate_inventory_report()
    export_inventory_evidence(sorted_assets)
    print("\n" + "=" * 70)
    print("LAB 4 COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()