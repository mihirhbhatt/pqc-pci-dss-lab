"""Unit tests for Lab 1 — no PQC library required."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from labs.lab1_standards_mapping import (
    get_nist_standards,
    get_pcidss_requirements,
    build_alignments,
    build_algorithm_decisions
)


def test_nist_standards_complete():
    standards = get_nist_standards()
    assert "FIPS_203" in standards
    assert "FIPS_204" in standards
    assert "FIPS_205" in standards
    assert standards["FIPS_203"]["name"] == "ML-KEM"
    assert standards["FIPS_204"]["name"] == "ML-DSA"
    assert standards["FIPS_205"]["name"] == "SLH-DSA"


def test_pcidss_requirements_complete():
    reqs = get_pcidss_requirements()
    required = ["2.2.7", "3.5.1", "3.6.1", "3.7.1", "4.2.1", "4.2.2", "12.3.3", "12.3.4"]
    for req in required:
        assert req in reqs, f"Missing PCI-DSS requirement {req}"


def test_alignments_cover_critical_requirements():
    alignments = build_alignments()
    pci_reqs = {a["pci_req"] for a in alignments}
    assert "4.2.1" in pci_reqs, "Missing critical requirement 4.2.1"
    assert "12.3.3" in pci_reqs, "Missing critical requirement 12.3.3"
    assert "3.5.1" in pci_reqs, "Missing requirement 3.5.1"


def test_algorithm_decisions_have_required_fields():
    decisions = build_algorithm_decisions()
    assert len(decisions) >= 5
    for d in decisions:
        assert "use_case" in d
        assert "current" in d
        assert "recommended" in d
        assert "nist" in d
        assert "pci_req" in d
        assert "priority" in d


def test_every_alignment_has_priority():
    alignments = build_alignments()
    for a in alignments:
        assert a["migration_priority"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]