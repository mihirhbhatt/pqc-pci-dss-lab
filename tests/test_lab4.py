"""Unit tests for Lab 4 crypto inventory."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from labs.lab4_crypto_inventory import (
    CRYPTO_INVENTORY,
    calculate_priority_score,
    assign_priority_tier
)


def test_inventory_has_minimum_assets():
    assert len(CRYPTO_INVENTORY) >= 10


def test_every_asset_has_required_fields():
    required = [
        "asset_id", "system_name", "algorithm", "data_type",
        "quantum_vulnerable_components", "migration_target",
        "owner", "test_gate", "rollback_plan",
        "pci_dss_requirements"
    ]
    for asset in CRYPTO_INVENTORY:
        for field in required:
            assert field in asset, f"{asset['asset_id']} missing {field}"


def test_priority_scoring():
    test_asset = CRYPTO_INVENTORY[0]
    score = calculate_priority_score(test_asset)
    assert 0 <= score <= 100
    tier = assign_priority_tier(score)
    assert "P1" in tier or "P2" in tier or "P3" in tier or "P4" in tier


def test_pcidss_coverage():
    all_reqs = set()
    for asset in CRYPTO_INVENTORY:
        for req in asset["pci_dss_requirements"]:
            all_reqs.add(req)
    assert "4.2.1" in all_reqs
    assert "3.5.1" in all_reqs
    assert "12.3.3" in all_reqs