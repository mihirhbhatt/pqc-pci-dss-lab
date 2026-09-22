# flake8: noqa: E501
"""Focused tests for enterprise Labs 15 through 18."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from labs.lab15_key_rotation import rotate_key_state, validate_rotation_state  # noqa: E402
from labs.lab16_configuration_drift import find_drift, snapshot_hash  # noqa: E402
from labs.lab17_zero_trust_policy import authorize  # noqa: E402
from labs.lab18_multi_region_failover import choose_failover_region  # noqa: E402


def test_rotation_requires_sequential_versions_and_overlap():
    state = rotate_key_state({"active_version": 1, "status": "ACTIVE"}, 2)
    assert validate_rotation_state(state) == []
    with pytest.raises(ValueError):
        rotate_key_state({"active_version": 1, "status": "ACTIVE"}, 3)


def test_drift_hash_is_stable_and_detects_changes():
    baseline = {"tls": "TLSv1.3", "fallback": False}
    assert snapshot_hash(baseline) == snapshot_hash(dict(reversed(list(baseline.items()))))
    assert find_drift(baseline, {"tls": "TLSv1.2", "fallback": False})["drift_detected"]


def test_zero_trust_defaults_to_deny():
    assert authorize("payment-api", "read", "pqc-key-service")
    assert not authorize("payment-api", "admin", "vault")


def test_failover_requires_healthy_quorum_and_low_lag():
    regions = [
        {"name": "primary", "healthy": False, "quorum": True, "replication_lag_seconds": 0},
        {"name": "secondary", "healthy": True, "quorum": True, "replication_lag_seconds": 10},
        {"name": "stale", "healthy": True, "quorum": True, "replication_lag_seconds": 100},
    ]
    assert choose_failover_region(regions) == "secondary"
    with pytest.raises(RuntimeError):
        choose_failover_region([regions[2]])
