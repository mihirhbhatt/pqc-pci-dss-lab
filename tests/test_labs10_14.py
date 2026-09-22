# flake8: noqa: E501
"""Focused policy tests for enterprise Labs 10 through 14."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from labs.lab10_vault_secret_policy import SECRET_POLICY, validate_secret_policy  # noqa: E402
from labs.lab11_vault_pki_issuance import CERTIFICATE_PROFILE, validate_certificate_profile  # noqa: E402
from labs.lab12_service_mesh_mtls import MESH_POLICY, validate_mesh_policy  # noqa: E402
from labs.lab13_iac_security_validation import IAC_PLAN, validate_iac_plan  # noqa: E402
from labs.lab14_network_policy_analysis import ALLOWED_EDGES, analyze_network_policy  # noqa: E402


def test_labs10_to_13_reference_policies_pass():
    assert validate_secret_policy(SECRET_POLICY) == []
    assert validate_certificate_profile(CERTIFICATE_PROFILE) == []
    assert validate_mesh_policy(MESH_POLICY) == []
    assert validate_iac_plan(IAC_PLAN) == []


def test_secret_policy_rejects_plaintext_logging():
    policy = dict(SECRET_POLICY, plaintext_logging=True)
    assert "plaintext secret logging must be disabled" in validate_secret_policy(policy)


def test_certificate_profile_rejects_long_lived_certificates():
    profile = dict(CERTIFICATE_PROFILE, max_ttl_hours=720)
    assert "certificate TTL must be between 1 and 168 hours" in validate_certificate_profile(profile)


def test_mesh_policy_rejects_permissive_mode():
    policy = dict(MESH_POLICY, mode="PERMISSIVE")
    assert "mesh mTLS mode must be STRICT" in validate_mesh_policy(policy)


def test_iac_policy_rejects_public_latest_resource():
    plan = dict(IAC_PLAN, resources=[{"name": "bad", "image": "repo:latest", "public": True, "encrypted_storage": False}])
    violations = validate_iac_plan(plan)
    assert "bad: image must be digest pinned" in violations
    assert "bad: public exposure is prohibited" in violations
    assert "bad: encrypted storage is required" in violations


def test_network_policy_is_default_deny():
    assert analyze_network_policy(ALLOWED_EDGES) == []
    assert analyze_network_policy([("payment-api", "database")]) == [("payment-api", "database")]
