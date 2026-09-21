"""Unit tests for Lab 7 migration roadmap."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from labs.lab7_migration_roadmap import build_migration_roadmap


def test_roadmap_has_three_phases():
    roadmap = build_migration_roadmap()
    assert len(roadmap["phases"]) == 3


def test_every_milestone_has_owner():
    roadmap = build_migration_roadmap()
    for phase in roadmap["phases"]:
        for m in phase["milestones"]:
            assert "owner" in m and m["owner"], f"{m['milestone_id']} has no owner"


def test_every_milestone_has_acceptance_criteria():
    roadmap = build_migration_roadmap()
    for phase in roadmap["phases"]:
        for m in phase["milestones"]:
            assert len(m["acceptance_criteria"]) >= 2, \
                f"{m['milestone_id']} needs more acceptance criteria"


def test_roadmap_covers_90_days():
    roadmap = build_migration_roadmap()
    last_phase = roadmap["phases"][-1]
    assert last_phase["end_day"] == 90


def test_pilot_milestones_have_rollback():
    roadmap = build_migration_roadmap()
    phase3 = roadmap["phases"][2]  # Pilot phase
    rollback_milestones = [m for m in phase3["milestones"] if "rollback_trigger" in m]
    assert len(rollback_milestones) >= 1, "Pilot phase needs rollback triggers"


def test_roadmap_includes_policy_template_and_signoff_gate():
    roadmap = build_migration_roadmap()
    policy = roadmap["migration_policy_template"]
    assert policy["target_hybrid_group"] == "X25519MLKEM768"
    assert "external_scanner_evidence" in policy
    checklist_items = {item["item"] for item in roadmap["pqc_signoff_checklist"]}
    assert any("External scanner" in item for item in checklist_items)