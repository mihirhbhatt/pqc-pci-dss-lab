"""Unit tests for Lab 7 QKD attack detection."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from labs.lab7_qkd_attack_detection import detect_attack, run_detection_trials


def test_high_qber_triggers_abort_and_alert():
    result = detect_attack(qber=0.25, sample_size=400, sifted_key_length=800)
    assert result["classification"] == "EAVESDROPPER_ATTACK_SUSPECTED"
    assert result["response"] == "ABORT_AND_ALERT"


def test_channel_noise_is_not_mislabeled_as_eavesdropping():
    result = detect_attack(qber=0.08, sample_size=400, sifted_key_length=800)
    assert result["classification"] == "CHANNEL_ANOMALY"
    assert result["response"] == "HOLD_KEY_AND_RECHECK_CHANNEL"


def test_missing_sifted_key_detects_availability_attack():
    result = detect_attack(qber=0.0, sample_size=0, sifted_key_length=0)
    assert result["classification"] == "AVAILABILITY_ATTACK_SUSPECTED"
    assert result["response"] == "ABORT_AND_ALERT"


def test_detection_trials_cover_expected_attack_classes():
    results = run_detection_trials()
    classifications = {result["scenario"]: result["classification"] for result in results}
    assert classifications["normal_channel"] == "NO_ATTACK_INDICATOR"
    assert classifications["intercept_resend"] == "EAVESDROPPER_ATTACK_SUSPECTED"
    assert classifications["channel_noise"] == "CHANNEL_ANOMALY"
    assert classifications["denial_of_service"] == "AVAILABILITY_ATTACK_SUSPECTED"