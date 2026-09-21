#!/usr/bin/env python3
"""
Lab 6: QKD Attack Detection and Response

Uses QBER, sample availability, and a configured channel baseline to classify
QKD observations. The simulation is educational evidence, not a substitute
for authenticated QKD equipment telemetry or a physical side-channel test.
"""

import json
import os
from datetime import datetime
from pathlib import Path

import numpy as np

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "evidence"))
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def detect_attack(qber, sample_size, sifted_key_length,
                  expected_channel_error_rate=0.01, qber_threshold=0.11,
                  minimum_sample_size=30):
    """Classify a QKD observation and return the required protocol response."""
    if not 0 <= qber <= 1:
        raise ValueError("qber must be between 0 and 1")
    if sample_size < 0 or sifted_key_length < 0:
        raise ValueError("sample_size and sifted_key_length must be non-negative")
    if not 0 <= expected_channel_error_rate <= 1:
        raise ValueError("expected_channel_error_rate must be between 0 and 1")

    if sifted_key_length == 0:
        classification = "AVAILABILITY_ATTACK_SUSPECTED"
        response = "ABORT_AND_ALERT"
        reason = "No sifted key material was available for authenticated sampling"
    elif sample_size < minimum_sample_size:
        classification = "INSUFFICIENT_DATA"
        response = "HOLD_KEY_AND_RESAMPLE"
        reason = f"QBER sample has fewer than {minimum_sample_size} bits"
    elif qber >= qber_threshold:
        classification = "EAVESDROPPER_ATTACK_SUSPECTED"
        response = "ABORT_AND_ALERT"
        reason = "QBER exceeds the BB84 abort threshold"
    elif qber > expected_channel_error_rate + 0.05:
        classification = "CHANNEL_ANOMALY"
        response = "HOLD_KEY_AND_RECHECK_CHANNEL"
        reason = "QBER is elevated above the measured channel baseline"
    else:
        classification = "NO_ATTACK_INDICATOR"
        response = "PROCEED_WITH_POST_PROCESSING"
        reason = "QBER is consistent with the configured channel baseline"

    return {
        "classification": classification,
        "response": response,
        "reason": reason,
        "qber": round(float(qber), 6),
        "sample_size": int(sample_size),
        "sifted_key_length": int(sifted_key_length),
        "qber_threshold": qber_threshold,
        "expected_channel_error_rate": expected_channel_error_rate
    }


def run_detection_trials(seed=7, sample_size=400, expected_channel_error_rate=0.01):
    """Run repeatable observations for normal, noisy, and attacked channels."""
    rng = np.random.default_rng(seed)
    scenarios = [
        {"name": "normal_channel", "error_rate": expected_channel_error_rate,
         "sifted_key_length": 800, "expected_classification": "NO_ATTACK_INDICATOR"},
        {"name": "intercept_resend", "error_rate": 0.25,
         "sifted_key_length": 800, "expected_classification": "EAVESDROPPER_ATTACK_SUSPECTED"},
        {"name": "channel_noise", "error_rate": 0.08,
         "sifted_key_length": 800, "expected_classification": "CHANNEL_ANOMALY"},
        {"name": "denial_of_service", "error_rate": 0.0,
         "sifted_key_length": 0, "expected_classification": "AVAILABILITY_ATTACK_SUSPECTED"}
    ]

    results = []
    for scenario in scenarios:
        observed_sample_size = sample_size if scenario["sifted_key_length"] else 0
        errors = rng.binomial(observed_sample_size, scenario["error_rate"])
        qber = errors / observed_sample_size if observed_sample_size else 0.0
        assessment = detect_attack(
            qber=qber,
            sample_size=observed_sample_size,
            sifted_key_length=scenario["sifted_key_length"],
            expected_channel_error_rate=expected_channel_error_rate
        )
        results.append({
            "scenario": scenario["name"],
            "simulated_error_rate": scenario["error_rate"],
            "observed_errors": int(errors),
            "expected_classification": scenario["expected_classification"],
            **assessment
        })
    return results


def main():
    results = run_detection_trials()
    evidence = {
        "lab": "Lab 6: QKD Attack Detection and Response",
        "generated": datetime.now().isoformat(),
        "detection_policy": {
            "qber_abort_threshold": 0.11,
            "channel_anomaly_margin": 0.05,
            "minimum_qber_sample_size": 30,
            "responses": {
                "eavesdropper": "Abort key generation and alert",
                "availability_attack": "Abort key generation and alert",
                "channel_anomaly": "Hold key and recheck channel",
                "insufficient_data": "Hold key and resample"
            }
        },
        "trials": results,
        "conclusion": (
            "QBER is a detection signal, not proof of attacker identity. "
            "Operational QKD must combine authenticated classical messages, "
            "availability monitoring, calibrated baselines, and physical "
            "device protections."
        )
    }
    path = EVIDENCE_DIR / "lab6_qkd_attack_detection.json"
    with open(path, "w") as evidence_file:
        json.dump(evidence, evidence_file, indent=2)

    print("LAB 6: QKD ATTACK DETECTION")
    for result in results:
        print(f"{result['scenario']}: {result['classification']} -> {result['response']}")
    print(f"Evidence exported to: {path}")


if __name__ == "__main__":
    main()