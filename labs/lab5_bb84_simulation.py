#!/usr/bin/env python3
"""
Lab 5: BB84 Quantum Key Distribution Simulation

Simulates the BB84 QKD protocol between Alice and Bob with optional
intercept-resend attacker (Eve). Measures Quantum Bit Error Rate (QBER)
and demonstrates eavesdropper detection.

Includes honest analysis of QKD limitations for PCI-DSS environments.

No PQC library required — uses only numpy for random number generation.
"""

import json
import os
import numpy as np
from datetime import datetime
from pathlib import Path

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "evidence"))
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

np.random.seed(42)  # Reproducible results for lab


class BB84Simulator:
    """
    Simulates the BB84 QKD protocol.

    Protocol steps:
    1. Alice generates random bits and random bases (rectilinear + or diagonal x)
    2. Alice encodes qubits and sends to Bob (Eve may intercept)
    3. Bob measures in random bases
    4. Alice and Bob compare bases over authenticated classical channel (sifting)
    5. They sample a subset to estimate QBER
    6. If QBER < threshold, they produce a shared key
    """

    def __init__(self, num_qubits=1000, eve_present=False, channel_error_rate=0.0,
                 attacker_variant="intercept_resend"):
        self.num_qubits = num_qubits
        self.eve_present = eve_present
        self.channel_error_rate = channel_error_rate
        self.attacker_variant = attacker_variant

    def run_protocol(self):
        """Execute the full BB84 protocol and return results."""

        print(f"\n{'=' * 60}")
        print(f"BB84 Simulation | Qubits: {self.num_qubits} | "
              f"Eve: {'YES' if self.eve_present else 'NO'} | "
              f"Channel Error: {self.channel_error_rate * 100:.1f}%")
        print(f"{'=' * 60}")

        # Step 1: Alice prepares qubits
        alice_bits = np.random.randint(0, 2, self.num_qubits)
        alice_bases = np.random.randint(0, 2, self.num_qubits)
        # Basis 0 = Rectilinear (+): |0>, |1>
        # Basis 1 = Diagonal (x): |+>, |->

        print(f"\n[Step 1] Alice prepares {self.num_qubits} qubits")
        print(f"  Bases: {np.sum(alice_bases == 0)} rectilinear, "
              f"{np.sum(alice_bases == 1)} diagonal")

        # Step 2: Transmission (with optional Eve)
        transmitted_bits = alice_bits.copy()
        eve_bases = None
        transmission_available = True

        if self.eve_present:
            print(f"\n[Step 2] Eve attack: {self.attacker_variant}")
            if self.attacker_variant == "intercept_only":
                transmission_available = False
                print("  Eve intercepts the signal and does not resend it")
            elif self.attacker_variant == "correct_basis_resend":
                # Educational idealization: Eve is given Alice's basis.
                eve_bases = alice_bases.copy()
                print("  Eve measures and resends using Alice's disclosed basis")
            elif self.attacker_variant in {"intercept_resend", "partial_intercept"}:
                eve_bases = np.random.randint(0, 2, self.num_qubits)
                if self.attacker_variant == "partial_intercept":
                    intercepted = np.random.random(self.num_qubits) < 0.5
                    eve_bases[~intercepted] = alice_bases[~intercepted]
                    print("  Eve intercepts approximately half of the qubits")
                else:
                    print("  Eve intercepts all qubits and resends")
            else:
                raise ValueError(f"Unknown attacker variant: {self.attacker_variant}")

            if not transmission_available:
                eve_bases = np.zeros(self.num_qubits, dtype=int)
            eve_bits = np.zeros(self.num_qubits, dtype=int)

            for i in range(self.num_qubits):
                if not transmission_available:
                    continue
                if eve_bases[i] == alice_bases[i]:
                    eve_bits[i] = alice_bits[i]  # Correct basis
                else:
                    eve_bits[i] = np.random.randint(0, 2)  # Wrong basis = random

                transmitted_bits[i] = eve_bits[i]  # Eve re-sends

            if transmission_available:
                eve_correct = np.sum(eve_bits == alice_bits)
                print(f"  Eve learned {eve_correct}/{self.num_qubits} bits correctly "
                    f"({eve_correct / self.num_qubits * 100:.1f}%)")
        else:
            print(f"\n[Step 2] Direct transmission (no eavesdropper)")

        # Step 3: Bob measures
        bob_bases = np.random.randint(0, 2, self.num_qubits)
        bob_bits = np.zeros(self.num_qubits, dtype=int)

        for i in range(self.num_qubits):
            if not transmission_available:
                bob_bits[i] = np.random.randint(0, 2)
            elif self.eve_present:
                if bob_bases[i] == eve_bases[i]:
                    bob_bits[i] = transmitted_bits[i]
                else:
                    bob_bits[i] = np.random.randint(0, 2)
            else:
                if bob_bases[i] == alice_bases[i]:
                    bob_bits[i] = alice_bits[i]
                else:
                    bob_bits[i] = np.random.randint(0, 2)

            # Channel noise
            if np.random.random() < self.channel_error_rate:
                bob_bits[i] = 1 - bob_bits[i]

        print(f"\n[Step 3] Bob measures {self.num_qubits} qubits")
        print(f"  Bases: {np.sum(bob_bases == 0)} rectilinear, "
              f"{np.sum(bob_bases == 1)} diagonal")

        # Step 4: Sifting
        matching_bases = alice_bases == bob_bases
        sifted_indices = np.where(matching_bases)[0]
        alice_sifted = alice_bits[sifted_indices]
        bob_sifted = bob_bits[sifted_indices]

        print(f"\n[Step 4] Sifting: {len(sifted_indices)}/{self.num_qubits} "
              f"bases match ({len(sifted_indices) / self.num_qubits * 100:.1f}%)")

        # Step 5: QBER estimation
        sample_size = min(len(sifted_indices) // 4, 200)
        if sample_size > 0:
            sample_indices = np.random.choice(len(sifted_indices), sample_size, replace=False)
            errors = int(np.sum(alice_sifted[sample_indices] != bob_sifted[sample_indices]))
            qber = errors / sample_size
        else:
            errors = 0
            qber = 0.0

        QBER_THRESHOLD = 0.11  # Standard BB84 security threshold

        if not transmission_available:
            assessment = "ABORT - No key formed (intercepted signal not resent)"
        elif qber < 0.05:
            assessment = "SAFE - QBER below warning threshold"
        elif qber < QBER_THRESHOLD:
            assessment = "WARNING - Elevated QBER"
        else:
            assessment = "ABORT - Eavesdropper detected"

        print(f"\n[Step 5] QBER Estimation")
        print(f"  Sample: {sample_size} bits | Errors: {errors} | "
              f"QBER: {qber * 100:.2f}%")
        print(f"  Threshold: {QBER_THRESHOLD * 100:.0f}% | "
              f"Assessment: {assessment}")

        # Step 6: Final key
        eve_detected = qber > QBER_THRESHOLD or not transmission_available

        if eve_detected:
            print(f"\n[Step 6] PROTOCOL ABORTED - Eavesdropper detected")
            final_key_length = 0
            final_key = "ABORTED"
        else:
            remaining = np.delete(np.arange(len(sifted_indices)), sample_indices)
            final_key_length = len(remaining)
            key_bits = alice_sifted[remaining]

            if final_key_length >= 8:
                key_bytes = np.packbits(key_bits[:final_key_length - (final_key_length % 8)])
                final_key = key_bytes.tobytes().hex()[:32]
            else:
                final_key = "".join(str(b) for b in key_bits)

            print(f"\n[Step 6] Final Key: {final_key_length} bits")
            print(f"  Preview: {final_key}")

        return {
            "num_qubits_sent": int(self.num_qubits),
            "eve_present": self.eve_present,
            "channel_error_rate": self.channel_error_rate,
            "sifted_key_length": int(len(sifted_indices)),
            "sifting_efficiency": round(len(sifted_indices) / self.num_qubits, 4),
            "qber_sample_size": int(sample_size),
            "qber_errors": int(errors),
            "qber": round(float(qber), 6),
            "qber_threshold": QBER_THRESHOLD,
            "qber_assessment": assessment,
            "eavesdropper_detected": bool(eve_detected),
            "final_key_length_bits": int(final_key_length),
            "final_key_preview": final_key,
            "attacker_variant": self.attacker_variant if self.eve_present else "none",
            "protocol_response": assessment
        }


def run_experiments():
    """Run multiple BB84 experiments."""

    experiments = [
        {"num_qubits": 1000, "eve_present": False, "channel_error_rate": 0.0,
         "description": "Ideal channel, no eavesdropper"},
        {"num_qubits": 1000, "eve_present": True, "channel_error_rate": 0.0,
         "attacker_variant": "intercept_resend",
         "description": "Ideal channel, intercept-resend attacker"},
        {"num_qubits": 1000, "eve_present": True, "channel_error_rate": 0.0,
         "attacker_variant": "correct_basis_resend",
         "description": "Idealized correct-basis resend (privileged attacker)"},
        {"num_qubits": 1000, "eve_present": True, "channel_error_rate": 0.0,
         "attacker_variant": "intercept_only",
         "description": "Intercept-only attacker, no resend"},
        {"num_qubits": 1000, "eve_present": True, "channel_error_rate": 0.0,
         "attacker_variant": "partial_intercept",
         "description": "Custom variant: partial intercept"},
        {"num_qubits": 1000, "eve_present": False, "channel_error_rate": 0.03,
         "description": "Noisy channel (3%), no eavesdropper"},
        {"num_qubits": 1000, "eve_present": True, "channel_error_rate": 0.03,
         "description": "Noisy channel (3%), intercept-resend attacker"},
        {"num_qubits": 4000, "eve_present": True, "channel_error_rate": 0.0,
         "description": "Large sample, intercept-resend (better QBER estimate)"},
    ]

    all_results = []

    for i, exp in enumerate(experiments):
        print(f"\n{'#' * 60}")
        print(f"EXPERIMENT {i + 1}: {exp['description']}")
        print(f"{'#' * 60}")

        sim = BB84Simulator(
            num_qubits=exp["num_qubits"],
            eve_present=exp["eve_present"],
            channel_error_rate=exp["channel_error_rate"],
            attacker_variant=exp.get("attacker_variant", "intercept_resend")
        )
        result = sim.run_protocol()
        result["experiment_id"] = i + 1
        result["description"] = exp["description"]
        all_results.append(result)

    return all_results


def qkd_vs_pqc_analysis():
    """Honest analysis of QKD vs PQC for PCI-DSS environments."""

    print(f"\n{'=' * 70}")
    print("QKD vs PQC ANALYSIS FOR PCI-DSS ENVIRONMENTS")
    print(f"{'=' * 70}")

    analysis = {
        "qkd_advantages": [
            "Information-theoretic security based on physics",
            "Detects eavesdropping in real-time via QBER",
            "No vulnerability to future mathematical breakthroughs"
        ],
        "qkd_limitations_for_pci_dss": [
            "AUTHENTICATION REQUIRED: BB84 does not authenticate peers. "
            "An authenticated classical channel is needed, which requires "
            "digital signatures. If using PQC signatures for auth, you "
            "already need PQC.",
            "POINT-TO-POINT ONLY: PCI-DSS environments have hundreds of "
            "endpoints (web, API, POS, mobile, cloud). QKD cannot scale "
            "to distributed architectures.",
            "TRUSTED NODES: Long-distance QKD requires trusted relay nodes "
            "where keys exist in plaintext.",
            "HARDWARE COST: $100K-$1M+ per link. Not feasible for 500+ POS terminals.",
            "DISTANCE LIMITS: ~100-300 km over fiber without trusted relays.",
            "KEY RATE: Much lower than computational key generation.",
            "SIDE CHANNELS: Real implementations vulnerable to blinding "
            "and Trojan horse attacks.",
            "NO SIGNATURES: QKD only establishes symmetric keys. It cannot "
            "provide certificates, code signing, or non-repudiation."
        ],
        "pqc_advantages": [
            "Software-only deployment on existing infrastructure",
            "Supports key exchange AND digital signatures",
            "Scales to any number of endpoints",
            "Standardized by NIST with broad industry support",
            "Compatible with TLS, PKI, VPN, and application architectures",
            "No specialized hardware required"
        ],
        "recommendation": (
            "For PCI-DSS compliance, PQC (FIPS 203/204/205) is the primary "
            "migration path. QKD may complement PQC for specific high-value "
            "point-to-point links but does not replace PQC."
        )
    }

    print("\n--- QKD Advantages ---")
    for a in analysis["qkd_advantages"]:
        print(f"  + {a}")

    print("\n--- QKD Limitations for PCI-DSS ---")
    for lim in analysis["qkd_limitations_for_pci_dss"]:
        print(f"  - {lim}")
        print()

    print("\n--- PQC Advantages ---")
    for a in analysis["pqc_advantages"]:
        print(f"  + {a}")

    print(f"\n--- RECOMMENDATION ---")
    print(f"  {analysis['recommendation']}")

    return analysis


# =============================================================================
# MAIN
# =============================================================================

def main():
    print("=" * 70)
    print("LAB 5: BB84 QKD SIMULATION + PCI-DSS SUITABILITY ANALYSIS")
    print("=" * 70)

    experiment_results = run_experiments()
    analysis = qkd_vs_pqc_analysis()

    # Summary table
    print(f"\n{'=' * 70}")
    print("EXPERIMENT SUMMARY")
    print(f"{'=' * 70}")
    print(f"\n{'#':>3} {'Description':<45} {'QBER':>7} {'Eve':>5} {'Detected':>9}")
    print("-" * 72)
    for r in experiment_results:
        eve_str = "Yes" if r["eve_present"] else "No"
        det_str = "YES" if r["eavesdropper_detected"] else "no"
        print(f"{r['experiment_id']:>3} {r['description']:<45} "
              f"{r['qber'] * 100:>6.2f}% {eve_str:>5} {det_str:>9}")

    # Export evidence
    evidence = {
        "lab": "Lab 5: BB84 QKD Simulation",
        "generated": datetime.now().isoformat(),
        "experiments": experiment_results,
        "qkd_pci_dss_analysis": analysis,
        "conclusion": (
            "BB84 detects intercept-resend eavesdropping via elevated QBER. "
            "However, QKD requires authenticated classical channels, specialized "
            "hardware, and does not provide digital signatures. For PCI-DSS "
            "compliance, PQC (FIPS 203/204/205) is the primary migration path."
        )
    }

    path = EVIDENCE_DIR / "lab5_bb84_evidence.json"
    with open(path, "w") as f:
        json.dump(evidence, f, indent=2, default=str)

    print(f"\nEvidence exported to: {path}")
    print("\n" + "=" * 70)
    print("LAB 5 COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()