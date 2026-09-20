"""Unit tests for Lab 5 BB84 simulation."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from labs.lab5_bb84_simulation import BB84Simulator


def test_bb84_no_eve_low_qber():
    sim = BB84Simulator(num_qubits=2000, eve_present=False, channel_error_rate=0.0)
    result = sim.run_protocol()
    assert result["qber"] < 0.05
    assert result["eavesdropper_detected"] is False


def test_bb84_eve_detected():
    sim = BB84Simulator(num_qubits=4000, eve_present=True, channel_error_rate=0.0)
    result = sim.run_protocol()
    # Intercept-resend attack should produce ~25% QBER
    assert result["qber"] > 0.10


def test_bb84_sifting_efficiency():
    sim = BB84Simulator(num_qubits=10000, eve_present=False, channel_error_rate=0.0)
    result = sim.run_protocol()
    # Sifting should produce roughly 50% efficiency
    assert 0.40 < result["sifting_efficiency"] < 0.60


def test_bb84_key_produced_without_eve():
    sim = BB84Simulator(num_qubits=1000, eve_present=False, channel_error_rate=0.0)
    result = sim.run_protocol()
    assert result["final_key_length_bits"] > 0
    assert result["final_key_preview"] != "ABORTED"