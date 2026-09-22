"""Focused tests for the Lab 8 envelope format and key lifecycle."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from labs.lab8_pqc_envelope_encryption import (  # noqa: E402
    open_payload,
    rotate_payload,
    seal_payload,
)


def test_round_trip_with_shared_secret():
    secret = os.urandom(32)
    plaintext = b"PAN test value: 4111111111111111"

    envelope = seal_payload(plaintext, secret)

    assert open_payload(envelope, secret) == plaintext
    assert envelope["kem"] == "ML-KEM-768"
    assert envelope["version"] == 1


def test_tampered_payload_is_rejected():
    secret = os.urandom(32)
    envelope = seal_payload(b"sensitive payment data", secret)
    envelope["payload"]["ciphertext"] = (
        envelope["payload"]["ciphertext"][:-2] + "AA"
    )

    with pytest.raises(Exception):
        open_payload(envelope, secret)


def test_wrong_secret_is_rejected():
    envelope = seal_payload(b"sensitive payment data", os.urandom(32))

    with pytest.raises(Exception):
        open_payload(envelope, os.urandom(32))


def test_rotation_preserves_plaintext_and_changes_key_id():
    old_secret = os.urandom(32)
    new_secret = os.urandom(32)
    envelope = seal_payload(b"rotated payment data", old_secret, "key-2026-09")

    rotated = rotate_payload(envelope, old_secret, new_secret, "key-2026-10")

    assert open_payload(rotated, new_secret) == b"rotated payment data"
    assert rotated["key_id"] == "key-2026-10"
    with pytest.raises(Exception):
        open_payload(rotated, old_secret)
