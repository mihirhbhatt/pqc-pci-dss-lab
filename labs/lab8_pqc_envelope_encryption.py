#!/usr/bin/env python3
"""
Lab 8: ML-KEM envelope encryption for long-lived payment data.

The envelope uses ML-KEM to establish a shared secret, HKDF-SHA256 to derive
an AES-256-GCM key-wrapping key, and AES-256-GCM to protect a random data
encryption key (DEK) and the payload. The liboqs adapter is optional so the
envelope format and its negative tests remain runnable without liboqs.
"""

import base64
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "evidence"))
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
ENVELOPE_VERSION = 1
KEM_NAME = "ML-KEM-768"


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


def derive_wrap_key(shared_secret: bytes, key_id: str) -> bytes:
    """Derive an independent AES-256 wrapping key from a KEM shared secret."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"pqc-pci-dss-lab:ml-kem:{key_id}".encode("ascii"),
    ).derive(shared_secret)


def _aad(key_id: str) -> bytes:
    return f"pqc-envelope-v{ENVELOPE_VERSION}:{key_id}".encode("ascii")


def _encrypt(key: bytes, plaintext: bytes, key_id: str) -> dict[str, str]:
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, _aad(key_id))
    return {"nonce": _encode(nonce), "ciphertext": _encode(ciphertext)}


def _decrypt(key: bytes, encrypted: dict[str, str], key_id: str) -> bytes:
    return AESGCM(key).decrypt(
        _decode(encrypted["nonce"]),
        _decode(encrypted["ciphertext"]),
        _aad(key_id),
    )


def seal_payload(
    plaintext: bytes, shared_secret: bytes, key_id: str = "primary"
) -> dict[str, Any]:
    """Create a versioned envelope from an established shared secret."""
    if not plaintext:
        raise ValueError("plaintext must not be empty")
    if not shared_secret:
        raise ValueError("shared_secret must not be empty")

    dek = AESGCM.generate_key(bit_length=256)
    wrapping_key = derive_wrap_key(shared_secret, key_id)
    return {
        "version": ENVELOPE_VERSION,
        "kem": KEM_NAME,
        "key_id": key_id,
        "wrapped_dek": _encrypt(wrapping_key, dek, key_id),
        "payload": _encrypt(dek, plaintext, key_id),
    }


def open_payload(envelope: dict[str, Any], shared_secret: bytes) -> bytes:
    """Open an envelope and let AES-GCM reject tampered metadata or data."""
    if envelope.get("version") != ENVELOPE_VERSION:
        raise ValueError("unsupported envelope version")
    if envelope.get("kem") != KEM_NAME:
        raise ValueError("unsupported KEM")

    key_id = envelope["key_id"]
    wrapping_key = derive_wrap_key(shared_secret, key_id)
    dek = _decrypt(wrapping_key, envelope["wrapped_dek"], key_id)
    return _decrypt(dek, envelope["payload"], key_id)


def rotate_payload(
    envelope: dict[str, Any],
    old_shared_secret: bytes,
    new_shared_secret: bytes,
    new_key_id: str,
) -> dict[str, Any]:
    """Decrypt with the old secret and re-encrypt with a new one."""
    plaintext = open_payload(envelope, old_shared_secret)
    return seal_payload(plaintext, new_shared_secret, new_key_id)


class OQSMLKEM768:
    """Small adapter around liboqs-python's ML-KEM-768 implementation."""

    def __init__(self) -> None:
        import oqs

        self._kem = oqs.KeyEncapsulation(KEM_NAME)
        self.public_key = self._kem.generate_keypair()

    def encapsulate(self) -> tuple[bytes, bytes]:
        return self._kem.encap_secret(self.public_key)

    def decapsulate(self, ciphertext: bytes) -> bytes:
        return self._kem.decap_secret(ciphertext)


def run_mlkem_demo() -> dict[str, Any]:
    """Run the real ML-KEM path when liboqs-python is installed."""
    try:
        receiver = OQSMLKEM768()
    except ImportError:
        return {"status": "SKIPPED", "reason": "liboqs-python not available"}

    ciphertext, shared_secret = receiver.encapsulate()
    envelope = seal_payload(b"PAN test value: 4111111111111111", shared_secret)
    opened = open_payload(envelope, receiver.decapsulate(ciphertext))
    return {
        "status": "PASS" if opened.startswith(b"PAN test value") else "FAIL",
        "kem": KEM_NAME,
        "ciphertext_bytes": len(ciphertext),
        "envelope_bytes": len(json.dumps(envelope)),
        "round_trip": opened.decode("ascii"),
    }


def main() -> None:
    result = run_mlkem_demo()
    evidence = {
        "lab": "Lab 8: ML-KEM Envelope Encryption",
        "generated": datetime.now(timezone.utc).isoformat(),
        "python_version": sys.version,
        "status": result["status"],
        "result": result,
        "design": {
            "kem": KEM_NAME,
            "kdf": "HKDF-SHA256",
            "data_encryption": "AES-256-GCM",
            "rotation": "decrypt with old secret, re-encrypt with new secret",
        },
    }
    evidence_path = EVIDENCE_DIR / "lab8_pqc_envelope_evidence.json"
    evidence_path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
