#!/usr/bin/env python3
"""
Lab 2: ML-KEM and ML-DSA Algorithm Testing
Tests NIST FIPS 203/204/205 with evidence collection.
Requires liboqs-python.
"""

import hashlib
import time
import json
import sys
import os
from datetime import datetime
from pathlib import Path

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "evidence"))
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

test_results = []


def record(name, status, details):
    result = {
        "test_name": name,
        "status": status,
        "timestamp": datetime.now().isoformat(),
        "details": details
    }
    test_results.append(result)
    sym = "✓" if status == "PASS" else "✗" if status == "FAIL" else "ℹ"
    print(f"  [{sym}] {name}: {status}")


def find_algorithm(target_names, available_list):
    """Find a working algorithm name from available list."""
    for name in target_names:
        if name in available_list:
            return name
    return None


def test_kem(alg_display, alg_name, oqs_module):
    """Test a KEM algorithm."""
    print(f"\n--- Testing {alg_display} ---")

    # Key Generation
    try:
        kem = oqs_module.KeyEncapsulation(alg_name)
        t = time.perf_counter()
        pk = kem.generate_keypair()
        keygen_ms = (time.perf_counter() - t) * 1000

        record(f"{alg_display} KeyGen", "PASS", {
            "pk_bytes": kem.length_public_key,
            "sk_bytes": kem.length_secret_key,
            "ct_bytes": kem.length_ciphertext,
            "ss_bytes": kem.length_shared_secret,
            "time_ms": round(keygen_ms, 3)
        })
    except Exception as e:
        record(f"{alg_display} KeyGen", "FAIL", {"error": str(e)})
        return

    # Encapsulation
    try:
        t = time.perf_counter()
        ct, ss_enc = kem.encap_secret(pk)
        encap_ms = (time.perf_counter() - t) * 1000
        record(f"{alg_display} Encap", "PASS", {
            "ct_bytes": len(ct),
            "ss_bytes": len(ss_enc),
            "time_ms": round(encap_ms, 3)
        })
    except Exception as e:
        record(f"{alg_display} Encap", "FAIL", {"error": str(e)})
        return

    # Decapsulation
    try:
        t = time.perf_counter()
        ss_dec = kem.decap_secret(ct)
        decap_ms = (time.perf_counter() - t) * 1000
        match = (ss_enc == ss_dec)
        record(f"{alg_display} Decap", "PASS" if match else "FAIL", {
            "secrets_match": match,
            "time_ms": round(decap_ms, 3)
        })
    except Exception as e:
        record(f"{alg_display} Decap", "FAIL", {"error": str(e)})
        return

    # Negative test — corrupted ciphertext
    try:
        bad_ct = bytearray(ct)
        bad_ct[0] ^= 0xFF
        bad_ct = bytes(bad_ct)
        bad_ss = kem.decap_secret(bad_ct)
        rejected = (bad_ss != ss_enc)
        record(f"{alg_display} Corruption Rejection", "PASS" if rejected else "FAIL", {
            "implicit_rejection": rejected
        })
    except Exception:
        record(f"{alg_display} Corruption Rejection", "PASS", {
            "explicit_rejection": True
        })

    kem.free()


def test_sig(alg_display, alg_name, oqs_module):
    """Test a signature algorithm."""
    print(f"\n--- Testing {alg_display} ---")

    messages = {
        "tls_cert": b"CN=payment-gateway.example.com",
        "audit_log": b'{"event":"PAN_ACCESS","result":"PERMITTED"}',
        "code_sign": hashlib.sha256(b"payment-app-v3.2.1").digest()
    }

    try:
        sig = oqs_module.Signature(alg_name)
        t = time.perf_counter()
        pk = sig.generate_keypair()
        keygen_ms = (time.perf_counter() - t) * 1000

        record(f"{alg_display} KeyGen", "PASS", {
            "pk_bytes": sig.length_public_key,
            "sk_bytes": sig.length_secret_key,
            "max_sig_bytes": sig.length_signature,
            "time_ms": round(keygen_ms, 3)
        })
    except Exception as e:
        record(f"{alg_display} KeyGen", "FAIL", {"error": str(e)})
        return

    for msg_name, msg_data in messages.items():
        try:
            t = time.perf_counter()
            signature = sig.sign(msg_data)
            sign_ms = (time.perf_counter() - t) * 1000

            v = oqs_module.Signature(alg_name)
            t = time.perf_counter()
            valid = v.verify(msg_data, signature, pk)
            verify_ms = (time.perf_counter() - t) * 1000

            record(f"{alg_display} Sign/Verify ({msg_name})", "PASS" if valid else "FAIL", {
                "msg_bytes": len(msg_data),
                "sig_bytes": len(signature),
                "sign_ms": round(sign_ms, 3),
                "verify_ms": round(verify_ms, 3)
            })
            v.free()
        except Exception as e:
            record(f"{alg_display} Sign/Verify ({msg_name})", "FAIL", {"error": str(e)})

    # Negative test — tampered message
    try:
        signature = sig.sign(b"original message")
        v = oqs_module.Signature(alg_name)
        try:
            valid = v.verify(b"tampered message", signature, pk)
            record(f"{alg_display} Tamper Detection", "PASS" if not valid else "FAIL", {
                "tampered_rejected": not valid
            })
        except Exception:
            record(f"{alg_display} Tamper Detection", "PASS", {"rejected_via_exception": True})
        v.free()
    except Exception as e:
        record(f"{alg_display} Tamper Detection", "FAIL", {"error": str(e)})

    # Negative test — wrong key
    try:
        msg = b"test message for wrong key"
        signature = sig.sign(msg)

        wrong = oqs_module.Signature(alg_name)
        wrong_pk = wrong.generate_keypair()

        v = oqs_module.Signature(alg_name)
        try:
            valid = v.verify(msg, signature, wrong_pk)
            record(f"{alg_display} Wrong Key Rejection", "PASS" if not valid else "FAIL", {
                "wrong_key_rejected": not valid
            })
        except Exception:
            record(f"{alg_display} Wrong Key Rejection", "PASS", {"rejected_via_exception": True})

        wrong.free()
        v.free()
    except Exception as e:
        record(f"{alg_display} Wrong Key Rejection", "FAIL", {"error": str(e)})

    sig.free()


def main():
    print("=" * 70)
    print("LAB 2: ML-KEM + ML-DSA Algorithm Testing")
    print("=" * 70)

    try:
        import oqs
    except ImportError:
        print("ERROR: liboqs-python not installed.")
        print("Install with: pip install oqs")
        # Create minimal evidence showing the import failure
        evidence = {
            "lab": "Lab 2",
            "generated": datetime.now().isoformat(),
            "status": "SKIPPED",
            "reason": "liboqs-python not available",
            "test_results": []
        }
        with open(EVIDENCE_DIR / "lab2_algorithm_test_evidence.json", "w") as f:
            json.dump(evidence, f, indent=2)
        sys.exit(0)

    available_kems = oqs.get_enabled_kem_mechanisms()
    available_sigs = oqs.get_enabled_sig_mechanisms()

    print(f"Available KEMs: {len(available_kems)}")
    print(f"Available Sigs: {len(available_sigs)}")

    # Test KEMs
    kem_targets = [
        ("ML-KEM-512", ["ML-KEM-512", "Kyber512"]),
        ("ML-KEM-768", ["ML-KEM-768", "Kyber768"]),
        ("ML-KEM-1024", ["ML-KEM-1024", "Kyber1024"]),
    ]

    for display, candidates in kem_targets:
        alg = find_algorithm(candidates, available_kems)
        if alg:
            test_kem(display, alg, oqs)
        else:
            record(f"{display} Availability", "INFO",
                   {"message": "Not available", "tried": candidates})

    # Test Signatures
    sig_targets = [
        ("ML-DSA-44", ["ML-DSA-44", "Dilithium2"]),
        ("ML-DSA-65", ["ML-DSA-65", "Dilithium3"]),
        ("ML-DSA-87", ["ML-DSA-87", "Dilithium5"]),
    ]

    for display, candidates in sig_targets:
        alg = find_algorithm(candidates, available_sigs)
        if alg:
            test_sig(display, alg, oqs)
        else:
            record(f"{display} Availability", "INFO",
                   {"message": "Not available", "tried": candidates})

    # Export evidence
    evidence = {
        "lab": "Lab 2: Algorithm Testing",
        "generated": datetime.now().isoformat(),
        "python_version": sys.version,
        "available_kems": available_kems[:20],
        "available_sigs": available_sigs[:20],
        "test_results": test_results,
        "summary": {
            "total": len(test_results),
            "passed": sum(1 for r in test_results if r["status"] == "PASS"),
            "failed": sum(1 for r in test_results if r["status"] == "FAIL"),
            "info": sum(1 for r in test_results if r["status"] == "INFO"),
        }
    }

    path = EVIDENCE_DIR / "lab2_algorithm_test_evidence.json"
    with open(path, "w") as f:
        json.dump(evidence, f, indent=2, default=str)

    print(f"\n✓ Evidence: {path}")
    print(f"Total: {evidence['summary']['total']} | "
          f"Pass: {evidence['summary']['passed']} | "
          f"Fail: {evidence['summary']['failed']}")
    print("LAB 2 COMPLETE")


if __name__ == "__main__":
    main()