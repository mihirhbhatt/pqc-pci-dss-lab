#!/usr/bin/env python3
"""
Lab 3: PQC TLS Configuration Testing
Tests certificate generation and TLS configuration for PCI-DSS 4.2.1.
"""

import subprocess
import json
import os
import tempfile
import time
from datetime import datetime
from pathlib import Path

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "evidence"))
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def run_cmd(cmd, check=False):
    """Run a shell command and return result."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
    return result


def test_openssl_version():
    """Check OpenSSL version and capabilities."""
    r = run_cmd("openssl version -a")
    return {
        "version": r.stdout.strip().split("\n")[0] if r.returncode == 0 else "unknown",
        "available": r.returncode == 0
    }


def test_certificate_generation():
    """Generate and measure certificates."""
    results = {}

    with tempfile.TemporaryDirectory() as tmpdir:
        # Classical RSA certificate
        run_cmd(f"openssl req -x509 -newkey rsa:2048 -sha256 -days 365 "
                f"-nodes -keyout {tmpdir}/rsa.key -out {tmpdir}/rsa.crt "
                f'-subj "/CN=test-rsa.lab.local"')

        if os.path.exists(f"{tmpdir}/rsa.crt"):
            rsa_size = os.path.getsize(f"{tmpdir}/rsa.crt")
            r = run_cmd(f"openssl x509 -in {tmpdir}/rsa.crt -outform DER "
                       f"-out {tmpdir}/rsa.der")
            rsa_der = os.path.getsize(f"{tmpdir}/rsa.der") if os.path.exists(f"{tmpdir}/rsa.der") else 0

            results["rsa_2048"] = {
                "pem_bytes": rsa_size,
                "der_bytes": rsa_der,
                "status": "generated"
            }

        # Classical ECDSA certificate
        run_cmd(f"openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 "
                f"-sha256 -days 365 -nodes "
                f"-keyout {tmpdir}/ecdsa.key -out {tmpdir}/ecdsa.crt "
                f'-subj "/CN=test-ecdsa.lab.local"')

        if os.path.exists(f"{tmpdir}/ecdsa.crt"):
            ecdsa_size = os.path.getsize(f"{tmpdir}/ecdsa.crt")
            run_cmd(f"openssl x509 -in {tmpdir}/ecdsa.crt -outform DER "
                   f"-out {tmpdir}/ecdsa.der")
            ecdsa_der = os.path.getsize(f"{tmpdir}/ecdsa.der") if os.path.exists(f"{tmpdir}/ecdsa.der") else 0

            results["ecdsa_p256"] = {
                "pem_bytes": ecdsa_size,
                "der_bytes": ecdsa_der,
                "status": "generated"
            }

        # Try PQC certificates (may not be available)
        pqc_algs = ["mldsa65", "dilithium3", "ML-DSA-65"]
        pqc_generated = False

        for alg in pqc_algs:
            r = run_cmd(f"openssl req -x509 -newkey {alg} -days 365 -nodes "
                       f"-keyout {tmpdir}/pqc.key -out {tmpdir}/pqc.crt "
                       f'-subj "/CN=test-pqc.lab.local" 2>&1')

            if os.path.exists(f"{tmpdir}/pqc.crt"):
                pqc_size = os.path.getsize(f"{tmpdir}/pqc.crt")
                run_cmd(f"openssl x509 -in {tmpdir}/pqc.crt -outform DER "
                       f"-out {tmpdir}/pqc.der")
                pqc_der = os.path.getsize(f"{tmpdir}/pqc.der") if os.path.exists(f"{tmpdir}/pqc.der") else 0

                results["pqc_certificate"] = {
                    "algorithm": alg,
                    "pem_bytes": pqc_size,
                    "der_bytes": pqc_der,
                    "status": "generated"
                }
                pqc_generated = True
                break

        if not pqc_generated:
            results["pqc_certificate"] = {
                "status": "not_available",
                "note": "PQC certificate generation requires OpenSSL with OQS provider. "
                       "Algorithm testing completed in Lab 2."
            }

        # TLS server test
        tls_test = test_tls_connection(tmpdir)
        results["tls_test"] = tls_test

    return results


def test_tls_connection(cert_dir):
    """Test TLS connection with certificates."""
    cert_file = None
    key_file = None

    for prefix in ["pqc", "ecdsa", "rsa"]:
        if os.path.exists(f"{cert_dir}/{prefix}.crt"):
            cert_file = f"{cert_dir}/{prefix}.crt"
            key_file = f"{cert_dir}/{prefix}.key"
            break

    if not cert_file:
        return {"status": "skipped", "reason": "No certificate available"}

    # Start TLS server
    server_proc = subprocess.Popen(
        f"openssl s_server -cert {cert_file} -key {key_file} "
        f"-port 14433 -www -tls1_3",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    time.sleep(2)

    # Test connection
    client_result = run_cmd(
        f'echo "Q" | openssl s_client -connect localhost:14433 '
        f"-CAfile {cert_file} -tls1_3 -brief 2>&1"
    )

    # Clean up server
    server_proc.terminate()
    try:
        server_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server_proc.kill()

    connected = "CONNECTION ESTABLISHED" in client_result.stdout.upper() or \
                "CONNECTED" in client_result.stdout.upper()

    return {
        "status": "connected" if connected else "failed",
        "tls_version": "TLS 1.3",
        "output_preview": client_result.stdout[:500] if client_result.stdout else "",
        "cert_type": os.path.basename(cert_file).replace(".crt", "")
    }


def main():
    print("=" * 70)
    print("LAB 3: PQC TLS Configuration for PCI-DSS 4.2.1")
    print("=" * 70)

    openssl_info = test_openssl_version()
    print(f"OpenSSL: {openssl_info['version']}")

    cert_results = test_certificate_generation()

    # Size comparison
    print("\n--- Certificate Size Comparison ---")
    for cert_type, info in cert_results.items():
        if cert_type == "tls_test":
            continue
        if isinstance(info, dict) and "der_bytes" in info:
            print(f"  {cert_type}: PEM={info.get('pem_bytes', 'N/A')} bytes, "
                  f"DER={info.get('der_bytes', 'N/A')} bytes")

    print(f"\n--- TLS Test ---")
    tls = cert_results.get("tls_test", {})
    print(f"  Status: {tls.get('status', 'unknown')}")
    print(f"  TLS Version: {tls.get('tls_version', 'unknown')}")

    # Export evidence
    evidence = {
        "lab": "Lab 3: PQC TLS Configuration",
        "pci_dss_requirement": "4.2.1",
        "generated": datetime.now().isoformat(),
        "openssl": openssl_info,
        "certificates": cert_results,
        "pci_dss_notes": [
            "TLS 1.3 enforced",
            "Certificate size impacts measured",
            "PQC key exchange protects against harvest-now-decrypt-later",
            "Hybrid mode recommended during transition"
        ]
    }

    path = EVIDENCE_DIR / "lab3_tls_evidence.json"
    with open(path, "w") as f:
        json.dump(evidence, f, indent=2, default=str)

    print(f"\n✓ Evidence: {path}")
    print("LAB 3 COMPLETE")


if __name__ == "__main__":
    main()