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
import argparse
import re
import statistics
from datetime import datetime
from pathlib import Path

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "evidence"))
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


HYBRID_GROUP = "X25519MLKEM768"


def run_cmd(cmd, check=False, input_text=None, timeout=30):
    """Run a shell command and return result."""
    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        input=input_text,
        timeout=timeout
    )
    return result


def test_openssl_version():
    """Check OpenSSL version and capabilities."""
    r = run_cmd("openssl version -a")
    return {
        "version": r.stdout.strip().split("\n")[0] if r.returncode == 0 else "unknown",
        "available": r.returncode == 0
    }


def detect_pqc_capabilities():
    """Detect native ML-KEM and hybrid TLS group support."""
    kem_result = run_cmd("openssl list -kem-algorithms 2>&1")
    group_result = run_cmd("openssl list -tls1_3-groups 2>&1")
    kem_output = f"{kem_result.stdout}\n{kem_result.stderr}"
    group_output = f"{group_result.stdout}\n{group_result.stderr}"
    return {
        "mlkem_available": bool(re.search(r"ML-KEM|MLKEM", kem_output, re.IGNORECASE)),
        "hybrid_group_available": HYBRID_GROUP.lower() in group_output.lower(),
        "kem_output": kem_output[:1000],
        "group_output": group_output[:1000],
        "provider_hint": "native OpenSSL 3.5+ or oqsprovider"
    }


def verify_hybrid_connection(host, port=443):
    """Verify that a live endpoint negotiates the requested hybrid group."""
    command = (
        f"openssl s_client -connect {host}:{int(port)} "
        f"-groups {HYBRID_GROUP} -tls1_3 -brief 2>&1"
    )
    result = run_cmd(command, input_text="Q\n", timeout=30)
    output = result.stdout or ""
    negotiated = HYBRID_GROUP.lower() in output.lower()
    return {
        "host": host,
        "port": int(port),
        "requested_group": HYBRID_GROUP,
        "status": "verified" if negotiated else "not_verified",
        "negotiated_group": HYBRID_GROUP if negotiated else None,
        "return_code": result.returncode,
        "output_preview": output[:2000]
    }


def extract_client_hello_size(output):
    """Extract the first TLS handshake payload length from OpenSSL -msg output."""
    match = re.search(
        r">>>\s+TLS[^\n]*Handshake\s+\[length\s+([0-9a-fA-F]+)\]",
        output,
        re.IGNORECASE
    )
    return int(match.group(1), 16) if match else None


def benchmark_handshakes(host, port=443, samples=100):
    """Measure live hybrid handshake latency and OpenSSL-reported ClientHello size."""
    latencies_ms = []
    client_hello_sizes = []
    failures = 0

    for _ in range(max(1, int(samples))):
        started = time.perf_counter()
        command = (
            f"openssl s_client -connect {host}:{int(port)} "
            f"-groups {HYBRID_GROUP} -tls1_3 -msg -brief 2>&1"
        )
        result = run_cmd(command, input_text="Q\n", timeout=30)
        elapsed_ms = (time.perf_counter() - started) * 1000
        output = result.stdout or ""
        if result.returncode != 0 or "CONNECTED" not in output.upper():
            failures += 1
            continue
        latencies_ms.append(elapsed_ms)
        client_hello_size = extract_client_hello_size(output)
        if client_hello_size is not None:
            client_hello_sizes.append(client_hello_size)

    def percentile(values, fraction):
        if not values:
            return None
        ordered = sorted(values)
        index = min(len(ordered) - 1, round((len(ordered) - 1) * fraction))
        return round(ordered[index], 3)

    return {
        "host": host,
        "port": int(port),
        "requested_group": HYBRID_GROUP,
        "requested_samples": int(samples),
        "successful_samples": len(latencies_ms),
        "failed_samples": failures,
        "latency_ms": {
            "median": round(statistics.median(latencies_ms), 3) if latencies_ms else None,
            "p95": percentile(latencies_ms, 0.95)
        },
        "client_hello_bytes": {
            "median": round(statistics.median(client_hello_sizes), 3)
            if client_hello_sizes else None,
            "p95": percentile(client_hello_sizes, 0.95),
            "measurement": "OpenSSL -msg handshake payload length"
        },
        "status": "complete" if latencies_ms else "failed"
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
    parser = argparse.ArgumentParser(description="PQC TLS capability and handshake evidence")
    parser.add_argument("--verify-endpoint", metavar="HOST", help="Verify a live hybrid TLS endpoint")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--benchmark-endpoint", metavar="HOST", help="Benchmark a live hybrid TLS endpoint")
    parser.add_argument("--samples", type=int, default=100)
    args = parser.parse_args()

    print("=" * 70)
    print("LAB 3: PQC TLS Configuration for PCI-DSS 4.2.1")
    print("=" * 70)

    openssl_info = test_openssl_version()
    print(f"OpenSSL: {openssl_info['version']}")
    capabilities = detect_pqc_capabilities()
    print(f"Hybrid group available: {capabilities['hybrid_group_available']}")

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

    hybrid_verification = (
        verify_hybrid_connection(args.verify_endpoint, args.port)
        if args.verify_endpoint else
        {"status": "not_run", "reason": "Pass --verify-endpoint to test a live endpoint"}
    )
    benchmark = (
        benchmark_handshakes(args.benchmark_endpoint, args.port, args.samples)
        if args.benchmark_endpoint else
        {"status": "not_run", "reason": "Pass --benchmark-endpoint to measure live handshakes"}
    )

    # Export evidence
    evidence = {
        "lab": "Lab 3: PQC TLS Configuration",
        "pci_dss_requirement": "4.2.1",
        "generated": datetime.now().isoformat(),
        "openssl": openssl_info,
        "pqc_capabilities": capabilities,
        "certificates": cert_results,
        "hybrid_verification": hybrid_verification,
        "handshake_benchmark": benchmark,
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