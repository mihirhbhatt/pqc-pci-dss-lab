#  PQC + PCI-DSS Compliance Lab — Proof of Concept

## What Is This POC?

This is a **hands-on proof-of-concept laboratory** that demonstrates how an
organization can migrate its cryptographic infrastructure from classical
public-key algorithms (RSA, ECDH, ECDSA) to **Post-Quantum Cryptography (PQC)**
algorithms standardized by NIST, while simultaneously satisfying **PCI-DSS v4.0**
cryptographic compliance requirements.

It answers one critical question:

> *"How do we make our payment processing environment quantum-safe without
> breaking PCI-DSS compliance?"*

---

## Why Does This Matter?

### The Quantum Threat to Payment Data

Quantum computers, once sufficiently powerful, will break the public-key
cryptography that protects virtually all digital communications today:

| Classical Algorithm | Quantum Attack | Impact |
|---|---|---|
| RSA-2048/4096 | Shor's algorithm | Key recovery in polynomial time |
| ECDH (P-256, P-384) | Shor's algorithm | Key agreement broken |
| ECDSA | Shor's algorithm | Signature forgery |
| DH | Shor's algorithm | Key exchange broken |
| AES-128 | Grover's algorithm | Effective strength halved (use AES-256) |
| AES-256 | Grover's algorithm | Still secure at 128-bit quantum strength |
| SHA-256/384 | Grover's algorithm | Still secure (use larger output) |

### The "Harvest Now, Decrypt Later" Problem

Adversaries are **already collecting** encrypted TLS sessions, VPN traffic, and
stored encrypted data. Even though quantum computers capable of breaking RSA
do not exist yet, data encrypted today with classical algorithms can be stored
and decrypted years from now when quantum capability arrives.

For PCI-DSS environments, this is critical because:

- **PAN (Primary Account Numbers)** stored in encrypted databases may have
  retention periods of 7+ years
- **TLS sessions** carrying cardholder data can be recorded passively
- **Backup encryption keys** wrapped with RSA are vulnerable
- **Certificate signatures** can be forged, enabling man-in-the-middle attacks

### The Compliance Intersection

PCI-DSS v4.0 requires organizations to:

1. **Inventory all cryptographic assets** (Requirement 12.3.3)
2. **Use strong cryptography** for PAN storage and transmission (Requirements 3.5, 4.2)
3. **Manage cryptographic keys** securely (Requirements 3.6, 3.7)
4. **Review technologies annually** for end-of-life and vulnerabilities (Requirement 12.3.4)

NIST has finalized three post-quantum cryptographic standards:

1. **FIPS 203 — ML-KEM** (Module-Lattice-Based Key-Encapsulation Mechanism)
   - Replaces RSA key transport, ECDH, DH
   - Used for key exchange and key wrapping

2. **FIPS 204 — ML-DSA** (Module-Lattice-Based Digital Signature Algorithm)
   - Replaces RSA signatures, ECDSA
   - Used for certificates, code signing, authentication

3. **FIPS 205 — SLH-DSA** (Stateless Hash-Based Digital Signature Algorithm)
   - Conservative alternative based only on hash function security
   - Used for root-of-trust signatures where maximum assurance is needed

**This POC demonstrates that these two requirements — quantum safety and
PCI-DSS compliance — are not separate projects. They are the same project.**

---

## What Does This POC Do?

The POC consists of **six integrated labs** that walk through the complete
PQC migration lifecycle:

### Lab 1: NIST PQC ↔ PCI-DSS Standards Mapping
**What it does:** Creates a formal cross-reference matrix mapping every NIST
PQC algorithm (ML-KEM, ML-DSA, SLH-DSA) to every PCI-DSS v4.0 cryptographic
requirement (2.2.7, 3.5.1, 3.6.1, 3.7.1, 4.2.1, 4.2.2, 12.3.3, 12.3.4).

**Why it matters:** Before migrating anything, you need to know which algorithm
replaces which classical algorithm for each compliance control. This lab
produces the decision matrix.

**Output:** JSON and CSV alignment matrices showing, for example, that
PCI-DSS 4.2.1 (PAN transmission) requires ML-KEM-768 for key exchange and
ML-DSA-65 for certificate signatures.

### Lab 2: ML-KEM and ML-DSA Algorithm Testing
**What it does:** Installs the Open Quantum Safe (liboqs) library and runs
real cryptographic operations — key generation, encapsulation, decapsulation,
signing, and verification — using the actual NIST-standardized algorithms.

**Why it matters:** You need to verify that the algorithms work correctly,
measure their performance, understand their key and signature sizes, and
confirm that negative cases (corrupted data, wrong keys) are properly rejected.

**Output:** Complete test evidence including positive tests, negative tests,
size measurements, and performance benchmarks for all parameter sets.

### Lab 3: PQC TLS Configuration
**What it does:** Generates cryptographic certificates (classical and PQC),
configures a TLS 1.3 server, tests connections, and measures the impact of
larger PQC keys and certificates on the TLS handshake.

**Why it matters:** PCI-DSS 4.2.1 specifically requires strong cryptography
for PAN in transit. TLS is the primary mechanism. This lab shows what a
PQC-enabled TLS deployment looks like and what size/performance trade-offs
to expect.

**Output:** Certificate chain evidence, TLS connection test results, and
size impact analysis.

### Lab 4: Cryptographic Asset Inventory
**What it does:** Builds a complete inventory of 10 representative
cryptographic assets in a payment processing environment — TLS gateways,
card vaults, PKI, API authentication, backups, POS terminals, code signing,
VPNs, email encryption, and audit logs.

**Why it matters:** PCI-DSS 12.3.3 explicitly requires a cryptographic cipher
suite and protocol inventory. This is also the foundational step in NIST's
PQC migration guidance. Each asset is scored for quantum vulnerability,
mapped to PCI-DSS requirements, and assigned a migration priority.

**Output:** Prioritized 10-asset inventory with quantum risk scores,
migration targets, owners, test gates, and rollback plans.

### Lab 5: BB84 Quantum Key Distribution Simulation
**What it does:** Simulates the BB84 quantum key distribution protocol with
and without an eavesdropper (Eve), measures the Quantum Bit Error Rate (QBER),
and demonstrates how eavesdropping is detected through elevated error rates.

**Why it matters:** There is widespread confusion between PQC (software
algorithms) and QKD (quantum hardware). This lab honestly demonstrates
what QKD can and cannot do, and why PQC is the primary migration path
for PCI-DSS environments while QKD has limited applicability.

**Output:** Five BB84 experiments with QBER measurements, eavesdropper
detection results, and a QKD-vs-PQC suitability analysis.

### Lab 6: 90-Day Migration Roadmap
**What it does:** Assembles all previous lab outputs into a concrete 90-day
migration plan with three phases (Discovery, Testing, Pilot), 14 milestones,
named owners, acceptance criteria, and rollback triggers.

**Why it matters:** A migration plan without specific milestones, owners,
and test gates is not actionable. This lab produces a defensible roadmap
that can be presented to security leadership, QSAs, and auditors.

**Output:** Complete 90-day roadmap with milestone checklist and
crypto-agility framework recommendations.

---


---

## Compliance Mapping Summary

| Lab | NIST Standard | PCI-DSS Requirement | Evidence Produced |
|---|---|---|---|
| Lab 1 | FIPS 203/204/205 | 2.2.7, 3.5, 3.6, 3.7, 4.2, 12.3 | Alignment matrix |
| Lab 2 | FIPS 203/204/205 | 3.5.1, 3.6.1, 4.2.1, 6.2, 10.3 | Algorithm test evidence |
| Lab 3 | FIPS 203 + 204 | 4.2.1 | TLS configuration evidence |
| Lab 4 | Migration guidance | 12.3.3, 12.3.4 | Asset inventory + priority scores |
| Lab 5 | QKD evaluation | Supplementary | BB84 simulation + QKD analysis |
| Lab 6 | Migration guidance | 3.7.1, 12.3.3, 12.3.4 | 90-day roadmap + checklist |

---

## Key Findings This POC Demonstrates

1. **PQC migration and PCI-DSS compliance are the same project.** The
   cryptographic inventory required by PCI-DSS 12.3.3 is the same inventory
   needed for PQC migration planning.

2. **ML-KEM replaces RSA/ECDH for key exchange.** PCI-DSS 4.2.1 (PAN
   transmission) is the highest-priority migration target because recorded
   TLS sessions are vulnerable to harvest-now-decrypt-later attacks.

3. **ML-DSA replaces RSA/ECDSA for signatures.** Certificate signatures,
   code signing, and audit log integrity all require quantum-safe signatures.

4. **Symmetric cryptography (AES-256, HMAC-SHA256) is already quantum-safe.**
   Only public-key operations need migration. Grover's algorithm provides
   only a quadratic speedup against symmetric ciphers.

5. **QKD is not a replacement for PQC.** QKD requires authenticated classical
   channels, specialized hardware, point-to-point links, and does not provide
   digital signatures. PQC is the primary migration path for distributed
   payment environments.

6. **Hybrid deployment is the transition strategy.** During migration,
   classical and PQC algorithms run simultaneously (e.g., ECDHE + ML-KEM
   in TLS 1.3) to maintain compatibility while adding quantum resistance.

---

## How to Use This POC

### For Security Engineers
Run the labs locally or via GitHub Actions. Use the output evidence to
build your organization's actual cryptographic inventory and migration plan.

### For Compliance Teams (QSA Preparation)
The evidence artifacts demonstrate proactive quantum risk management.
Present the alignment matrix (Lab 1) and inventory (Lab 4) to your QSA
as evidence of PCI-DSS 12.3.3 and 12.3.4 compliance planning.

### For Security Leadership
Review the 90-day roadmap (Lab 6) and priority scores (Lab 4) to
understand resource requirements and timeline for quantum-safe migration.

### For Students and Researchers
Each lab is self-contained with detailed comments. The BB84 simulation
(Lab 5) is particularly useful for understanding QKD protocol mechanics.

---

## Technology Stack

- **PQC Library:** [liboqs](https://github.com/open-quantum-safe/liboqs) (Open Quantum Safe)
- **PQC Python Bindings:** [liboqs-python](https://github.com/open-quantum-safe/liboqs-python)
- **TLS Testing:** OpenSSL 3.x with OQS Provider
- **CI/CD:** GitHub Actions
- **Dashboard:** GitHub Pages (static HTML)
- **Language:** Python 3.11
- **Containerization:** Docker (optional)

---

## How the POC Fits Together

This repository is a small, repeatable migration decision system rather than
just a collection of cryptography demonstrations. The flow is:

```text
Standards and controls
            |
            v
Algorithm decisions -----> Cryptographic asset inventory
            |                              |
            v                              v
Algorithm tests -------------> Prioritized migration targets
            |                              |
            v                              v
TLS and certificate POC ------> 90-day migration roadmap
            |
            v
Evidence files, consolidated report, and dashboard
```

Each lab answers a different question:

| Question | Lab | Result |
|---|---|---|
| What should replace the current algorithms? | Lab 1 | Standards mapping and decision matrix |
| Do the target algorithms work correctly? | Lab 2 | Key, encapsulation, signature, negative-test, and timing evidence |
| Can the algorithms fit into TLS? | Lab 3 | Certificate, TLS 1.3, and size-impact evidence |
| Where are the vulnerable systems? | Lab 4 | Asset inventory with owners, risk, priority, test gate, and rollback |
| Is QKD relevant to this environment? | Lab 5 | BB84 experiment results and a QKD-vs-PQC assessment |
| What happens next? | Lab 6 | Phased roadmap with owners and acceptance criteria |

The labs are intentionally connected through a common evidence directory. Each
program writes JSON, and selected labs also write CSV or console logs. The
report scripts consume those artifacts and produce a consolidated migration
pack plus a static dashboard suitable for a GitHub Pages deployment.

## What Each Lab Proves

### Lab 1: Make the decision defensible

Lab 1 is the policy and architecture layer. It records which NIST standard
applies to each use case, what classical mechanism it replaces, the relevant
PCI-DSS requirement, and the migration priority.

The key distinction is that not every cryptographic component needs the same
change. AES-256 protects bulk data effectively against the expected quantum
search speedup, while RSA, ECDH, ECDSA, and DH are the urgent public-key
targets. This prevents an expensive "replace everything" program and focuses
work on key exchange, signatures, key wrapping, certificates, and trust
anchors.

### Lab 2: Test real implementations

Lab 2 uses liboqs-python and the liboqs native library. It discovers available
algorithms, then tests the ML-KEM parameter sets and ML-DSA parameter sets that
are available in the installed build.

For KEMs it checks key generation, encapsulation, decapsulation, shared-secret
agreement, corrupted-ciphertext handling, object sizes, and operation time.
For signatures it checks key generation, signing, verification, tampered
messages, wrong public keys, signature sizes, and operation time.

This is implementation evidence, not a certification of the library or a
replacement for a validated cryptographic module. It is a compatibility and
engineering baseline for the next test stage.

### Lab 3: Test the transport boundary

Lab 3 compares classical RSA and ECDSA certificate generation with PQC
certificate support when the installed OpenSSL build exposes an OQS provider.
It starts a local TLS 1.3 server, connects with an OpenSSL client, and records
certificate sizes and connection status.

The important operational lesson is that PQC changes the transport envelope:
public keys, signatures, certificates, and handshake messages are larger.
Production testing therefore needs to include MTU behavior, proxies, load
balancers, client compatibility, handshake latency, connection rates, and
certificate-chain limits. The current lab establishes the first local signal;
it does not claim broad production interoperability.

### Lab 4: Find the work that matters first

Lab 4 models ten payment-environment assets, including TLS termination, card
vault encryption, internal PKI, API signing, backups, POS terminals, code
signing, VPN, email, and audit-related systems. Every record includes the
algorithm, data lifetime, quantum-vulnerable components, PCI-DSS mapping,
owner, migration target, test gate, and rollback plan.

The inventory makes prioritization explicit. Long-lived PAN backups, card-vault
key wrapping, root CA keys, and recorded TLS traffic generally deserve earlier
attention than short-lived non-sensitive tokens. In a real deployment this
model should be populated from discovery data rather than treated as the
organization's actual inventory.

### Lab 5: Separate QKD from PQC

Lab 5 is an educational and architectural comparison. It simulates BB84 with
an ideal channel, channel noise, and an intercept-resend attacker. The measured
QBER demonstrates why eavesdropping can be detected in the protocol model.

QKD is not a drop-in replacement for ML-KEM or ML-DSA. It needs specialized
point-to-point hardware, an authenticated classical channel, operational
management, and still does not provide general-purpose digital signatures.
For most distributed payment estates, software-based PQC is the scalable
baseline. QKD may be evaluated separately for a small number of high-value
links.

### Lab 6: Convert evidence into execution

Lab 6 turns the previous results into three phases:

1. **Discovery and planning:** complete the inventory, select algorithms,
    assess vendors and HSMs, and obtain approval.
2. **Testing and validation:** verify algorithms, hybrid TLS, key management,
    QKD suitability, and rollback behavior.
3. **Pilot deployment:** move a bounded workload into production, monitor it,
    and use measured results to approve wider rollout.

The roadmap includes named owners, deliverables, acceptance criteria, and
rollback conditions. This is what turns a cryptography experiment into a
change-management artifact that security leadership and a QSA can review.

## Running the POC

### Local execution

Install the Python dependencies and run the tests:

```bash
python -m pip install -r requirements.txt
python -m pytest tests/ -v
```

Run individual labs with the Makefile on a Unix-like shell:

```bash
make lab1
make lab2
make lab3
make lab4
make lab5
make lab6
make report
```

On Windows, the equivalent Python commands are:

```powershell
$env:EVIDENCE_DIR = "evidence"
python -m labs.lab1_standards_mapping
python -m labs.lab4_crypto_inventory
python -m labs.lab5_bb84_simulation
python -m labs.lab6_migration_roadmap
$env:REPORTS_DIR = "reports"
python scripts/generate_report.py
python scripts/publish_dashboard.py
```

Lab 2 additionally requires a working liboqs installation and liboqs-python.
Lab 3 can run its classical TLS checks without a PQC-enabled OpenSSL provider,
but PQC certificate generation requires that provider to be installed.

### GitHub Actions execution

The workflow in `.github/workflows/pqc-full-lab.yml` runs the six labs in
separate jobs, validates important evidence fields, uploads lab artifacts, and
then aggregates the artifacts into a report and dashboard. The Pages job runs
only for a push to `main`.

The workflow is useful for repeatability, but each job has a fresh runner.
Artifacts from the setup job do not automatically install software into later
jobs, so jobs that need liboqs build or install what they need themselves.
This is deliberate infrastructure behavior to account for when optimizing the
pipeline with reusable images or caches.

## Evidence and Deliverables

The main evidence files are:

| Path | Meaning |
|---|---|
| `evidence/lab1_pqc_pcidss_alignment.json` and `.csv` | NIST-to-PCI-DSS alignments and algorithm decisions |
| `evidence/lab2_algorithm_test_evidence.json` | PQC correctness, negative tests, sizes, and timings |
| `evidence/lab3_tls_evidence.json` | OpenSSL, certificate, and TLS test results |
| `evidence/lab4_crypto_inventory.json` and `.csv` | Asset inventory and quantum-risk priorities |
| `evidence/lab5_bb84_evidence.json` | BB84 experiments, QBER, and eavesdropper assessment |
| `evidence/lab6_migration_roadmap.json` | Phases, milestones, owners, and acceptance criteria |
| `reports/consolidated_report.json` | Machine-readable status across all labs |
| `reports/REPORT.md` | Human-readable summary |
| `reports/dashboard/` | Static dashboard for review or Pages publishing |

Evidence should be treated as versioned engineering output. For audit use,
also retain the commit SHA, runner and tool versions, configuration, test
parameters, approvals, and the identity of the person who reviewed the result.

## Benefits of This POC

### Security benefits

- Identifies public-key exposure before a cryptographically relevant quantum
   computer exists.
- Addresses harvest-now-decrypt-later risk for long-lived cardholder data.
- Encourages hybrid migration, preserving classical interoperability while
   adding a quantum-resistant path.
- Makes rollback and acceptance criteria part of the migration design.

### Compliance and governance benefits

- Connects cryptographic inventory work to PCI-DSS Requirements 3, 4, and 12.
- Produces repeatable evidence instead of a one-time presentation or spreadsheet.
- Gives security leadership a prioritized backlog with owners and effort.
- Gives a QSA a traceable relationship between control, asset, algorithm,
   test, and planned remediation.

### Engineering benefits

- Measures key, ciphertext, certificate, and signature size before production
   rollout.
- Exercises invalid-input handling, which is often missed by happy-path demos.
- Provides CI checks that can detect regression in algorithms or evidence shape.
- Creates a common vocabulary for application, network, PKI, HSM, cloud, and
   compliance teams.

## Current Scope and Important Limitations

This is a POC and planning accelerator, not a production deployment or a PCI
assessment. In particular:

- The Lab 4 assets are representative templates and must be replaced with
   discovered organizational data.
- liboqs is useful for experimentation, but production cryptography should use
   approved, maintained, and appropriately validated implementations.
- Lab 3 does not validate every browser, mobile client, POS terminal, proxy,
   HSM, CDN, or cloud service in the environment.
- The current TLS test is local and does not measure production-scale latency,
   throughput, packet fragmentation, or failure recovery.
- The BB84 model is a simulation; it is not a security evaluation of quantum
   hardware or a QKD vendor.
- The roadmap contains template dates and statuses and requires organizational
   approval, dependency tracking, and risk acceptance.
- Evidence demonstrates testing and planning activity. It does not by itself
   prove PCI-DSS compliance or NIST validation.

## How to Scale from POC to Program

### Stage 1: Make the evidence trustworthy

1. Replace the sample inventory with exports from CMDB, cloud asset discovery,
    certificate management, vulnerability scanners, source repositories, API
    gateways, HSMs, VPNs, and network telemetry.
2. Add stable asset identifiers, data owners, environments, dependencies,
    cryptoperiods, certificate expiry, key location, and data-retention period.
3. Store evidence in an immutable artifact repository with commit SHA, tool
    versions, timestamps, and reviewer approval.
4. Add JSON schemas and fail CI when required fields, risk decisions, or
    evidence provenance are missing.

### Stage 2: Build a crypto-discovery service

Move from manually maintained records to scheduled discovery. Collect TLS
certificates and negotiated groups, scan repositories for cryptographic API
usage, inspect configuration and infrastructure-as-code, query HSM and KMS
metadata, and ingest vendor product versions. Normalize these observations
into one inventory while retaining the original source and confidence level.

The inventory should answer, for every cryptographic use:

- What algorithm and parameter set is used?
- What data does it protect and for how long?
- Is it in the cardholder data environment or connected to it?
- Who owns it and what depends on it?
- Can the vendor support hybrid or PQC operation?
- What is the migration and rollback path?

### Stage 3: Add production-like test environments

Create representative test lanes for payment gateways, service meshes, API
signing, PKI, backups, VPNs, terminals, and HSM-backed key management. Test
classical, hybrid, and PQC-only modes where supported. Add load tests for
handshake rate, CPU, memory, packet size, latency, certificate-chain size,
connection failures, and recovery.

Use compatibility matrices for operating systems, browsers, SDKs, payment
terminals, proxies, load balancers, and third-party processors. A migration
should not advance because one local TLS handshake succeeds; it should advance
because the required client population and failure modes are understood.

### Stage 4: Introduce crypto-agility

Put algorithm selection behind configuration and supported policy interfaces.
Separate data encryption from key wrapping, support key rotation and dual-key
read paths, version certificates and signing keys, and make rollback a tested
deployment action. Avoid embedding algorithm names throughout application code.

For signatures and tokens, plan key discovery, trust-store updates, signature
size limits, replay handling, and dual-sign or dual-verify periods. For data at
rest, plan rewrapping and re-encryption without taking payment services offline.

### Stage 5: Pilot, measure, and expand

Start with high-value, bounded flows such as an internal service pair or a
non-production payment gateway. Define SLOs and security gates before the
pilot. Monitor handshake failures, client fallbacks, certificate errors,
latency, CPU, packet fragmentation, and key-rotation outcomes. Expand by
application group or region only after the rollback procedure and evidence
review succeed.

### Stage 6: Institutionalize the program

Make PQC readiness part of architecture review, procurement, annual PCI-DSS
technology review, vendor assessments, incident response, change management,
and disaster recovery. Track unsupported products as explicit risks with due
dates and compensating controls. Repeat the inventory and test pipeline on a
schedule so the program remains current as standards, libraries, vendors, and
client support change.

## Suggested Scale-Up Metrics

Track metrics that show both risk reduction and operational readiness:

| Area | Example metric |
|---|---|
| Discovery | Percentage of in-scope assets with a verified cryptographic record |
| Exposure | Number of critical assets using RSA, ECDH, DH, or ECDSA |
| Data risk | Years of retained sensitive data protected by quantum-vulnerable key wrapping |
| Vendor readiness | Percentage of critical dependencies with a PQC support statement and test plan |
| Interoperability | Percentage of required clients completing the approved hybrid handshake |
| Performance | p95 handshake latency, CPU cost, and failure rate compared with baseline |
| Crypto-agility | Time to rotate or replace a key, certificate, or algorithm configuration |
| Delivery | Milestones completed on time with evidence and rollback validation |
| Compliance | Inventory and annual-review findings closed by due date |

The goal is not simply to count migrated algorithms. The goal is to reduce
quantum exposure while preserving payment availability, proving control
effectiveness, and retaining the ability to change algorithms again.

---

## References

- [NIST FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [NIST NCCoE: Migration to PQC](https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc)
- [PCI-DSS v4.0](https://www.pcisecuritystandards.org/document_library/)
- [NSA: QKD and Quantum Cryptography](https://www.nsa.gov/Cybersecurity/Quantum-Key-Distribution-QKD-and-Quantum-Cryptography-QC/)

---
