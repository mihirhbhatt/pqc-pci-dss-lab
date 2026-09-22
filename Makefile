.PHONY: all setup test lab1 lab2 lab3 lab4 lab5 lab6 lab7 lab8 lab9 lab10 lab11 lab12 lab13 lab14 lab15 lab16 lab17 lab18 report tls-verify tls-benchmark clean

PYTHON := python3
EVIDENCE_DIR := evidence
REPORTS_DIR := reports

all: setup lab1 lab2 lab3 lab4 lab5 lab6 lab7 lab8 lab9 lab10 lab11 lab12 lab13 lab14 lab15 lab16 lab17 lab18 report

setup:
	$(PYTHON) -m pip install -r requirements.txt
	mkdir -p $(EVIDENCE_DIR) $(REPORTS_DIR)

lab1:
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab1_standards_mapping

lab2:
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab2_algorithm_testing

lab3:
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab3_tls_migration

tls-verify:
	@test -n "$(TLS_HOST)" || (echo "Usage: make tls-verify TLS_HOST=example.com" && exit 1)
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab3_tls_migration --verify-endpoint $(TLS_HOST) --port $(or $(TLS_PORT),443)

tls-benchmark:
	@test -n "$(TLS_HOST)" || (echo "Usage: make tls-benchmark TLS_HOST=example.com [SAMPLES=100]" && exit 1)
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab3_tls_migration --benchmark-endpoint $(TLS_HOST) --port $(or $(TLS_PORT),443) --samples $(or $(SAMPLES),100)

lab4:
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab4_crypto_inventory

lab5:
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab5_bb84_simulation

lab6:
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab6_qkd_attack_detection

lab7:
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab7_migration_roadmap

lab8:
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab8_pqc_envelope_encryption

lab9:
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab9_kubernetes_crypto_baseline

lab10:
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab10_vault_secret_policy

lab11:
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab11_vault_pki_issuance

lab12:
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab12_service_mesh_mtls

lab13:
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab13_iac_security_validation

lab14:
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab14_network_policy_analysis

lab15:
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab15_key_rotation

lab16:
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab16_configuration_drift

lab17:
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab17_zero_trust_policy

lab18:
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab18_multi_region_failover

report:
	EVIDENCE_DIR=$(EVIDENCE_DIR) REPORTS_DIR=$(REPORTS_DIR) $(PYTHON) scripts/generate_report.py

test:
	$(PYTHON) -m pytest tests/ -v

clean:
	rm -rf $(EVIDENCE_DIR) $(REPORTS_DIR) __pycache__ labs/__pycache__ .pytest_cache
