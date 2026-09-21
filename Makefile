.PHONY: all setup test lab1 lab2 lab3 lab4 lab5 lab6 lab7 report tls-verify tls-benchmark clean

PYTHON := python3
EVIDENCE_DIR := evidence
REPORTS_DIR := reports

all: setup lab1 lab4 lab5 lab6 lab7 report

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
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab6_migration_roadmap

lab7:
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab7_qkd_attack_detection

report:
	EVIDENCE_DIR=$(EVIDENCE_DIR) REPORTS_DIR=$(REPORTS_DIR) $(PYTHON) scripts/generate_report.py

test:
	$(PYTHON) -m pytest tests/ -v

clean:
	rm -rf $(EVIDENCE_DIR) $(REPORTS_DIR) __pycache__ labs/__pycache__ .pytest_cache
