.PHONY: all setup test lab1 lab2 lab3 lab4 lab5 lab6 report clean

PYTHON := python3
EVIDENCE_DIR := evidence
REPORTS_DIR := reports

all: setup lab1 lab4 lab5 lab6 report

setup:
	$(PYTHON) -m pip install -r requirements.txt
	mkdir -p $(EVIDENCE_DIR) $(REPORTS_DIR)

lab1:
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab1_standards_mapping

lab2:
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab2_algorithm_testing

lab3:
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab3_tls_migration

lab4:
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab4_crypto_inventory

lab5:
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab5_bb84_simulation

lab6:
	EVIDENCE_DIR=$(EVIDENCE_DIR) $(PYTHON) -m labs.lab6_migration_roadmap

report:
	EVIDENCE_DIR=$(EVIDENCE_DIR) REPORTS_DIR=$(REPORTS_DIR) $(PYTHON) scripts/generate_report.py

test:
	$(PYTHON) -m pytest tests/ -v

clean:
	rm -rf $(EVIDENCE_DIR) $(REPORTS_DIR) __pycache__ labs/__pycache__ .pytest_cache
