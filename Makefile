.PHONY: help install scan list triage validate record metrics goldenset import clean check-scope

REPO    ?= .
SARIF   ?= findings/raw.sarif
N       ?= 0
ID      ?=
MINUTES ?=

help:
	@echo "appsec-review - manual security review workflow"
	@echo ""
	@echo "  make install              install deterministic tooling"
	@echo "  make scan REPO=../myapp   run scanners, produce SARIF"
	@echo "  make list                 list findings with scope status"
	@echo "  make triage N=3           build a review packet for finding 3"
	@echo "  make validate ID=F-abc    build the adversarial challenge packet"
	@echo "  make record ID=F-abc MINUTES=12   validate, apply policy, log"
	@echo "  make metrics              programme health"
	@echo "  make goldenset            regression bench"
	@echo "  make import ENGAGEMENT=42 upload to DefectDojo"
	@echo "  make check-scope          print the active exclusion policy"
	@echo ""
	@echo "Read docs/03-data-handling.md before first use."

install:
	pip install semgrep
	@echo "Optional: syft, grype or trivy, and jsonschema for strict validation."

scan:
	./scripts/scan.sh $(REPO)

list:
	@python3 scripts/build_packet.py --sarif $(SARIF) --list

triage:
	@python3 scripts/build_packet.py --sarif $(SARIF) --index $(N) --repo $(REPO)

validate:
	@test -n "$(ID)" || (echo "Set ID=<finding-id>" && exit 1)
	@python3 scripts/build_packet.py --challenge --verdict findings/verdicts/$(ID).json

record:
	@test -n "$(ID)" || (echo "Set ID=<finding-id>" && exit 1)
	@python3 scripts/record_verdict.py \
		--verdict findings/verdicts/$(ID).json \
		$(if $(wildcard findings/challenges/$(ID).json),--challenge findings/challenges/$(ID).json,) \
		$(if $(MINUTES),--minutes $(MINUTES),)

metrics:
	@python3 scripts/metrics.py

goldenset:
	@python3 goldenset/run_goldenset.py --label "$(LABEL)" --strict

import:
	@test -n "$(ENGAGEMENT)" || (echo "Set ENGAGEMENT=<id>" && exit 1)
	@python3 scripts/import_defectdojo.py --engagement $(ENGAGEMENT)

check-scope:
	@python3 scripts/check_scope.py --list

clean:
	rm -rf findings/packets findings/reviewed.sarif
	@echo "Kept: verdicts, challenges, triage-log.csv"
