.PHONY: help install scan list triage validate record decide metrics goldenset import clean check-scope check-template test

REPO    ?= .
SARIF   ?= findings/raw.sarif
N       ?= 0
ID      ?=
MINUTES ?=
SEMGREP_VERSION ?=

help:
	@echo "appsec-review - manual security review workflow"
	@echo ""
	@echo "  make install              install deterministic tooling"
	@echo "  make scan REPO=../myapp   run scanners, produce SARIF"
	@echo "  make list                 list findings with scope status"
	@echo "  make list LEVEL=error UNREVIEWED=1   filtered triage queue"
	@echo "  make triage N=3           build a review packet for finding 3"
	@echo "  make triage ID=F-abc      build a packet by finding id"
	@echo "  make validate ID=F-abc    build the adversarial challenge packet"
	@echo "  make record ID=F-abc AGENT=<model> VALIDATOR=<model> MINUTES=12"
	@echo "  make decide ID=F-abc DECISION=rejected BY=appsec-oncall"
	@echo "  make metrics              programme health"
	@echo "  make goldenset            regression bench"
	@echo "  make import ENGAGEMENT=42 upload to DefectDojo"
	@echo "  make check-scope          print the active exclusion policy"
	@echo "  make check-template       refuse while CLAUDE.md is unfilled"
	@echo "  make test                 run the test suite (stdlib only)"
	@echo ""
	@echo "Read docs/03-data-handling.md before first use."

install:
	@test -n "$(SEMGREP_VERSION)" || ( \
	  echo "Set SEMGREP_VERSION=<version>."; \
	  echo ""; \
	  echo "Scanner fingerprints feed finding identity, so an unpinned"; \
	  echo "upgrade silently re-keys every finding and orphans its verdicts."; \
	  echo "See docs/02-setup.md."; \
	  exit 1)
	pip install "semgrep==$(SEMGREP_VERSION)"
	@echo ""
	@echo "Record $(SEMGREP_VERSION) in docs/02-setup.md before the first scan."
	@echo "Optional: syft, grype or trivy, and jsonschema for strict validation."

scan:
	./scripts/scan.sh $(REPO)

list:
	@python3 scripts/build_packet.py --sarif $(SARIF) --list \
		$(if $(LEVEL),--level $(LEVEL),) \
		$(if $(RULE),--rule $(RULE),) \
		$(if $(PATH_GLOB),--path "$(PATH_GLOB)",) \
		$(if $(UNREVIEWED),--unreviewed,) \
		$(if $(LIMIT),--limit $(LIMIT),)

triage:
	@python3 scripts/build_packet.py --sarif $(SARIF) --repo $(REPO) \
		$(if $(ID),--finding-id $(ID),--index $(N))

validate:
	@test -n "$(ID)" || (echo "Set ID=<finding-id>" && exit 1)
	@python3 scripts/build_packet.py --challenge --verdict findings/verdicts/$(ID).json

record:
	@test -n "$(ID)" || (echo "Set ID=<finding-id>" && exit 1)
	@test -n "$(AGENT)" || (echo "Set AGENT=<model that ran triage>" && exit 1)
	@python3 scripts/record_verdict.py \
		--verdict findings/verdicts/$(ID).json \
		--agent "$(AGENT)" \
		$(if $(VALIDATOR),--validator "$(VALIDATOR)",) \
		$(if $(wildcard findings/challenges/$(ID).json),--challenge findings/challenges/$(ID).json,) \
		$(if $(MINUTES),--minutes $(MINUTES),)

decide:
	@test -n "$(ID)" || (echo "Set ID=<finding-id>" && exit 1)
	@test -n "$(DECISION)" || (echo "Set DECISION=accepted|rejected|escalated" && exit 1)
	@test -n "$(BY)" || (echo "Set BY=<role or work handle, not a name>" && exit 1)
	@python3 scripts/record_human_decision.py --finding-id $(ID) \
		--decision $(DECISION) --by "$(BY)" \
		$(if $(RATIONALE),--rationale "$(RATIONALE)",)

metrics:
	@python3 scripts/metrics.py

goldenset:
	@python3 goldenset/run_goldenset.py --label "$(LABEL)" --strict

import:
	@test -n "$(ENGAGEMENT)" || (echo "Set ENGAGEMENT=<id>" && exit 1)
	@python3 scripts/import_defectdojo.py --engagement $(ENGAGEMENT)

check-scope:
	@python3 scripts/check_scope.py --list

check-template:
	@python3 scripts/check_template.py

test:
	@python3 -m unittest discover -s tests -t . -v

clean:
	rm -rf findings/packets findings/reviewed.sarif
	@echo "Kept: verdicts, challenges, triage-log.csv"
