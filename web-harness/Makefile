# Cernis benchmark — make targets
#
# All real logic lives in `benchmark/{build_splits,evaluate,leaderboard,
# runner_container}.py`. This Makefile is ergonomics on top: a one-line
# `make eval SUBMISSION=…` instead of remembering the full python -m
# incantation.

PYTHON   ?= python3
DATA     ?= data
SEED     ?= 0
SPLITS   ?= benchmark/splits/v1
FP_BUDGET ?= 1.0
SPLIT    ?= public_test
LEADERBOARD ?= data/reports/leaderboard.jsonl
DASHBOARD_PORT ?= 8095

.PHONY: help build-splits eval eval-heldout eval-container leaderboard smoke-bench smoke-bench-4 dashboard smoke-dashboard

help:
	@echo "Cernis benchmark targets:"
	@echo "  make build-splits                          # build splits/v1 from data/"
	@echo "  make eval SUBMISSION=<path>                # eval on public_test"
	@echo "  make eval SUBMISSION=<path> SPLIT=heldout  # eval on hidden splits"
	@echo "  make eval-heldout SUBMISSION=<path>        # shortcut for the above"
	@echo "  make eval-container SUBMISSION=<path> SUBMISSION_IMAGE=<tag>"
	@echo "                                             # eval via docker --network none"
	@echo "  make leaderboard                           # regenerate leaderboard.md"
	@echo "  make smoke-bench                           # run the phase-bench-2 smoke"
	@echo "  make smoke-bench-4                         # run the phase-bench-4 smoke"
	@echo "  make dashboard                             # serve the live dashboard on 127.0.0.1:8095"
	@echo "  make smoke-dashboard                       # run the phase-15 smoke"
	@echo ""
	@echo "Overrides: DATA=$(DATA)  SEED=$(SEED)  SPLITS=$(SPLITS)  FP_BUDGET=$(FP_BUDGET)"
	@echo "Leaderboard: LEADERBOARD=$(LEADERBOARD)"
	@echo "Dashboard: DASHBOARD_PORT=$(DASHBOARD_PORT)"

build-splits:
	$(PYTHON) -m benchmark.build_splits \
		--data $(DATA) --out $(SPLITS) --seed $(SEED)

eval:
	@if [ -z "$(SUBMISSION)" ]; then \
		echo "usage: make eval SUBMISSION=<path> [SPLIT=public_test|heldout] [SEED=0] [LEADERBOARD=<path>]"; \
		exit 2; \
	fi
	$(PYTHON) -m benchmark.evaluate \
		--submission $(SUBMISSION) \
		--split $(SPLIT) \
		--seed $(SEED) \
		--splits-dir $(SPLITS) \
		--data $(DATA) \
		--fp-per-hour-budget $(FP_BUDGET) \
		$(if $(LEADERBOARD),--leaderboard $(LEADERBOARD),)

eval-heldout:
	$(MAKE) eval SUBMISSION=$(SUBMISSION) SPLIT=heldout SEED=$(SEED)

eval-container:
	@if [ -z "$(SUBMISSION)" ] || [ -z "$(SUBMISSION_IMAGE)" ]; then \
		echo "usage: make eval-container SUBMISSION=<path> SUBMISSION_IMAGE=<docker tag>"; \
		exit 2; \
	fi
	$(PYTHON) -m benchmark.evaluate \
		--submission $(SUBMISSION) \
		--container-image $(SUBMISSION_IMAGE) \
		--split $(SPLIT) \
		--seed $(SEED) \
		--splits-dir $(SPLITS) \
		--data $(DATA) \
		--fp-per-hour-budget $(FP_BUDGET) \
		$(if $(LEADERBOARD),--leaderboard $(LEADERBOARD),)

leaderboard:
	$(PYTHON) -m benchmark.leaderboard --leaderboard $(LEADERBOARD)

smoke-bench:
	$(PYTHON) tests/phase_bench_2_smoke.py

smoke-bench-4:
	$(PYTHON) tests/phase_bench_4_smoke.py

dashboard:
	$(PYTHON) -m dashboard.app --data-dir $(DATA) --port $(DASHBOARD_PORT)

smoke-dashboard:
	$(PYTHON) tests/phase15_smoke.py
