# Cernis benchmark — make targets
#
# All real logic lives in `benchmark/{build_splits,evaluate}.py`. This
# Makefile is ergonomics on top: a one-line `make eval SUBMISSION=…`
# instead of remembering the full python -m incantation.

PYTHON   ?= python3
DATA     ?= data
SEED     ?= 0
SPLITS   ?= benchmark/splits/v1
FP_BUDGET ?= 1.0
SPLIT    ?= public_test

.PHONY: help build-splits eval eval-heldout smoke-bench

help:
	@echo "Cernis benchmark targets:"
	@echo "  make build-splits                          # build splits/v1 from data/"
	@echo "  make eval SUBMISSION=<path>                # eval on public_test"
	@echo "  make eval SUBMISSION=<path> SPLIT=heldout  # eval on hidden splits"
	@echo "  make eval-heldout SUBMISSION=<path>        # shortcut for the above"
	@echo "  make smoke-bench                           # run the phase-bench-2 smoke"
	@echo ""
	@echo "Overrides: DATA=$(DATA)  SEED=$(SEED)  SPLITS=$(SPLITS)  FP_BUDGET=$(FP_BUDGET)"

build-splits:
	$(PYTHON) -m benchmark.build_splits \
		--data $(DATA) --out $(SPLITS) --seed $(SEED)

eval:
	@if [ -z "$(SUBMISSION)" ]; then \
		echo "usage: make eval SUBMISSION=<path> [SPLIT=public_test|heldout] [SEED=0]"; \
		exit 2; \
	fi
	$(PYTHON) -m benchmark.evaluate \
		--submission $(SUBMISSION) \
		--split $(SPLIT) \
		--seed $(SEED) \
		--splits-dir $(SPLITS) \
		--data $(DATA) \
		--fp-per-hour-budget $(FP_BUDGET)

eval-heldout:
	$(MAKE) eval SUBMISSION=$(SUBMISSION) SPLIT=heldout SEED=$(SEED)

smoke-bench:
	$(PYTHON) tests/phase_bench_2_smoke.py
