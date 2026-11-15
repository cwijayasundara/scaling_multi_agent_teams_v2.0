PYTHON ?= .venv/bin/python
export PYTHONPATH := src

.PHONY: test demo replay attack benchmark
test:
	$(PYTHON) -m pytest -q
demo:
	$(PYTHON) -m teamlab run --root runs/scripted
replay:
	$(PYTHON) -m teamlab run --root runs/sdk --mode sdk-replay --injection
attack:
	$(PYTHON) -m teamlab attack-demo --root runs/attack
benchmark:
	$(PYTHON) -m teamlab benchmark --mode sdk-replay

.PHONY: collaborate collaboration-benchmark
collaborate:
	$(PYTHON) -m teamlab run --root runs/collaboration --mode sdk-replay --workflow collaborative --injection
collaboration-benchmark:
	$(PYTHON) -m teamlab collaboration-benchmark

# Setup and services. See README "Scripts".
ROOT ?= runs/openshell
.PHONY: setup qualify dashboard authored
setup:
	scripts/setup.sh
qualify:
	$(PYTHON) -m teamlab qualify-host
dashboard:
	$(PYTHON) scripts/dashboard.py --root $(ROOT)
authored:
	@test -n "$(BUDGET)" -a -n "$(INPUT_PRICE)" -a -n "$(OUTPUT_PRICE)" || { echo 'usage: make authored BUDGET=usd INPUT_PRICE=usd_per_million OUTPUT_PRICE=usd_per_million [ARGS="--workers 2"]'; exit 2; }
	scripts/run-authored.sh --root $(ROOT) --budget-usd $(BUDGET) --input-usd-per-million $(INPUT_PRICE) --output-usd-per-million $(OUTPUT_PRICE) $(ARGS)
