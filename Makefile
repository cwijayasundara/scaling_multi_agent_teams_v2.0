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
