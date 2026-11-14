"""Local overhead measurements, explicitly excluding live LLM performance."""

import json
import statistics
import time
from pathlib import Path

from .controller import Controller
from .fixture import generate, read_records
from .grader import reference


def benchmark(root: Path, output: Path, rows: int, seeds: int, worker_counts: list[int], mode: str):
    if mode not in ("scripted", "sdk-replay") or not 1 <= seeds <= 10:
        raise ValueError("benchmark requires 1..10 seeds and an offline mode")
    measurements = []
    for seed in range(seeds):
        source = root / f"seed-{seed}.csv"
        generate(source, rows=rows, seed=seed, injection=True)
        records, input_hash = read_records(source)
        started = time.perf_counter()
        expected = reference(records)
        baseline = time.perf_counter() - started
        measurements.append({"seed": seed, "workers": 0, "mode": "reference-sql", "elapsed_seconds": baseline,
            "input_hash": input_hash, "correct": True, "model_calls": 0})
        for workers in worker_counts:
            c = Controller(root / f"seed-{seed}-workers-{workers}-{mode}", source, workers=workers, mode=mode)
            started = time.perf_counter()
            if mode == "scripted":
                c.run_scripted()
            else:
                from .agents import AgentTeam
                AgentTeam(c, replay=True).run()
            elapsed = time.perf_counter() - started
            correct = c.candidate() == expected and c.store.run(c.run_id)["state"] == "COMPLETED"
            run = c.store.run(c.run_id)
            measurements.append({"seed": seed, "workers": workers, "mode": mode, "elapsed_seconds": elapsed,
                "input_hash": input_hash, "correct": correct, "model_calls": run["model_calls"], "tool_calls": run["calls"]})
    summary = []
    for workers in [0, *worker_counts]:
        entries = [m for m in measurements if m["workers"] == workers]
        summary.append({"workers": workers, "mode": entries[0]["mode"], "runs": len(entries),
            "median_seconds": statistics.median(m["elapsed_seconds"] for m in entries),
            "all_correct": all(m["correct"] for m in entries)})
    result = {"profile": "local-trusted-tools", "rows_before_defects": rows, "seeds": seeds,
        "disclaimer": "Offline overhead experiment, not LLM intelligence, Luna latency, microVM isolation, or useful multi-agent speedup.",
        "summary": summary, "measurements": measurements}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n")
    return result

