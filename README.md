# Secure TeamLab

An agent team (coordinator, analysts, verifier) analyses a sales CSV and reports sales, refunds and net totals per region. The agents write their own Python. That code runs only in disposable, offline OpenShell microVMs. A verifier re-runs it, and the results are checked against an independent reference.

## 1. Set up the infrastructure

Needs macOS (Apple Silicon) or Linux, Python 3.12, `uv`, Node.js and Homebrew.

```bash
make setup                                # Python, UI, OpenShell microVM gateway, sandbox check
security add-generic-password -s teamlab-openai -a teamlab -w   # macOS Keychain; prompts for the key (Linux: secret-tool store --label teamlab service teamlab-openai)
```

The Keychain is the recommended home for the provider key. A key in `.env` (copy `.env.example`) still works as a fallback but prints a warning, because a static key on disk is a known gap. The run records where the key came from in `run.started`.

`make setup` must end with `qualified`. Check the gateway at any time with `openshell status`.

## 2. Start the UI

```bash
make dashboard ROOT=runs/openshell
```

Open **http://127.0.0.1:3000** and leave it running.

## 3. Kick off the agent team

In a second terminal:

```bash
make authored BUDGET=1 INPUT_PRICE=0.10 OUTPUT_PRICE=0.50
```

This bills your model provider, up to $1. `0.10` and `0.50` are the `gpt-6-luna` prices in USD per million input and output tokens, as recorded on 14 November 2026. Update them if your rates differ. The team works on 200 synthetic sales rows. To analyse your own data, pass a CSV with the columns `event_id,order_id,region,event_type,amount_pence,timestamp_utc,note`:

```bash
make authored BUDGET=1 INPUT_PRICE=0.10 OUTPUT_PRICE=0.50 ARGS="--input path/to/sales.csv"
```

While it runs, the UI shows each agent's activity. `openshell sandbox list` shows the short-lived `tl-…` microVMs running the agents' code.

## 4. Review the output

The run prints its `run_id` first and its `artifacts` folder last. Results are in `runs/openshell/artifacts/RUN_ID/`:

| File | What to review |
|---|---|
| `answer.md` | The final report: totals per region, verified |
| `metrics.json` | The same totals as data |
| `issues.jsonl` | Every excluded row and why |
| `sources.json` | The Python each agent wrote and ran in OpenShell |
| `events.jsonl` | Full audit trail of every agent action |

In the UI, open the run to replay the timeline, inspect each agent and see the evidence checks.
