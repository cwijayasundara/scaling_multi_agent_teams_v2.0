# Runbook: incident response

Bookkeeping is automated: TeamLab detects, records, triages and measures. Decisions are human: only an operator stops a team for good, restarts, acknowledges, discloses, or raises limits. Triage is a recommendation (`decision_owner: human`), never an action.

Targets: detect in under 1 hour (the eBook's bar); acknowledge within `SLO_SECONDS` = 3600 s of detection (`src/teamlab/metrics.py`). An alert open past that counts as an SLO breach.

Practice it: `teamlab tabletop` (see [tabletop.md](tabletop.md)); tests `tests/test_metrics.py::test_ack_and_metrics_cli`, `tests/test_triage.py::test_triage_subcommand_prints_dispositions`.

## 1. Alert: see what is open

```bash
teamlab metrics --root runs/demo --run-id RUN_ID
```

Read `open_alerts`, `oldest_open_age_s` and `slo_breaches`. Omit `--run-id` for the whole root.

## 2. Triage: read the recorded first pass

```bash
teamlab triage --root runs/demo --run-id RUN_ID
```

Runs after every stop or pause automatically; this command is idempotent and never changes run state. Each disposition gives a classification, recommended action, confidence and evidence event numbers. `--model` adds a tool-free model view and needs a spend budget; the rules stand for deterministic blocks.

## 3. Evidence: verdicts, states, trace

- `action.denied` events carry the `verdicts` list. The last non-`ALLOW` verdict names the monitor (`output-filter-v1`, `deterministic-rules-v1`, behaviour profile, or a `luna-*` classifier) and its rule.
- Agent states (`ACTIVE`, `RESTRICTED`, `QUARANTINED`) and strikes are in the monitoring snapshot, `GET /runs/RUN_ID/snapshot` (read-only, loopback, bearer token).
- Follow one operation back to its root:

```bash
teamlab trace --root runs/demo --run-id RUN_ID --span SPAN_ID
```

## 4. Decide and record

| Alert kind (triage mapping) | Triage says | Who decides | Evidence required before acting | Decision |
|---|---|---|---|---|
| `action.denied` or stop from a deterministic monitor: capability violation, invalid signature, output filter, deterministic rules | likely true positive, `keep_stopped`, high | Operator on call | The verdict (monitor, rule) and the trace of the denied span | Leave stopped; investigate the input and role; restart only after the cause is fixed |
| Behaviour-profile breach (`CONTAIN`) or `luna-*` PAUSE | needs human, `escalate`, medium | Operator on call | The rule that fired, the agent's last authorized actions (evidence seqs) | Judge true or false positive; adjust a profile only through a reviewed, re-signed change |
| `agent.restricted` | needs human, `escalate`, medium | Operator on call | The strike source and the agent's recent actions | Keep, or stop the run if the strike looks like compromise |
| `agent.quarantined` | likely true positive, `escalate`, medium | Operator on call; deployment owner if disclosure is possible | The strike history and the quarantine alert; there is no un-quarantine | Accept the team continuing without that agent, or stop; `restart` for fresh agents |
| `credential.rejected` | likely true positive, `escalate`, medium | Operator on call; deployment owner for key handling | Whether the token was expired or replayed; the quarantine that followed | Treat as possible credential theft: stop, then [emergency-change.md](emergency-change.md) |
| `run.stopped` or `run.paused` because the monitor was unavailable, or a `luna-*` monitor returned PAUSE | needs human, `escalate`, medium | Operator on call | The stop reason (`monitor unavailable` or `luna-…: PAUSE on …`) and the action that was held | Check the monitor and provider, judge the held action, then restart clean; do not raise limits to get past it |
| `run.stopped` or `run.paused` for a budget, inference or deadline limit | operational, `raise_limits`, high | Operator | The configured limit and the spend recorded | Raise the limit deliberately, or restart clean |
| `run.stopped` by the operator | operational, `restart_clean`, low | Operator who stopped it | The stop reason they wrote | Restart clean when the reason is resolved |
| `run.paused`: agent quarantined, or every worker quarantined | needs human, `escalate`, medium | Operator on call | The quarantine alerts; whether the work can be reassigned | Restart clean with a reviewed checkpoint, or abandon |
| Anything unrecognized | needs human, `escalate`, low | Operator on call | The raw alert and context events | Escalate; do not guess |

## 5. Act

Acknowledge (recorded with your OS user name, advisory not authenticated):

```bash
teamlab ack --root runs/demo --run-id RUN_ID --all-open --note "reviewed: capability denial, input corrected"
teamlab ack --root runs/demo --run-id RUN_ID --alert-seq 7
```

Stop the whole team (a provider call already in flight may still finish and be billed):

```bash
teamlab stop --root runs/demo --run RUN_ID --reason "suspected credential misuse"
```

Restart creates a clean new run with fresh agents and credentials from the captured input. It does not repair a broken task. Fix the cause first; the same input may stop again.

```bash
teamlab restart --root runs/demo --run RUN_ID --reason "input corrected after review"
```

Do not paste secrets into `--note` or `--reason`; both are recorded in the audit trail.
