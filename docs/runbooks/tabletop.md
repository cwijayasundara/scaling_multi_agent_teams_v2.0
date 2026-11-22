# Runbook: tabletop exercise

The drill runs five synthetic attack incidents concurrently, each in its own root, then (optionally) acknowledges every alert so the human-response numbers are measured. TeamLab only; synthetic data, no network, no host shell.

```bash
teamlab tabletop --root runs/tabletop --ack-after 1
```

Only scenarios that create their own run and touch nothing outside their root can be incidents. `tampered-policy-config` and `plane-untrusted-client` are marked `isolation: process-wide` in `src/teamlab/threats.json` (they patch the process environment or the profile path), so `run_tabletop` refuses them before any incident starts; run them alone with `teamlab attack-suite --include-slow`.

`--ack-after SECONDS` stands in for the human; omit it to see every alert triaged and open. For a real exercise, leave it out and acknowledge by hand with `teamlab ack` (see [incident-response.md](incident-response.md)).

## What to watch

- Fleet dwell: `dwell_p50_s` and `dwell_max_s`, measured from alert detection to acknowledgement.
- Coverage: `triage_coverage` and `human_coverage` should both be 1.0.
- `slo_breaches` should be 0 (SLO is 3600 s) and `open_alerts` 0 when the drill ends.
- Each incident's `containment`: `team` (run stopped) or `agent` (one agent contained, team running).

## Last measured results

Measured 2026-11-22 with `teamlab tabletop --root runs/tabletop --ack-after 1`, scripted and offline:

| Measure | Result |
|---|---|
| Incidents | 5 |
| Alerts | 11 |
| Triage coverage | 1.0 |
| Human coverage | 1.0 |
| Dwell p50 | 1.03 s (1.02 s in the first run) |
| Dwell max | 1.09 s (1.07 s in the first run) |
| SLO breaches | 0 |
| Elapsed | 1.13 s (1.11 s in the first run) |

The dwell is dominated by the 1 s `--ack-after` delay, so it shows that bookkeeping adds almost nothing; it does not measure how fast a person responds. A real exercise will be slower; compare it with the 3600 s SLO.

## Debrief (five questions)

1. Which alert did we notice first, and how did we notice it?
2. Did triage recommend the action we took? Where did we overrule it, and why?
3. What evidence did we wish we had, and was it in the trace?
4. Who made each decision, and did they have the authority in [emergency-change.md](emergency-change.md)?
5. What one change (runbook, threshold, test) would shorten the next response?

Record the date, the numbers above and the answers.
