# Acceptable use

TeamLab is a constrained research and training system, not a production data platform.

## Approved

- Synthetic data, or data the deployment owner has approved in writing for this use.
- TeamLab's own roles and tools, run through the CLI by an operator on a host they control.
- The read-only monitoring API on loopback.

## Prohibited

- Real credentials, customer data or secrets in inputs, notes, `--reason` or `--note` text. Model-readable inputs are treated as untrusted and may be sent to the model provider in live mode.
- Adding a host-shell tool, or any tool that reaches the host, to make a demo more capable. Source execution is only in disposable OpenShell microVMs.
- Exposing the monitoring API, the control plane or the controller to a public network. Do not run untrusted Python files next to it.
- Editing or re-signing shipped configs without review (see [emergency-change.md](emergency-change.md)).
- Using the model keys, or any provider key, outside the credential store or process environment.

## Approval of new agent deployments

A new agent role, tool, workflow or data source needs written approval from the deployment owner before it runs. The request states the data, the tools, the budget and the profile thresholds; the change to a signed config is reviewed by a second person and re-signed. Operators may not approve their own deployments.

## Shadow AI

Do not run agents, scripts or model calls against TeamLab data outside TeamLab's gateway: no pasting its inputs, outputs or audit logs into unapproved chat tools or personal accounts. Found one? Report it to the deployment owner; if a key or real data was exposed, treat it as an incident ([incident-response.md](incident-response.md)).
