# Conformance

This file is the Durable Workflow 2.0 release-critical experiment runbook. It
is deliberately a checklist, not an orchestration system.

Ordinary repository CI and release work runs in GitHub Actions. Experiments
that need Docker restarts, process loss, or private Cloud access run locally by
a maintainer from the published-artifact command below. Every result is recorded
as a concise update on the active release issue so the tuple, outcome, and next
action remain visible without creating a second backlog.

## Stable 2.0 tier

Run every row against the same exact published Workflow, Waterline, Server,
CLI, PHP SDK, Python SDK, and Rust SDK tuple.

| Experiment | Published-artifact runner |
| --- | --- |
| Activities | `durable-workflow/server`: `scripts/conformance/activities-published-artifacts.sh` |
| Child workflows | `durable-workflow/server`: `scripts/conformance/child-workflows-published-artifacts.sh` |
| Cloud | Private `durable-workflow/cloud` `conformance.yml` workflow using an isolated conformance namespace |
| Heartbeats | `durable-workflow/server`: the PHP, Python, and Rust `heartbeats-*-published-artifacts.sh` runners |
| Migration | `durable-workflow/server`: `scripts/conformance/migration-published-artifacts.sh` |
| Namespaces | `durable-workflow/server`: `scripts/conformance/namespaces-published-artifacts.sh` |
| Polyglot | `durable-workflow/sample-app`: `scripts/polyglot-validation.sh` |
| Replay | `durable-workflow/server`: `scripts/conformance/replay-published-artifacts.sh` |
| Schedules | `durable-workflow/server`: `scripts/conformance/schedules-published-artifacts.sh` |
| SDK matrix | `durable-workflow/server`: PHP and Python published-artifact runners; `durable-workflow/sample-app`: `scripts/playground rust` |
| Search attributes | `durable-workflow/server`: `scripts/conformance/search-attributes-published-artifacts.sh` |
| Signals and queries | `durable-workflow/server`: `scripts/conformance/signals-queries-published-artifacts.sh` |
| Timers | `durable-workflow/server`: `scripts/conformance/timers-published-artifacts.sh` |
| Worker versioning | `durable-workflow/server`: `scripts/conformance/worker-versioning-published-artifacts.sh` |
| Workflow lifecycle | `durable-workflow/server`: `scripts/conformance/workflow-lifecycle-published-artifacts.sh` |
| Workflow updates | `durable-workflow/server`: `scripts/conformance/workflow-updates-published-artifacts.sh` |

Each runner documents its required exact-version environment variables and
result filename in `--help`. Use a unique result directory and isolated Docker
project for every run.

## Report a run

Add one comment to the active stable-release issue and update its fixed-tier
checklist. Include:

- the experiment and outcome;
- the exact seven-component tuple;
- the runner repository and full commit SHA;
- UTC start and finish timestamps;
- the command with secrets removed; and
- a concise scenario pass/fail summary and links to any product defects or
  runner corrections found by the run.

Do not commit per-run result payloads, logs, screenshots, or generated evidence
directories to this repository. The active release issue is the durable release
record. GitHub Actions may retain bounded-lifetime artifacts when raw output is
useful for diagnosis; locally executed runs keep raw output only until the issue
summary has been verified. Stable-release authority depends on the exact tuple,
runner revision, scenario outcomes, findings, and linked fixes, not permanent
storage of every raw execution detail.

Do not open and immediately close a separate issue for each run. Open a product
issue only when the experiment finds an actual product defect. Open a runner
issue only when the runner itself needs a durable code change.

Use one of four outcomes: `pass`, `product-fail`, `runner-blocked`, or
`out-of-scope`. A runner failure is not a product failure, but missing, stale,
partial, and runner-blocked evidence cannot authorize stable 2.0.

When an experiment finds a defect, link the product issue, fix PR, regression
fixture, replacement published artifact, and confirming run. Historical
aggregate pass rate is never release authority.
