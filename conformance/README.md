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
| Cloud | Private `durable-workflow/cloud`: `scripts/conformance/run-managed-runtime.sh` using an isolated conformance namespace |
| Heartbeats | `durable-workflow/server`: the PHP, Python, and Rust `heartbeats-*-published-artifacts.sh` runners |
| Migration | `durable-workflow/server`: `scripts/conformance/migration-published-artifacts.sh` |
| Namespaces | `durable-workflow/server`: `scripts/conformance/namespaces-published-artifacts.sh` |
| Polyglot | `durable-workflow/sample-app`: `scripts/polyglot-validation.sh` |
| Replay | `durable-workflow/server`: `scripts/conformance/replay-published-artifacts.sh` |
| Sagas | `durable-workflow/server`: `scripts/conformance/sagas-published-artifacts.sh` (PHP/Python matrix); `durable-workflow/sample-app`: [`polyglot/sagas/`](https://github.com/durable-workflow/sample-app/blob/main/polyglot/sagas/README.md) (five Rust-involving workflow/compensation directions) |
| Schedules | `durable-workflow/server`: `scripts/conformance/schedules-published-artifacts.sh` (PHP/Python matrix); `durable-workflow/sample-app`: [`polyglot/schedules/`](https://github.com/durable-workflow/sample-app/blob/main/polyglot/schedules/README.md) (PHP- and Python-created schedules, Rust worker) |
| SDK matrix | `durable-workflow/server`: PHP and Python published-artifact runners; `durable-workflow/sample-app`: `scripts/playground rust` |
| Search attributes | `durable-workflow/server`: `scripts/conformance/search-attributes-published-artifacts.sh` |
| Signals and queries | `durable-workflow/server`: `scripts/conformance/signals-queries-published-artifacts.sh` |
| Timers | `durable-workflow/server`: `scripts/conformance/timers-published-artifacts.sh` (embedded PHP workflow scenarios) |
| Worker versioning | `durable-workflow/server`: `scripts/conformance/worker-versioning-published-artifacts.sh` |
| Workflow lifecycle | `durable-workflow/server`: `scripts/conformance/workflow-lifecycle-published-artifacts.sh` |
| Workflow updates | `durable-workflow/server`: `scripts/conformance/workflow-updates-published-artifacts.sh` |

Each runner documents its required exact-version environment variables and
result filename in `--help`. Use a unique result directory and isolated Docker
project for every run.

## Evidence scope

A pinned or successfully installed SDK is not evidence that its worker executed
an experiment. For each claimed language or cross-language direction, check the
scenario-level result for the actual caller/parent and worker/child runtime,
outcome, and history. A tuple-wide `pass` does not fill in an unexecuted cell.

In particular, the current
[child-workflow scenario manifest](https://github.com/durable-workflow/server/blob/main/static/platform-conformance/child-workflow-runtime-scenarios.json)
requires a PHP/Python parent-child runtime matrix. Its Rust crate pin verifies
artifact resolution, not Rust child execution. Do not report that runner as
PHP/Python/Rust child-workflow coverage. The separate
[Sample App child-workflow matrix](https://github.com/durable-workflow/sample-app/blob/main/polyglot/child-workflows/README.md)
starts all nine PHP/Python/Rust parent-child directions against a published
local Server and checks their results and persisted lifecycle events. Report
its outcome and exact tuple separately; it does not add Rust cells to the
Server runner. The ordinary Rust authored-workflow playground does not prove
cross-language child-workflow behavior by itself.

The current
[saga scenario manifest](https://github.com/durable-workflow/server/blob/main/static/platform-conformance/saga-runtime-scenarios.json)
and published-artifact runner exercise PHP and Python workflow/compensation
directions. They do not execute Rust saga or compensation handlers. The separate
[Sample App Rust saga experiment](https://github.com/durable-workflow/sample-app/blob/main/polyglot/sagas/README.md)
executes five Rust-involving directions: Rust workflows with Rust, PHP, or
Python compensation, and PHP or Python workflows with Rust compensation. It
checks reverse-order compensation and persisted scheduled, failed, and
completed activities against a published local Server. Its opt-in failure mode
checks that a failed `undo-second` produces typed `SagaCompensationFailed`,
preserves both activity failures, and never schedules `undo-first`.
Report each outcome and exact tuple separately. Its stop/signal/restart check
covers the five Rust-involving directions after the first reserve. These
examples do not add Rust scenarios to the Server runner or cover duplicate
delivery, external side-effect recovery, or process loss during compensation.
Installing the Rust crate or passing a Rust playground is not saga evidence.

The current
[schedule scenario manifest](https://github.com/durable-workflow/server/blob/main/static/platform-conformance/schedules-runtime-scenarios.json)
and published-artifact runner require PHP/Python schedule creators and workflow
runtimes, plus the official CLI. They do not execute a schedule that dispatches
to a Rust worker. The Rust SDK currently has no schedule client API, so a Rust
schedule-creator cell is not a supported permutation. The separate
[Sample App schedule experiments](https://github.com/durable-workflow/sample-app/blob/main/polyglot/schedules/README.md)
create automatic interval schedules with the published PHP and Python SDKs,
then check the published Rust worker's result, linked schedule audit event,
and workflow history. Report each direction's outcome and exact tuple
separately; these examples do not add a Rust shard to the Server runner or
prove cadence, restart, or failure recovery behavior.

The current
[timer scenario manifest](https://github.com/durable-workflow/server/blob/main/static/platform-conformance/timer-runtime-scenarios.json)
and published-artifact runner execute timer behavior in the Server image with
an embedded PHP workflow. The Python SDK artifact pin does not mean a Python
worker ran these scenarios; the runner does not require the PHP or Rust SDK
artifacts. Published PHP, Python, and Rust SDKs expose durable timer APIs, but
their service-mode workflow timer paths are not covered by this runner. Record
those paths as unexecuted until separate published-artifact evidence checks
timer completion, replay/restart, cancellation, and history for each relevant
workflow runtime. A passing embedded timer scenario does not fill those SDK
cells.

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
