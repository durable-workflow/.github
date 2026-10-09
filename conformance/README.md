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

The [SDK coverage inventory](sdk-coverage.md) identifies actual runtime
directions, language-specific boundaries and remaining executable gaps for
each public experiment.

| Experiment | Published-artifact runner |
| --- | --- |
| Activities | `durable-workflow/server`: `scripts/conformance/activities-published-artifacts.sh`; `durable-workflow/sample-app`: [`scripts/sdk-activity-recovery.sh`](https://github.com/durable-workflow/sample-app/blob/main/polyglot/activities/README.md) (all nine PHP/Python/Rust SDK directions with retry, worker loss, total deadline expiry, retry exhaustion, application progress heartbeat expiry and stale claim refusal); its separate `--external-effects` mode checks idempotent downstream recovery after activity-worker SIGKILL in all nine directions |
| Child workflows | `durable-workflow/server`: `scripts/conformance/child-workflows-published-artifacts.sh`; `durable-workflow/sample-app`: [`scripts/sdk-children.sh`](https://github.com/durable-workflow/sample-app/blob/main/polyglot/child-workflows/README.md) (nine SDK completion directions, five Rust-involving failure/recovery/cancellation directions) |
| Cloud | Private `durable-workflow/cloud`: `scripts/conformance/run-managed-runtime.sh` using an isolated conformance namespace |
| Heartbeats | `durable-workflow/server`: the PHP, Python, and Rust `heartbeats-*-published-artifacts.sh` runners |
| Migration | `durable-workflow/server`: `scripts/conformance/migration-published-artifacts.sh` |
| Namespaces | `durable-workflow/server`: `scripts/conformance/namespaces-published-artifacts.sh`; `durable-workflow/sample-app`: [`scripts/sdk-namespaces.sh`](https://github.com/durable-workflow/sample-app/blob/main/polyglot/namespaces/README.md) (Rust namespace-bound clients/workers, denied cross-namespace operations and cold recovery) |
| Nexus | `durable-workflow/server`: `scripts/conformance/nexus-published-artifacts.sh` (supported PHP/Python caller-service directions) |
| Polyglot | `durable-workflow/sample-app`: `scripts/polyglot.sh` |
| Principal attribution | `durable-workflow/server`: `scripts/conformance/principal-attribution-published-artifacts.sh`; `durable-workflow/sample-app`: [`scripts/sdk-namespaces.sh`](https://github.com/durable-workflow/sample-app/blob/main/polyglot/namespaces/README.md) (Rust named and anonymous actors, runtime credential rotation, start/signal/completion/query/failure/terminal-cancellation attribution, forged metadata refusal, cold recovery, CLI JSON/human history and Waterline remote selected-run API); [`scripts/sdk-children.sh`](https://github.com/durable-workflow/sample-app/blob/main/polyglot/child-workflows/README.md) (legacy token requester through Rust-involving cooperative propagation, duplicate requests and cold cleanup replay under forged metadata) |
| Replay | `durable-workflow/server`: `scripts/conformance/replay-published-artifacts.sh` |
| Sagas | `durable-workflow/server`: `scripts/conformance/sagas-published-artifacts.sh` (PHP/Python matrix); `durable-workflow/sample-app`: [`polyglot/sagas/`](https://github.com/durable-workflow/sample-app/blob/main/polyglot/sagas/README.md) (five Rust-involving workflow/compensation directions) |
| Schedules | `durable-workflow/server`: `scripts/conformance/schedules-published-artifacts.sh` (PHP/Python matrix); `durable-workflow/sample-app`: [`polyglot/schedules/`](https://github.com/durable-workflow/sample-app/blob/main/polyglot/schedules/README.md) (PHP- and Python-created schedules, Rust worker) |
| SDK matrix | `durable-workflow/server`: PHP and Python published-artifact runners; `durable-workflow/sample-app`: `scripts/playground rust` |
| Search attributes | `durable-workflow/server`: `scripts/conformance/search-attributes-published-artifacts.sh`; `durable-workflow/sample-app`: [`scripts/sdk-search-attributes.sh`](https://github.com/durable-workflow/sample-app/blob/main/polyglot/search-attributes/README.md) (Rust typed authoring, PHP/Python visibility observers and cold worker replay) |
| Signals and queries | `durable-workflow/server`: `scripts/conformance/signals-queries-published-artifacts.sh` |
| Timers | `durable-workflow/server`: `scripts/conformance/timers-published-artifacts.sh` (embedded PHP); `durable-workflow/sample-app`: `scripts/sdk-timers.sh` (PHP/Python/Rust SDK workers) |
| Worker versioning | `durable-workflow/server`: `scripts/conformance/worker-versioning-published-artifacts.sh` with `DW_RUST_SDK_VERSION` for the managed Rust shard, or [`worker-versioning-rust-host-published-artifacts.sh`](https://github.com/durable-workflow/server/blob/main/scripts/conformance/worker-versioning.md) for its focused isolated stack and four Rust/PHP and Rust/Python build-cohort directions |
| Workflow lifecycle | `durable-workflow/server`: `scripts/conformance/workflow-lifecycle-published-artifacts.sh` |
| Workflow updates | `durable-workflow/server`: `scripts/conformance/workflow-updates-published-artifacts.sh`; `durable-workflow/sample-app`: [`scripts/sdk-updates.sh`](https://github.com/durable-workflow/sample-app/blob/main/polyglot/updates/README.md) (nine live SDK client/handler directions) |

Each runner documents its required exact-version environment variables and
result filename in `--help`. Use a unique result directory and isolated Docker
project for every run.

Sample App commands resolve their exact tuple with
`scripts/resolve-current-artifacts.sh`. That resolver requires Node.js in
addition to the Docker Compose and command-specific tools listed in each example.

## Operator experience

The [self-hosted operator diagnosis drill](operator-diagnosis.md) covers absent
workers, queue mismatches, expired leases, failed activities, backend interruption
and storage pressure. It records what an operator can observe and which recovery
actions work. Report its scope separately from the stable protocol experiments.

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
local Server and checks their results and persisted lifecycle events. Its
`scripts/sdk-children.sh` command also checks the five Rust-involving directions
for typed child failure and cold recovery: all three workers are SIGKILLed,
completion signals are acknowledged during their absence, and replacement
processes must complete the original parent/child runs once. The command checks
original child and relationship identities and matches SDK results to durable
history. Five additional Rust-involving cancellation cases use cooperative
child propagation and wait for child cleanup. Workers are killed during a
recorded child cleanup timer. Replacement must retain the original delivery,
timer, lineage and duplicate request identity, finish both runs as Cancelled
within the original 30-second budget, and produce matching complete API/CLI
cascade views. Report the executed scenarios and exact tuple separately;
these results do not add Rust cells to the Server runner.
The ordinary Rust authored-workflow playground does not prove
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
artifacts. The separate
[Sample App SDK timer experiment](https://github.com/durable-workflow/sample-app/blob/main/polyglot/timers/README.md)
executes actual PHP, Python and Rust timer workflows. It checks completion,
worker SIGKILL with timer fire during absence and cold replay, Server restart
across the deadline, and cooperative cancellation followed beyond the original
timer due time. Each cell checks persisted history and public status. Report
its twelve scenario outcomes separately. Concurrent timer groups and
timer-bearing application upgrades remain outside that focused experiment.

The [Sample App Rust search-attribute experiment](https://github.com/durable-workflow/sample-app/blob/main/polyglot/search-attributes/README.md)
authors all seven types through the published Rust workflow API. PHP and Python
clients verify selected-run values and server-side equality, integer/float
range, boolean, list membership and datetime queries. Values include the
Server boundary's UTF-8 byte limits, an integer beyond JavaScript's exact range
and microsecond datetime precision. After physical SIGKILL of the parked Rust
worker, a signal is acknowledged during its absence. A distinct replacement
must preserve the original run, typed upsert and signal-wait history, mutate
and delete once, remove obsolete visibility matches and complete once. Rust
currently has no search-attribute schema administration, start-time metadata
or visibility-filter client API. Do not invent Rust client permutations using
raw HTTP. This separate command does not add a Rust shard to Server's runner
or qualify Waterline, namespace isolation, load latency, continuation
inheritance or application-code upgrades.

The [Sample App SDK update experiment](https://github.com/durable-workflow/sample-app/blob/main/polyglot/updates/README.md)
executes all nine PHP/Python/Rust client-to-handler directions, including
increments whose returned intermediate state matches persisted update history.
Queries inspect accumulated state without adding workflow history. After
SIGKILL of all three workers, updates accepted during their absence must apply
once in fresh processes, preserve their original identities and recover the
prior state. Repeated completed requests must return their original results,
while queries and final workflow results retain the latest accumulated state.
The command also checks Rust workflow input and committed signal snapshots,
typed failure diagnostics and validator capability refusal. PHP and Rust
handlers reconstruct prior applied updates and apply the current request before
Server commits its completion. Python uses bound instance methods. Report the
actual outcomes with the frozen published tuple. Handler external effects and
additional update ordering races require their own scenarios.

The focused Server worker-versioning Action runs seven Rust routing/recovery cases
and all four mixed Rust/PHP and Rust/Python build-cohort directions. For the
Docker host command, select exact Server/Rust versions and an immutable image,
then set `DW_WV_MIXED_COHORTS=1`, `DW_PHP_SDK_VERSION` and
`DW_PYTHON_SDK_VERSION`. Follow the linked Server instructions for prerequisites,
observations and cleanup. The mixed cases hold the compatible worker while its
incompatible peer polls, then complete both original runs after promotion.
Each must retain its build, recorded result and single durable completion.
The Rust drain case also checks queued work while its build is drained, normal
SDK loop exit, visible worker absence after resume and a fresh compatible worker
recovering the original signal and recorded result. Resume permits routing again,
but an exited worker still needs to be restarted.

The Rust definition-registration case embeds the actual original and changed
handler sources using the SDK. It checks precise rejection of changed or missing
source identity under an active worker ID, preservation of the original
registration, and public conflict visibility when a new worker ID advertises
changed code under the same build. That peer must leave the original queued task
and history untouched. An unchanged cold replacement recovers the original run
after SIGKILL, while a positive control executes the changed waits and result
under its own build. Upgrading the Rust crate within a running cohort still needs
separate qualification through the same focused command: set
`DW_RUST_SDK_PREVIOUS_VERSION` to an exact distinct registry version. The focused
Action selects this eighth Rust case by default. Identical application source
must compile against both registry crates, with checksums and distinct executable
hashes. The older SDK starts an unversioned run. After worker SIGKILL and a signal
queued during absence, a fresh newer-SDK worker retains the original source
identity and run. A second SIGKILL and cold replacement completes it, and the
older SDK client reads the original result. History prefixes, both signal
deliveries, one recorded effect and one completion must survive. Qualification
applies to the selected SDK pair and these durable operations. Application changes
and adding build IDs to existing histories need separate cases.

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
