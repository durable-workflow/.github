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
| Nexus | `durable-workflow/server`: `scripts/conformance/nexus-published-artifacts.sh`; [published caller workflow](sdk-coverage.md#run-the-published-nexus-caller-cases) (PHP/Python terminal results, handled and uncaught typed failure, target/caller cancellation, cold/backend recovery, external payloads and authored authorization refusals); [Rust SDK profiles and installed-release evidence](sdk-coverage.md#run-and-interpret-rust-nexus-cases) with a separate tuple; separate embedded and API/browser/CLI consumers |
| Polyglot | `durable-workflow/sample-app`: `scripts/polyglot.sh` |
| Principal attribution | `durable-workflow/server`: `scripts/conformance/principal-attribution-published-artifacts.sh`; `durable-workflow/sample-app`: [`scripts/sdk-namespaces.sh`](https://github.com/durable-workflow/sample-app/blob/main/polyglot/namespaces/README.md) (Rust named and anonymous actors, runtime credential rotation, start/signal/completion/query/failure/terminal-cancellation attribution, forged metadata refusal, cold recovery, CLI JSON/human history and Waterline remote selected-run API); [`scripts/sdk-children.sh`](https://github.com/durable-workflow/sample-app/blob/main/polyglot/child-workflows/README.md) (legacy, runtime-token and anonymous cooperative requests through actual PHP/Python/Rust clients, duplicate identity and actor preservation, access refusals and cold cleanup replay under forged metadata) |
| Replay | `durable-workflow/server`: `scripts/conformance/replay-published-artifacts.sh` |
| Sagas | `durable-workflow/server`: `scripts/conformance/sagas-published-artifacts.sh` (PHP/Python matrix); `durable-workflow/sample-app`: [`polyglot/sagas/`](https://github.com/durable-workflow/sample-app/blob/main/polyglot/sagas/README.md) (five Rust-involving workflow/compensation directions) |
| Schedules | `durable-workflow/server`: `scripts/conformance/schedules-published-artifacts.sh` (PHP/Python matrix); `durable-workflow/sample-app`: [`polyglot/schedules/`](https://github.com/durable-workflow/sample-app/blob/main/polyglot/schedules/README.md) (PHP- and Python-created schedules, Rust worker) |
| SDK matrix | `durable-workflow/server`: PHP and Python published-artifact runners; `durable-workflow/sample-app`: `scripts/playground rust` |
| Search attributes | `durable-workflow/server`: `scripts/conformance/search-attributes-published-artifacts.sh`; `durable-workflow/sample-app`: [`scripts/sdk-search-attributes.sh`](https://github.com/durable-workflow/sample-app/blob/main/polyglot/search-attributes/README.md) (Rust typed authoring, PHP/Python visibility observers and cold worker replay) |
| Signals and queries | `durable-workflow/server`: `scripts/conformance/signals-queries-published-artifacts.sh` |
| Timers | `durable-workflow/server`: `scripts/conformance/timers-published-artifacts.sh` (embedded PHP); `durable-workflow/sample-app`: `scripts/sdk-timers.sh` (PHP/Python/Rust SDK workers) |
| Worker versioning | `durable-workflow/server`: `scripts/conformance/worker-versioning-published-artifacts.sh` with `DW_RUST_SDK_VERSION` for the managed Rust shard, or [`worker-versioning-rust-host-published-artifacts.sh`](https://github.com/durable-workflow/server/blob/main/scripts/conformance/worker-versioning.md) for its focused isolated stack and four Rust/PHP and Rust/Python build-cohort directions |
| Workflow lifecycle | `durable-workflow/server`: `scripts/conformance/workflow-lifecycle-host-published-artifacts.sh` (Docker host wrapper for the published-image result runner) |
| Workflow updates | `durable-workflow/server`: `scripts/conformance/workflow-updates-published-artifacts.sh`; `durable-workflow/sample-app`: [`scripts/sdk-updates.sh`](https://github.com/durable-workflow/sample-app/blob/main/polyglot/updates/README.md) (nine live SDK client/handler directions) |

Each runner documents its required exact-version environment variables and
result filename in `--help`. Use a unique result directory and isolated Docker
project for every run.

Sample App commands resolve their exact tuple with
`scripts/resolve-current-artifacts.sh`. That resolver requires Node.js in
addition to the Docker Compose and command-specific tools listed in each example.

For workflow lifecycle, run the host wrapper from the Server checkout with
Bash, Docker and Node.js. Set `DW_SERVER_VERSION`, `DW_RUST_SDK_VERSION`,
`DW_CLI_VERSION`, `DW_PYTHON_SDK_VERSION`, `DW_PHP_SDK_VERSION`,
`DW_WORKFLOW_PHP_VERSION` and `DW_WATERLINE_VERSION` from the selected exact
tuple. Set `DW_SERVER_IMAGE` to its immutable image digest. The wrapper starts
the isolated backend, HTTP and scheduler processes, builds the registry Rust
probe, and invokes `workflow-lifecycle-published-artifacts.sh` inside the
published Server image. Calling that inner script from a source checkout does
not execute its focused published-image runtime probes.

```sh
result_dir="$(mktemp -d "${TMPDIR:-/tmp}/dw-lifecycle.XXXXXX")"
bash scripts/conformance/workflow-lifecycle-host-published-artifacts.sh \
  --result-dir "$result_dir"
```

The wrapper removes its containers and network on normal exit or a handled
interrupt. Retain the result directory for the owning issue's evidence, then
remove that directory after recording the sanitized outcome.
Anonymous MySQL/Redis data volumes currently survive that container cleanup.
The [cleanup implementation gap](https://github.com/durable-workflow/.github/issues/122#issuecomment-6361991895)
remains open. Container and network removal alone does not establish complete
fixture cleanup.

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
The child command also runs five runtime-token and five anonymous cascades
through actual PHP, Python and Rust cancellation clients. Runtime operator
requests retain their original actor when an administrator repeats the request.
Worker-role cancellation is refused with HTTP 403. Missing authentication is
refused with HTTP 401, including Python's discovery wrapper around that response.
The separate auth-disabled phase checks the configured anonymous actor.
Both families preserve their original request identity, deadline and cleanup
history through SIGKILL and cold replacement. They require both original runs
to reach Cancelled within the initial shared 30-second budget. The same command
checks CLI and selected-run API inspection, then opens the published Waterline
image in Chromium after each cancellation batch converges. Its 45 connected
views cover parent desktop/mobile and child desktop for all five directions
through legacy-token, runtime-token and anonymous access. The actual HTTP
responses and rendered request, requester, deadline, delivery, recovery and
completed cleanup must match the original SDK/Server evidence. Browser checks
reject unhandled errors and horizontal overflow. Browser time is outside the
original cleanup budget.
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
and published-artifact runner use PHP-hosted protocol probes and the package's
timer queue jobs inside the Server image. The concurrent-deadline probe submits
timer commands directly, sorts their recorded deadlines, then drives each timer
job in that order before polling its continuation. It checks those controlled
transitions, rather than independently observing ordinary scheduler ordering or
SDK-authored concurrent waits. The Python SDK artifact pin does not mean a Python
worker ran these scenarios; the runner does not require the PHP or Rust SDK
artifacts. The separate
[Sample App SDK timer experiment](https://github.com/durable-workflow/sample-app/blob/main/polyglot/timers/README.md)
executes actual PHP, Python and Rust timer workflows. It checks completion,
worker SIGKILL with timer fire during absence and cold replay, Server restart
across the deadline, cooperative cancellation followed beyond the original
timer due time, and three concurrent deadlines in each SDK's original run.
The interruption and cancellation cases run with both single timers and
concurrent groups. It also replaces compatible business helpers while single/group
timers are pending, then checks fresh version-two runs in every SDK. Python has
four additional class-identity originals for refusal, restoration and fresh
replacement. Report the forty outcomes separately: PHP twelve, Python sixteen
and Rust twelve.

The concurrent cells use ordinary SDK all/parallel barriers and the Server's
queue worker. They preserve every scheduled identity/deadline and the common
barrier metadata through actual firing, reject early or duplicate fires, and
require one workflow completion after all three members resolve. Firing order
is recorded; a separate parent resume for each barrier member is not required.
The existing single-timer cases retain their own outcomes. Concurrent recovery
requires every member to fire while workers are absent, then one cold-replayed
completion. Concurrent Server restart crosses all original deadlines before
any fire. Concurrent cancellation requires three matching cancellations and
no fire or completion beyond the last original deadline. Resolved members keep
the original barrier metadata and scalar types, including nested group paths.
Application revision one records a version-one decision and the original timer
durations. Fresh replacement workers register revision two, which must replay
that same original decision, complete history prefix and timers before one
completion. Fresh runs then select version two and use the changed durations.
Both authored helpers ship in the scenario workers; the command chooses the
helper before process startup while keeping the registered wrapper unchanged.
The runner stops the old processes, retires only captured owned registrations
with zero lease recovery, and waits for the actual new roster before admission.
Python's separate class cases require a worker-sourced definition fingerprint:
the different class leaves the original unclaimed after its timers fire, then
a cold original-class worker completes it without rebinding history. Fresh runs
use the new class. This preserves the published definition fence, rather than
authorizing incompatible class adoption. SDK package upgrades, build-ID rollouts
and other class-evolution mechanisms need separate qualification. These forty
cases start from code that already records its version marker.

Use the separate [version-introduction command](https://github.com/durable-workflow/sample-app/blob/main/polyglot/timers/README.md#introduce-versioning-into-an-existing-history)
to cover an existing unversioned history:

```bash
SDK_TIMERS_COMPOSE_PROJECT_NAME=sample-app-unversioned-timers \
  scripts/sdk-timers.sh --unversioned-upgrades
```

Run it from the same prepared Sample App checkout with its resolved published
tuple. Report its twelve originals separately: old and fresh single/concurrent
runs in PHP, Python and Rust. Revision one schedules timers without a version
command. Cold revision-two workers introduce `getVersion(change, -1, 2)` or the
language equivalent under the same registered wrapper. Old runs must resolve
legacy `-1` without inserting a marker or rebasing their original command
sequences. Fresh runs must record version `2`, minimum `-1` and maximum `2`
before scheduling the new timer branch. Preserve the complete original prefix,
every timer/barrier identity and deadline, typed results and one completion.
Registration ownership, readiness and automatic cleanup follow the main timer
recipe. SDK package upgrades, other durable operations, further application
changes and nested cancellation scopes remain separate qualifications.

Use the separate [SDK-package command](https://github.com/durable-workflow/sample-app/blob/main/polyglot/timers/README.md#upgrade-sdk-packages-with-pending-timers)
to test pending timer histories across selected published package versions:

```bash
SDK_TIMERS_COMPOSE_PROJECT_NAME=sample-app-sdk-package-timers \
  scripts/sdk-timers.sh --sdk-upgrades
```

Report its twelve originals separately from both commands above: six old-package
single/concurrent originals replayed by cold current-package workers, plus six
fresh current-package controls across PHP, Python and Rust. Previous versions
come from the recipe's baseline manifest and targets from the existing qualified
tuple. Build both generations before admission and check installed package
identities plus the actual registered SDK versions. Application source and
registered types stay unchanged. Every original timer must fire while the old
workers are absent, then complete once with its original prefix, run, timer and
barrier identities, sequences, deadlines and typed result. Preserve Python's
recorded class binding. Do not introduce a version marker. Record actual old/new
package versions; a relabelled current image is not an upgrade. Other operations,
combined application/package changes, build routing and incompatible class
adoption remain separate qualifications.

Use the separate [combined SDK and application command](https://github.com/durable-workflow/sample-app/blob/main/polyglot/timers/README.md#upgrade-sdk-packages-and-application-logic-together)
to change the selected SDK package and versioned timer helper together:

```bash
SDK_TIMERS_COMPOSE_PROJECT_NAME=sample-app-sdk-application-timers \
  scripts/sdk-timers.sh --sdk-application-upgrades
```

Report another twelve originals separately: six old-package single/concurrent
runs and six fresh controls across PHP, Python and Rust. Revision one records
version `1` with bounds `1..1`. After its timers fire during worker absence,
cold current-package workers run the revision-two helper against the same
originals. Require the original marker and bounds, complete history prefix,
timer/barrier identities, command sequences, deadlines and one completion.
Fresh current-package runs must select version `2` with bounds `1..2` and the
new timer durations. Check actual installed packages and worker identities for
both generations, plus typed results and Python's recorded definition binding.
Both helpers are bundled under unchanged registered wrappers and selected
before startup. This qualifies the selected package pairs and helper changes;
other durable operations, build routing and incompatible class adoption need
their own cases.

Use the separate [pending activity SDK/application command](https://github.com/durable-workflow/sample-app/blob/main/polyglot/activities/README.md#pending-activities-across-sdk-and-application-upgrades)
for work scheduled before both package and business-helper replacement:

```bash
SDK_ACTIVITY_UPGRADES_COMPOSE_PROJECT_NAME=sample-app-activity-upgrades \
  scripts/sdk-activity-upgrades.sh
```

Run from the prepared Sample App checkout with its published tuple resolved.
Report eighteen originals separately: nine previous-package workflows with a
genuinely unstarted activity, then nine fresh current-package controls covering
every PHP/Python/Rust workflow/activity direction. Build and verify both package
generations before admission. Old helpers record version `1` with bounds `1..1`
and the original activity policy; cold current workers use revision-two helpers
and execute that same pending work. Fresh controls select version `2`, bounds
`1..2` and the new policy.

Require the complete original history prefix, original run and activity/attempt
identities, command sequences, full retry list/timeouts and exact typed activity
and workflow results. Activities execute once on the selected current package,
after worker replacement and inside the original total budget. Python's
registered wrapper and recorded definition remain unchanged. Keep the command's
pending/result observer bounds and automatic project/image cleanup. This covers
the selected pending-activity package/helper pairs; incompatible class adoption,
build routing, other durable operations and application side-effect recovery
retain their separate gates. Record the actual packages, runner SHA, Server
digest and all eighteen outcomes in the owning audit.

The [Sample App Rust search-attribute experiment](https://github.com/durable-workflow/sample-app/blob/main/polyglot/search-attributes/README.md)
authors all seven types through the published Rust workflow API. PHP and Python
clients verify selected-run values and server-side equality, integer/float
range, boolean, list membership and datetime queries. Values include the
Server boundary's UTF-8 byte limits, an integer beyond JavaScript's exact range
and microsecond datetime precision. After physical SIGKILL of the parked Rust
worker, a signal is acknowledged during its absence. A distinct replacement
must preserve the original run, typed upsert and signal-wait history, mutate
and delete once, remove obsolete visibility matches and complete once. The
recorded Sample App cohort uses Rust 4.1.0 and PHP/Python metadata observers.
Published Rust 4.6.0 separately adds a visibility-filter list API and lazy
history/list iteration, with its own Server 2.11.0 receipt. See the
[client API and evidence scope](sdk-coverage.md#read-complete-histories-and-lists).
Dedicated schema-administration and start-time metadata APIs remain absent in
4.6.0. Those client results do not retroactively qualify the Sample App tuple.
This separate command does not add a Rust shard to Server's runner
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

## Run the child workflow and browser cases

Use a prepared Sample App checkout with Docker Compose, Node.js 24, npm and the
command's shell tools. Review `scripts/sdk-children.sh --help` and the linked
[child-workflow instructions](https://github.com/durable-workflow/sample-app/blob/main/polyglot/child-workflows/README.md).
From its repository root, install the locked browser tooling as the owning
[CI workflow](https://github.com/durable-workflow/sample-app/blob/main/.github/workflows/sdk-children.yml)
does:

```bash
npm ci --ignore-scripts
./node_modules/.bin/playwright install --with-deps chromium
scripts/playground doctor
while IFS= read -r assignment; do export "$assignment"; done \
  < <(scripts/resolve-current-artifacts.sh)
SDK_CHILDREN_COMPOSE_PROJECT_NAME=sample-app-sdk-children \
  SDK_CHILDREN_RESULT_DIR=/path/to/disposable/results \
  scripts/sdk-children.sh
```

Choose an unused project name and a disposable result directory. The command
refuses a project with existing containers. It records the runner revision,
published tuple, image identities, original histories, request receipts,
worker-loss evidence and browser responses, screenshots and rendered text.
Require 15 browser views per access mode and report their outcomes separately
from the nine successful parent/child directions and the failure/recovery cases.
The exit trap removes the task stack, volumes, fixture images and temporary
proof directory on success or failure. The selected result directory remains
for review. Record sanitized findings in the owning issue, then remove those
results. Hosted runs retain them for 30 days. After an external interruption,
follow the owning instructions to remove only the same project and its printed
proof directory.

These checks cover cooperative cancellation with wait-for-child cleanup.
Process loss during an external side effect, direct child TRY_CANCEL/ABANDON
requests and parent close after normal completion still need separate cases.

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
