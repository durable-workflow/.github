# SDK experiment coverage

Use this inventory with the [conformance runbook](README.md). It maps existing
public experiments to the language directions they actually execute and the
portable behavior still requiring a runtime check. A row describes executable
scope, not a passing result for an arbitrary release tuple. Results and remaining
work belong to [the experiment audit](https://github.com/durable-workflow/.github/issues/122).

## Choose the meaningful directions

- Workflow authoring and durable replay require PHP, Python and Rust workflow
  execution. A client starting a workflow does not prove its worker runtime.
- Remote activities and children require all nine supported workflow-to-worker
  or parent-to-child directions. Retain the direction on failures and restart
  checks as well as the successful result.
- A timer belongs to its workflow runtime. It has no separate language-specific
  timer worker, so three workflow languages cover the meaningful directions.
- History and list inspection require the actual PHP, Python and Rust client
  bindings being claimed. A Python observer reading a Rust workflow's history
  does not prove a Rust client API. Client pagination and paged worker replay
  are separate cases, not nine new workflow/activity directions.
- Schedule creation follows the installed client's API. PHP and Python can
  create schedules targeting any of the three workflow languages. The Rust
  SDK currently has no schedule creation API. Do not invent a Rust creator.
- Nexus follows advertised support in the exact tuple. The frozen Server
  experiment executes four PHP/Python caller/service directions. Rust also
  supports authored `WorkflowContext::call_nexus_service` calls and has a
  separate five-direction fixture and installed-release acceptance. Keep those
  runners and artifact tuples distinct. A raw HTTP call from a Rust test
  process would not prove authored SDK execution.
- Python exposes authored pre-accept update validators. The PHP SDK advertises
  no validators and Rust refuses validator contracts. Exercise ordinary update
  handlers and explicit capability refusal separately from validator execution.
  Missing embedded PHP, PHP SDK and Rust validator authoring remains
  [a product capability gap](https://github.com/durable-workflow/.github/issues/234).
- Database migration, infrastructure failover and PHP framework integration
  each have their own scope. A language-independent backend assertion need not
  be copied nine times. Workflow continuity across that failure still needs the
  affected SDK workers.

## Public experiment inventory

Server commands below live in `scripts/conformance/` in
[Server](https://github.com/durable-workflow/server/tree/main/scripts/conformance).
Sample App commands and examples live in
[Sample App](https://github.com/durable-workflow/sample-app/tree/main/polyglot).
The scenario manifests define required evidence within their existing scope.
Their SDK installation lists do not widen that scope.

| Experiment and existing entry point | Executed language scope | Remaining portable behavior to qualify |
| --- | --- | --- |
| Remote activity external effects: Sample App `scripts/sdk-activity-recovery.sh --external-effects` | All nine PHP/Python/Rust workflow/activity directions commit an operation to an isolated downstream HTTP service before activity-worker SIGKILL. A distinct replacement retries with the original operation key, immutable input and total deadline. Require one business effect, two delivery receipts tied to the actual attempt identities, the original effect identity, stale completion refusal, unchanged history and one workflow completion. Separate service tests exercise concurrent duplicates, conflicting inputs and physical downstream restart over the same SQLite ledger. | This fixture requires application idempotency supplied by the downstream service. It does not establish exactly-once effects for arbitrary external systems or cover compensation, child or update-handler side effects. |
| Authoring, inputs/results and remote activities: Sample App `scripts/polyglot.sh`, full matrix in `polyglot/README.md`, `scripts/sdk-activity-recovery.sh`; Server `activities-published-artifacts.sh` | Featured PHP → Python → Rust journey and the full nine-direction successful activity matrix are separate commands. The recovery command executes retryable first-attempt failure, activity-worker SIGKILL, total deadline expiry across attempts, exhaustion of two retryable failures and application progress heartbeat expiry in all nine PHP/Python/Rust workflow/activity directions. It checks actual SDK claims, the original run/execution/total deadline, distinct attempts, recorded backoff, stale completion refusal while the retry is active and unchanged history. The progress case verifies typed details, liveness beyond the initial heartbeat deadline, a heartbeat retry with the same live worker, preserved expired progress and obsolete heartbeat refusal. Successful cases have one durable result/completion. Failed cases retain the actual terminal activity cause in one workflow failure, reject results after closure and admit no third attempt or successful result. Server's activity manifest primarily uses embedded PHP/Python cells, with a focused PHP SDK heartbeat-renewal shard. | The focused cases cover two attempts, start-to-close and heartbeat timeout retries, total deadline expiry, retry exhaustion and application progress in every supported workflow/activity language direction. Recovery of an external side effect requires a separate application idempotency or downstream fencing fixture. |
| Child workflows: Server `child-workflows-published-artifacts.sh`; Sample App `scripts/sdk-children.sh` and `polyglot/child-workflows/` | Server's four PHP Workflow-package/Python SDK parent-child directions, using the image-bundled probe described in the [runbook](README.md#run-the-server-child-workflow-probe). Sample App runs all nine PHP/Python/Rust SDK completion directions and the five Rust-involving typed failure, cold worker-recovery and cooperative cancellation directions. Separate five-case runtime-token and anonymous cancellation families execute actual PHP/Python/Rust cancellation clients, operator/administrator duplicate actor preservation and worker/missing-authentication refusals. Cancellation uses wait-for-child cleanup, worker SIGKILL during a recorded cleanup timer, original delivery/timer replay, immutable duplicate identity/deadline and complete matching API/CLI cascade views. The same command inspects the published Waterline image through 45 connected Chromium views: parent desktop/mobile and child desktop across all five cancellation directions and three access modes. Actual HTTP responses and rendered request, requester, deadline, delivery, recovery and completed cleanup must match the original SDK/Server evidence, with no browser errors or horizontal overflow. Browser time is outside the cleanup deadline measurement. | Process loss during an external side effect, direct child TRY_CANCEL/ABANDON requests, parent close after normal completion require separate scenarios. Keep the Server runner's PHP/Python cells and Sample App's SDK cells distinct. |
| Heartbeats: Server `heartbeats-published-artifacts.sh`, `heartbeats-python-published-artifacts.sh`, `heartbeats-rust-published-artifacts.sh`, shared wave runner; Sample App `scripts/sdk-activity-recovery.sh` | Server's Python and Rust fixtures use managed SDK worker loops. Its PHP fixture combines actual `Worker::tick()` execution with explicit client heartbeat calls. These inspect cadence, metrics, stale transitions and routing exclusion within their respective execution surfaces. Sample App separately executes application progress heartbeat and missing-progress retry in all nine workflow/activity directions using the published cooperative worker opt-in, while the activity worker stays running. Its four ordinary recovery scenarios retain their existing worker mode. | PHP managed `Worker::run()` heartbeat lifecycle needs separate installed qualification. Worker health, application progress and cancellation observation have distinct contracts and observations. Stopping application progress must not be hidden by healthy worker heartbeats. External effects still require application idempotency or downstream fencing. |
| Timers: Server `timers-published-artifacts.sh`; Sample App `scripts/sdk-timers.sh` | Server's PHP-hosted protocol/package timer probes. Its concurrent-deadline case directly submits commands and drives queue jobs in sorted deadline order, so it does not independently prove ordinary scheduler ordering or SDK-authored concurrent waits. Sample App supplies forty SDK originals: PHP twelve, Python sixteen, Rust twelve. Completion, worker SIGKILL/cold replay, Server restart and cooperative cancellation cover single timers and three-member concurrent all/parallel groups. Every concurrent member must fire during worker absence before one cold-replayed completion. Server restart crosses every original deadline; cancellation closes every member and is observed beyond its last deadline with no fire or completion. Original run/timer identities, full barrier metadata, scalar types and nested paths stay intact. Compatible business-helper replacement preserves the original prefix and version-one decision on fresh revision-two workers, then proves the new branch on fresh runs. Four additional Python originals require a recorded class fingerprint, different-class refusal with unclaimed original work, cold original-class restoration and fresh new-class execution. Worker replacement retires only the captured owned registrations with zero lease recovery and waits for the new roster before admission. | Both authored helpers are bundled and selected before startup under unchanged registered wrappers. The separate Python class cases preserve the released definition fence; they do not authorize adopting a different class into a pinned original. SDK package upgrades, build-ID rollouts, other class-evolution mechanisms, other application changes and nested cancellation need separate qualification. Keep the manually driven Server probe distinct from actual SDK execution. |
| Version introduction: Sample App `scripts/sdk-timers.sh --unversioned-upgrades` | Twelve separate originals: old and fresh single/concurrent runs in PHP, Python and Rust. Old code schedules timers without a marker. Cold replacement code introduces the numeric version helper with minimum -1 and maximum 2. The same old runs retain no marker, resolve legacy -1 and preserve their complete original prefixes, timer/barrier identities, sequences and deadlines. Fresh runs record version 2 before new timer commands. Typed results, stable registered wrappers and one completion remain required. | This covers introducing versioning around the selected timer operations. Keep its twelve outcomes separate from the default forty. Both helper implementations are bundled and selected before process startup. Other durable operations, SDK package upgrades, build routing and incompatible class adoption require separate cases. |
| SDK package timer upgrades: Sample App `scripts/sdk-timers.sh --sdk-upgrades` | Twelve separate originals across PHP, Python and Rust: old-package single/concurrent histories replayed by cold current-package workers and fresh current-package controls. Both image generations are built before admission, with installed/compiled package identity and exact registered SDK checks. Every original timer fires during worker absence, then the same run completes once with unchanged complete prefix, timer/barrier identities, sequences, deadlines and typed result. Python's recorded class binding stays exact; no version marker is introduced. | Selected baseline versions and current qualified targets are explicit manifests. This covers only those actual pairs and timer operations with unchanged application code. Other durable operations, combined package/application changes, build routing and incompatible class adoption require separate cases. Keep these twelve outcomes separate from the forty timer and twelve version-introduction cases. |
| Combined SDK and application timer upgrades: Sample App `scripts/sdk-timers.sh --sdk-application-upgrades` | Twelve separate originals across PHP, Python and Rust. Six old-package single/concurrent runs record helper version one with bounds 1..1. Their timers fire while workers are absent, then cold current-package workers use helper revision two to finish the same originals with the original decision, marker bounds, full prefix, timers, barriers, command sequences and deadlines. Six fresh controls use the new branch and bounds 1..2. Actual installed packages, original/replacement worker identities, typed results, one completion and Python's recorded definition binding are checked. | Both helpers ship under unchanged registered wrappers and are selected before startup. This covers the selected package pairs and helper changes, not arbitrary source or class adoption. Other durable operations, build routing and incompatible class adoption require separate cases. Report these twelve outcomes separately from the other timer commands. |
| Pending activity SDK/application upgrades: Sample App `scripts/sdk-activity-upgrades.sh` | Eighteen separate originals across every PHP/Python/Rust workflow/activity direction. Nine previous-package workflows record version 1/range 1..1 and leave their activity unstarted. Cold current-package workers use revision-two helpers, execute the same original activity once and complete the same workflow with its full original prefix, marker, policy, command sequence, identities and typed results. Nine fresh controls select version 2/range 1..2 and the changed policy. Both image generations and installed/registered package identities are verified before admission; Python's recorded definition remains bound to the unchanged wrapper. | This covers the selected package pairs and versioned helper changes around one pending remote activity. It does not qualify incompatible class adoption, build routing, other durable operations, an activity callback interrupted by the upgrade or external side-effect recovery. Report all eighteen actual outcomes separately from timer and recovery experiments; source verifier tests alone establish no package replay. |
| Sagas: Server `sagas-published-artifacts.sh`; Sample App `polyglot/sagas/` | Server combines the PHP Workflow package through a fixture protocol adapter with the Python SDK. Its cases include reverse compensation, typed failure and restart after the first compensation marker. Sample App executes the five Rust-involving service-SDK directions, typed compensation failure and restart before compensation. | The PHP service SDK's PHP/Python directions need their own cases; the Workflow package fixture does not fill them. Process loss during an external compensation side effect, duplicate delivery and external-effect recovery require explicit side-effect fixtures. A recorded restart boundary does not establish them. |
| Schedules: Server `schedules-published-artifacts.sh`; Sample App `polyglot/schedules/` | Server includes PHP/Python schedule creators and worker-protocol client cells. Sample App runs PHP- and Python-created schedules on an authored Rust workflow worker. | Direct worker-protocol completion does not establish authored PHP/Python workflow execution after a scheduled fire. The Rust examples check one automatic interval fire. Run cadence, restart, overlap/backfill and failure recovery for those directions. Calendar folds/gaps are temporal cases, not extra creator languages. |
| Signals and queries: Server `signals-queries-published-artifacts.sh` | PHP/Python/Rust clients and workers, including cross-language calls, Rust query immutability and cold-restarted instance state. | Read the direction-specific scenarios and histories. The crate pin alone proves none of them. |
| Workflow updates: Server `workflow-updates-published-artifacts.sh`; Sample App `scripts/sdk-updates.sh` | Server's embedded probe, directly driven worker-protocol validation controls, PHP SDK client/worker process boundary, Python installed-package surface fixtures, CLI and Waterline diagnostics. The Python fixture uses simulated HTTP responses. Sample App separately executes all nine PHP/Python/Rust client-to-handler directions and completed duplicate directions against a live published Server. It checks accumulated state, read-only queries, all-worker SIGKILL/replacement and queued updates in each worker runtime. Handler failure and validator refusal target Rust. Rust also checks original workflow input, three signal argument shapes and completion immediately after an acknowledged update. | Other command-ordering races and process loss during a handler's external effect require additional fixtures. Keep Server's protocol controls and simulated Python client fixtures distinct from authored SDK validator-worker evidence. PHP SDK validator authoring is absent and Rust refuses validator contracts. Their implementation and embedded PHP support remain in [#234](https://github.com/durable-workflow/.github/issues/234). |
| Deterministic replay: Server `replay-published-artifacts.sh` | Separate installed PHP, Python and Rust shards. Python reconstructs fixture history, including simulated restart controls. Rust uses actual Server calls and gracefully replaces Worker instances within one process. Inspect each selected package’s actual shard and outcome. | These surfaces do not establish OS process loss or registry-package upgrades. Pair affected histories with their runtime restart and upgrade cases. [Evidence boundaries](#interpret-replay-skew-and-migration-evidence). |
| History/list observation within existing experiments: Sample App readers and CLI `workflow:history` | The child, activity-recovery and update observers explicitly join Python history pages and guard repeated tokens. CLI history collects pages for JSON output or streams events as JSONL. These are inspection paths, separate from the worker's own history fetches. | [SDK iterator delivery](https://github.com/durable-workflow/.github/issues/247) needs actual multi-page history/list results through each claimed client binding. A manually paged observer or a constructed reader test does not establish that product API or a live multi-page SDK result. |
| Workflow lifecycle: Server `workflow-lifecycle-host-published-artifacts.sh` | The host extracts probes from the selected published Server image. PHP runs an installed SDK worker subprocess. Python exercises an installed client with simulated HTTP and serializes workflow commands. Rust runs authored workers, separate continuation processes and concurrent cancellation replacement. [Interpret each surface separately](#interpret-lifecycle-execution-surfaces). | Python worker execution and process recovery need actual worker cases. Rust cancellation replacement inside one probe process does not establish SIGKILL/cold-process recovery. Select actual continuation, retry/timeout, cancellation and termination outcomes for the exact tuple. Terminal cancellation and cooperative cleanup are separate contracts. |
| Worker versioning: Server `worker-versioning-published-artifacts.sh` and `worker-versioning-rust-host-published-artifacts.sh` | PHP/Python protocol-client build cohorts and mixed pinning, plus Python no-compatible-worker, replay and adversarial shards. Managed Rust SDK workers execute registration, pinning, promotion, incompatible refusal, cache eviction, SIGKILL/cold replay and drain/resume with queued work and recovery diagnostics. Source-bound handlers exercise changed/missing-definition refusal, divergent peer conflicts, unchanged recovery and a changed-build positive control. Selecting `DW_RUST_SDK_PREVIOUS_VERSION` compiles identical application sources against two published registry crates and preserves an original unversioned run through the upgrade and another SIGKILL, including the older client's result, both signals and one recorded effect/completion. The focused command also executes all four Rust/PHP and Rust/Python build-cohort directions with actual SDK workers and durable results. | The crate upgrade covers the selected version pair and signal/side-effect history. Changed application code, other durable operations and adding build IDs to existing unversioned histories need their own upgrade cases. Mixed build routing does not establish interchangeable cross-language histories or a shared build identity. |
| Namespaces: Server `namespaces-published-artifacts.sh` and Sample App `sdk-namespaces.sh` | Server authorization/routing, PHP and Python SDK paths, CLI and Waterline namespace surfaces. Actual Rust clients/workers execute remote activities in two namespaces sharing queue/type names, use separate namespace-bound role credentials, reject wrong-role/cross-namespace reads, signals, starts, registrations and polls, and retain original runs/activity attempts/signal waits after SIGKILL and replacement. The published Server's cross-namespace workflow-ID reservation also rejects duplicate IDs explicitly. | Rust namespace selection and execution are covered through real SDK requests. Namespace CRUD remains the published Server API and PHP/Python/CLI surface. This does not establish namespace deletion/retention during active Rust work or Rust SDK namespace-administration methods. |
| Search attributes: Server `search-attributes-published-artifacts.sh`; Sample App `scripts/sdk-search-attributes.sh` | Server's PHP SDK, Waterline and PHP/Python codec shards, or supplied host matrix evidence. Sample App separately runs published Rust workflow-side authoring of all seven typed values, PHP/Python selected-run and filtered-list observers, worker SIGKILL, an acknowledged signal during absence and cold replay of original upsert/wait identities before one mutation, deletion and completion. | Rust 4.6.0 adds a visibility-filter list API with a [separate client receipt](#read-complete-histories-and-lists). The recorded Sample App Rust 4.1.0 cohort still uses PHP/Python metadata observers. Dedicated schema-administration and start-time search-attribute client APIs remain absent in 4.6.0. The focused command does not establish Rust Waterline coverage, namespace isolation, load latency, continuation inheritance or application-code upgrades. Supplied evidence must come from a real worker run. |
| Frozen Server Nexus: `nexus-published-artifacts.sh` | Installed PHP/Python clients execute all four admission directions. Actual PHP/Python caller workflow workers execute all four caller/service directions in same and cross namespaces, with terminal results, handled and uncaught typed failures, direct target cancellation, waiting-caller cancellation propagation, caller SIGKILL/replacement and MySQL interruption. Uncaught cases require the original remote failure, one call failure and one failed caller workflow in eight distinct originals. The [focused workflow](#run-the-published-nexus-caller-cases) also checks oversized argument/result recovery and authored worker-role refusal before target dispatch. Original caller/call/target identities, deadlines and one terminal delivery remain required. | The complete scenario manifest retains its own coverage requirements. Its legacy invocable-carrier cells remain separate from workflow-run bindings and retain `not_covered` until their execution lane is qualified. Embedded applications use the separate [installed-package recipe](https://github.com/durable-workflow/workflow/blob/main/examples/embedded-http/qualification/nexus.md). Rust SDK and native Server qualification are separate. |
| Rust-involving Nexus: Rust SDK `tests/nexus/run.sh` and `examples/nexus_cooperation.rs` | Five authored caller/target directions: Rust/PHP, PHP/Rust, Rust/Rust, Rust/Python and Python/Rust. The [SDK fixture](#run-and-interpret-rust-nexus-cases) defines cooperative cancellation and cold target replacement, typed outcomes, cross-namespace isolation, explicit admission/wait modes, lost command acknowledgements and separate catalog browser inspection. Its ordinary preparation builds the Rust checkout. The [installed-release receipt](https://github.com/durable-workflow/sdk-rust/issues/86#issuecomment-6303358379) separately records 72 selected HTTP originals from a normally downloaded crate: six cancellation/cold-target, forty typed cross-namespace outcomes, twenty lost acknowledgements and six selected admission cases. | That installed result belongs to its recorded published tuple and actor. It does not qualify every source admission cell, the current package tuple, native Server or catalog browser rendering. Do not combine it with the frozen Server's four directions to claim one nine-direction tuple. |
| 1.x → 2.x migration: Server `migration-published-artifacts.sh` | Composes actual host evidence for supported 1.x PHP artifacts and durable state, target PHP/Python and operator surfaces. A supplied foundation plan can execute setup, migration and post-upgrade commands. | Artifact resolution or storage connectivity alone does not establish migration. Missing required cells remain uncovered. Rust has no 1.x source artifact to migrate; running it against the migrated target is a separate post-migration case. [Evidence requirements](#interpret-replay-skew-and-migration-evidence). |
| Compatibility skew: Server `skew-published-artifacts.sh` | CLI, Python SDK, PHP SDK worker and Waterline protocol negotiation/refusal under one exact selected artifact tuple. Older, future and outside-window protocol shapes come from the Server’s advertised authority. | These protocol cases do not install historical or future SDK packages. Add Rust’s supported and refused protocol pairings, and retain separate installed-package compatibility evidence. A major SDK package number is not itself a worker protocol boundary. [Interpret the results](#interpret-replay-skew-and-migration-evidence). |
| Principal attribution: Server `principal-attribution-published-artifacts.sh`; Sample App `scripts/sdk-namespaces.sh` and `scripts/sdk-children.sh` | Server covers named/anonymous/raw HTTP actors, PHP/Python clients, worker completion/failure, CLI and Waterline. Sample App separately executes real Rust starts, signals, remote activities and workflow completions with namespace-bound operator and worker credentials. A disposable gateway injects the published principal contract's forged body fields and headers into actual SDK requests. During worker absence, all four credentials are rotated through the Server API. Duplicate rotations preserve their timestamp, real Rust calls refuse the old credentials, and new credentials complete the original runs with the same authenticated subjects. Successful request receipts and original-run histories retain start/signal/completion actors through worker SIGKILL and cold replacement. Selected-run queries distinguish Server's authenticated response principal from a forged application-result principal and leave history unchanged. Additional Rust workflows fail with the worker actor or receive terminal cancellation with the operator actor after a declared wait, preserving their original runs and one terminal boundary. A final isolated phase requires token-driver refusal before explicitly recreating the disposable frontend with the `none` driver. Actual credential-free Rust callers and worker then execute activity/workflow completion, signals, queries, authored failure and terminal cancellation with server/anonymous actors and the same forged metadata matrix. Published native CLI JSON and human tables inspect every original terminal run. Published Waterline uses its read-only remote backend to inspect the same selected runs, statuses, complete timelines and command actors. Both views must match preserved Server histories without mutating them. | The Rust case covers named and anonymous actors, runtime credential rotation and start/signal/completion/query/failure/terminal-cancellation attribution, plus CLI and Waterline API visibility of actual Rust runs. Activity execution identities are checked separately, while internal events may have explicit null principals. The separate child runner checks legacy, runtime-token and anonymous requesters through actual PHP/Python/Rust cancellation clients, Rust-involving cooperative propagation, duplicate identity and original actor preservation, committed delivery and cold cleanup recovery under forged metadata. It also requires actual worker-role 403 and unauthenticated 401 refusals. The same command also checks 45 connected published Waterline browser views across those five directions and three access modes, preserving the original requester and complete cascade after cold cleanup recovery. The anonymous phase qualifies auth-disabled self-hosting, not anonymous Cloud access or namespace isolation without authentication. Credential administration uses the Server API. Transport injection does not add a custom-header SDK API, and the query observer does not add a Rust raw-response API. |
| Cooperative cancellation and worker affinity: SDK integration suites, public qualification records and the timer command above | Source integration tests exist in every SDK. Published local-activity/session and mixed-cancellation qualifications are distinct release evidence. Python 2.5.0 and Rust 3.4.0 provide opt-in bounded sticky history with Server 2.5.10, covering paged warm reuse, entry/byte limits, expiry, build refusal and SIGKILL/replacement cold replay. Rust also checks cached canonical cancellation and cleanup on a cold successor. Exact installed-package and tuple evidence is recorded in [.github #124](https://github.com/durable-workflow/.github/issues/124). | Keep installed-package proof separate from source CI. Sticky history does not retain live workflow objects or session resources. Older affinity manifest expectations must not override the tested tuple's capabilities. |
| Backend failover: Server `single-region-failover-published-artifacts.sh` | A Python HTTP driver registers, polls and completes workflow tasks directly across cross-node completion, API-node loss, database/Redis interruption, worker lease loss and scheduler restart. Its registration declares `runtime: python`. | That field does not establish Python SDK Worker execution. SDK-authored workflow continuity, pending durable operations and external effects require their own worker/runtime evidence. [Host prerequisites and results](#run-the-backend-failover-rehearsal). |
| MCP operator loop: Server `agent-operability-published-artifacts.sh` | Validates retained Sample App metadata or drives an explicitly configured MCP endpoint through discover, guarded operating choice, run, diagnose and repair stages. | Record which evidence source actually ran. The script requires existing metadata or an isolated app endpoint and does not provision the app. SDK-worker recovery and the separate six-case diagnosis drill retain their own qualification. [Inputs and result interpretation](#run-the-mcp-operator-loop). |
| Self-hosted operator diagnosis: [six-case drill](operator-diagnosis.md) | Documented CLI, Server API and Waterline diagnosis/recovery instructions with explicit original-run tracking. Published command syntax and source dispatch have been checked. | Actual staged faults, recovery and original-run outcomes need their own recorded execution. Embedded Laravel injection/testing remains a PHP framework-specific case. |
| Managed Cloud | Private Cloud repository's isolated qualification | Keep account, provisioning, provider chaos and commercial qualification private. Public SDK protocol coverage does not establish managed-plan capacity or Cloud recovery. |


## Run the backend failover rehearsal

Use a Server checkout with Bash, Python 3 and Docker Compose v2. Set
`DW_SERVER_IMAGE` to the selected exact public Server image. The wrapper pulls
that image and its selected MySQL, Redis and Nginx dependencies, resolves their
repository digests and rejects Compose builds and source mounts. Review
`--help` for supporting-image, connection and port overrides.

Choose an unused project when overriding `DW_FAILOVER_PROJECT`. The default
name includes the run context and process ID. From the Server repository root:

```sh
result_dir="$(mktemp -d "${TMPDIR:-/tmp}/dw-failover.XXXXXX")"
bash scripts/conformance/single-region-failover-published-artifacts.sh \
  --result-dir "$result_dir"
```

Read `single-region-failover-result.json`, its `outcome`, `runner_blocked`,
`phase_outcomes` and `phase_evidence`, together with the resolved image digests.
The [driver supplies worker-protocol HTTP commands itself](https://github.com/durable-workflow/server/blob/c36710e860a44c5d51f016eadabd49f5b85c451e/scripts/conformance/single-region-failover-published-artifacts.py#L788-L879).
Its Python runtime declaration identifies that probe, rather than an installed
SDK worker or authored three-language workload.

Default cleanup calls Compose down with volumes for the selected project.
`--keep-stack` retains the stack for inspection. Retire that same stack after
review, and remove this run's disposable results after recording the sanitized
outcomes. Backend recovery alone does not qualify SDK workflow continuity.
The audited c367 runner can [lose its JSON result when cleanup times out](https://github.com/durable-workflow/server/issues/325#issuecomment-6369070712).
A missing result is incomplete qualification. This documentation change does
not correct that runner defect.

## Run the MCP operator loop

Use a Server checkout with Bash and Python 3. Set the exact artifact versions
and Sample App ref listed in the runner's `--help`. Prepare actual recorded
Sample App conformance metadata, or an isolated Sample App MCP endpoint. The
runner does not start or provision that application.

For the recorded-metadata path, clear the live endpoint override and supply
the metadata file:

```sh
result_dir="$(mktemp -d "${TMPDIR:-/tmp}/dw-operator-loop.XXXXXX")"
DW_AGENT_OPERABILITY_MCP_URL= \
DW_AGENT_OPERABILITY_SAMPLE_APP_METADATA_PATH=/path/to/recorded-metadata.json \
  bash scripts/conformance/agent-operability-published-artifacts.sh \
    --result-dir "$result_dir"
```

[Usable metadata takes precedence](https://github.com/durable-workflow/server/blob/c36710e860a44c5d51f016eadabd49f5b85c451e/scripts/conformance/agent-operability-published-artifacts.sh#L794-L807).
With no usable metadata and `DW_AGENT_OPERABILITY_MCP_URL` set, the runner
calls MCP tools to start a synthetic diagnostic workflow, observe its failure,
diagnose it, request repair and read history. Run that mode against an isolated
app prepared for this experiment. Missing inputs produce a coverage finding.

Read `agent-operability-result.json`, including `evidence_source`,
`scenario_results` and `findings`. All five loop stages and the artifact-policy
checks must pass. The change stage records a guarded operating choice.
Recorded metadata, a live MCP loop, SDK-worker recovery and the
[six-case operator diagnosis drill](operator-diagnosis.md) require their own
identified evidence. Record the source and outcome before retiring this run's
results and any app resources created for it.

## Interpret replay, skew and migration evidence

A scenario name is not sufficient evidence of process recovery or package
compatibility. Read the selected package's implementation and the individual
result alongside its exact distribution identity.

Python's [published replay command](https://github.com/durable-workflow/sdk-python/blob/04116871c83e6a502c713789cb452e90917a3438/src/durable_workflow/replay_conformance.py#L431-L460)
reconstructs query state from golden history and records
`worker_restart_simulated: true`. Its signal timing case also uses constructed
history. Rust's [published replay binary](https://github.com/durable-workflow/sdk-rust/blob/5e2af20fde934e05bf18f64111dce8e590ea6c90/src/bin/durable-workflow-replay-conformance.rs#L92-L176)
uses real Server calls, stops one Worker gracefully and creates another in the
same process with a wider supported version range. Its replacement boundary is
a Worker instance. SIGKILL recovery, executable replacement and registry-package
upgrades require separate cases. Keep those runtime recovery and upgrade
receipts attached to their actual tuples.

The skew runner [selects one current artifact tuple](https://github.com/durable-workflow/server/blob/c36710e860a44c5d51f016eadabd49f5b85c451e/static/platform-conformance/skew-refusal-matrix-scenarios.json#L19-L32)
and derives its protocol pairings from the Server's advertised compatibility
window. Read `skew-result.json`, per-surface/per-pairing results and
`request-response-captures.json` to verify the actual operation or refusal.
A successful older-protocol case does not qualify an older package that was
never installed.

The migration wrapper [accepts host evidence or a supplied foundation plan](https://github.com/durable-workflow/server/blob/c36710e860a44c5d51f016eadabd49f5b85c451e/scripts/conformance/migration-published-artifacts.sh#L8-L56).
Use `DW_MIGRATION_EVIDENCE_JSON` or `DW_MIGRATION_EVIDENCE_DIR` for retained
results from an actual host migration. Use
`DW_MIGRATION_FOUNDATION_PLAN_FILE` for an explicit reviewed plan of setup,
migration and post-upgrade commands. Automatic plan execution requires that
plan to be present. Review the command's `--help` before invoking it against
disposable state, and inspect `migration-conformance-result.json` for source
capabilities, artifact prerequisites, command outcomes and every required
scenario. Missing migration cells remain uncovered; a storage connection or
successful evidence-composer invocation cannot replace them.

## Interpret saga runtime evidence

The Server saga runner [declares `workflow-php` and `sdk-python` runtimes](https://github.com/durable-workflow/server/blob/c36710e860a44c5d51f016eadabd49f5b85c451e/scripts/conformance/sagas-published-artifacts.sh#L3968).
Its PHP actor [uses the Workflow package's `Workflow` and
`WorkflowFiberRunner`](https://github.com/durable-workflow/server/blob/c36710e860a44c5d51f016eadabd49f5b85c451e/scripts/conformance/sagas-published-artifacts.sh#L1248)
with a fixture adapter for the Server worker protocol. This exercises that
package's compensation logic. The PHP service SDK's `DurableWorkflow\Worker`
is a separate authoring and execution path. Installing both packages in the
artifact tuple does not make their runtime coverage interchangeable.

The [Sample App saga client](https://github.com/durable-workflow/sample-app/blob/40be451c020c6a0e8c9561585bcd96d38a352a75/polyglot/sagas/client.py#L25)
selects Rust → Rust, Rust → PHP, Rust → Python, PHP → Rust and Python → Rust.
Its PHP and Python actors use the service SDK workers. These cases leave three
non-Rust service-SDK directions requiring their own qualification: PHP → PHP,
PHP → Python and Python → PHP. The Server runner's Python → Python SDK baseline
remains distinct from its PHP package cases. Keep every result bound to its
own runner and artifact tuple.

The Server's [mid-compensation restart case](https://github.com/durable-workflow/server/blob/c36710e860a44c5d51f016eadabd49f5b85c451e/scripts/conformance/sagas-published-artifacts.sh#L3530)
observes `pause_after_refund`, restarts the selected worker and checks resumed
compensation order and duplicate ledger rows. The Sample App restart recipe
stops before compensation. Neither boundary alone qualifies process loss
during an external compensation side effect or recovery after its lost
acknowledgement. Those claims need their own application-idempotency or
downstream-fencing fixture and retained outcomes.

## Interpret worker heartbeat evidence

The Server PHP heartbeat fixture [registers through the client, then runs
`Worker::tick()` and explicit `Client::heartbeatWorker()` calls](https://github.com/durable-workflow/server/blob/c36710e860a44c5d51f016eadabd49f5b85c451e/scripts/conformance/heartbeats-published-artifacts.mjs#L651).
It executes real PHP workflow tasks and observes SDK heartbeat acknowledgements
and Server stale-worker routing. It does not invoke the PHP managed worker loop.

In published PHP SDK 3.1.0, [`Worker::run()` establishes the internal registration
and managed heartbeat state](https://github.com/durable-workflow/sdk-php/blob/222e27eddc0915957ad513dcc3b2b2418f5eb959/src/Worker.php#L356).
`tick()` does not establish that state, and automatic heartbeat refresh refuses
while the worker is internally unregistered. The fixture's explicit client
heartbeats therefore do not qualify managed interval adoption, automatic
refresh, heartbeat retry or shutdown behavior for that package.

The Python fixture [starts `Worker.run()`](https://github.com/durable-workflow/server/blob/c36710e860a44c5d51f016eadabd49f5b85c451e/scripts/conformance/heartbeats-published-artifacts.mjs#L789).
The Rust fixture [uses `Worker::run_until()` and its heartbeat observation
callback](https://github.com/durable-workflow/server/blob/c36710e860a44c5d51f016eadabd49f5b85c451e/scripts/conformance/heartbeats-published-artifacts.mjs#L914).
Keep these execution surfaces and each retained artifact tuple distinct.
Neither a shared wave nor another language's managed loop fills the PHP
qualification gap. This distinction does not establish a product defect or
promote an unexecuted tuple into passing coverage.

## Interpret scheduled workflow evidence

The Server schedule runner's cross-language shard [reports
`worker_execution_mode: published_php_python_worker_protocol_clients`](https://github.com/durable-workflow/server/blob/c36710e860a44c5d51f016eadabd49f5b85c451e/scripts/conformance/schedules-published-artifacts.mjs#L7590).
Its helpers use actual SDK clients to create schedules, register and heartbeat
workers, poll tasks and submit completion commands. The
[Python helper](https://github.com/durable-workflow/server/blob/c36710e860a44c5d51f016eadabd49f5b85c451e/scripts/conformance/schedules-published-artifacts.mjs#L9344)
and [PHP helper](https://github.com/durable-workflow/server/blob/c36710e860a44c5d51f016eadabd49f5b85c451e/scripts/conformance/schedules-published-artifacts.mjs#L9488)
construct the `complete_workflow` result directly. Those cells test schedule
dispatch and the worker protocol, rather than executing authored workflows
through the PHP or Python SDK worker runtime.

The separate [Sample App schedule examples](https://github.com/durable-workflow/sample-app/blob/40be451c020c6a0e8c9561585bcd96d38a352a75/polyglot/schedules/README.md)
use PHP and Python SDK creators with an authored Rust workflow worker. Each
waits for its first automatic interval fire, checks the result and linked
schedule/run history, then deletes the schedule. Neither client manually
triggers the fire. These two cases do not qualify other worker runtimes or
schedule cadence, restart, overlap/backfill and failure recovery.

Keep protocol-client results, authored worker execution and each recorded
artifact tuple distinct. A result field naming a runtime or an SDK package pin
alone does not fill a missing authored-worker case.

## Interpret lifecycle execution surfaces

The Docker host command [extracts the probe sources and scenario manifest](https://github.com/durable-workflow/server/blob/c36710e860a44c5d51f016eadabd49f5b85c451e/scripts/conformance/workflow-lifecycle-host-published-artifacts.sh#L216-L242)
from the selected published Server image and builds the Rust actor outside that
image. Record both the host runner commit and the image digest. The checkout's
current probe files alone do not identify the image's bundled implementation.

The Python fixture installs the selected PyPI package, then [uses simulated HTTP responses](https://github.com/durable-workflow/server/blob/c36710e860a44c5d51f016eadabd49f5b85c451e/scripts/conformance/workflow-lifecycle-published-artifacts.sh#L528-L539)
for lifecycle client calls. Its continuation and child checks serialize SDK
commands. These establish installed client and command behavior. Actual Python
worker continuation, cancellation and process recovery require worker execution
against the selected Server.

The PHP runner [starts the installed SDK's worker in a subprocess](https://github.com/durable-workflow/server/blob/c36710e860a44c5d51f016eadabd49f5b85c451e/scripts/conformance/php-sdk-published-artifacts.sh#L3356-L3359).
Rust also registers authored workflows and activities. Its continuation probe
[launches separate predecessor and successor processes](https://github.com/durable-workflow/server/blob/c36710e860a44c5d51f016eadabd49f5b85c451e/scripts/conformance/workflow-lifecycle-rust-probe.rs#L331-L359).
Its `worker_restart_during_cancellation` case [starts a replacement while the original task remains unsettled](https://github.com/durable-workflow/server/blob/c36710e860a44c5d51f016eadabd49f5b85c451e/scripts/conformance/workflow-lifecycle-rust-probe.rs#L969-L1027)
inside one probe process. That checks replacement before original settlement;
SIGKILL and cold-process recovery need their own case.

The manifest's `workflow_retry_backoff_or_refusal` probe [checks explicit refusal
of an unsupported workflow-level retry policy](https://github.com/durable-workflow/server/blob/c36710e860a44c5d51f016eadabd49f5b85c451e/scripts/conformance/workflow-lifecycle-published-artifacts.sh#L1359-L1401).
That outcome establishes the refusal contract. Activity retry execution belongs
to the separate activity scenarios above.

Read each retained scenario's status, installed artifact identity and observed
outputs. Keep constructed client responses, typed result inspection, live worker
execution and physical process loss distinct. A successful lifecycle job belongs
to its recorded tuple and executed cells. Unexecuted cells and newer artifact
tuples remain unqualified.

## Read signals and queries outcomes

The Server [signals/query runner](https://github.com/durable-workflow/server/blob/c36710e860a44c5d51f016eadabd49f5b85c451e/scripts/conformance/signals-queries-published-artifacts.sh#L4)
documents its published artifact inputs, optional probes and result directory:

```sh
bash scripts/conformance/signals-queries-published-artifacts.sh --help
```

Run that command from the Server checkout. Freeze the published tuple and runner
revision before executing probes. A configured CLI binary or Python executable
alone does not prove installation from the published artifact.

The full runner declares these SDK client-to-worker directions, with additional
CLI checks. They are signal/query directions, separate from workflow-to-activity
directions:

| Worker runtime | SDK clients |
| --- | --- |
| PHP | PHP, Python, Rust |
| Python | PHP, Python, Rust |
| Rust | PHP, Python, Rust |

Inspect `signals-queries-result.json`: its `outcome`, `runtime_matrix`,
`scenario_results` and `executed_distribution_identities` identify the result
and consumed artifacts. The runner [requires nineteen scenarios](https://github.com/durable-workflow/server/blob/c36710e860a44c5d51f016eadabd49f5b85c451e/scripts/conformance/signals-queries-published-artifacts.sh#L17046),
including replay, terminal behavior, adversarial errors and Waterline visibility.
Each scenario has its own executed scope. Declaring all nine client/worker
directions does not repeat every adversarial or recovery case in every direction.

The command [writes a structured record](https://github.com/durable-workflow/server/blob/c36710e860a44c5d51f016eadabd49f5b85c451e/scripts/conformance/signals-queries-published-artifacts.sh#L18506)
even when the result is `non_passing` or `non_passing_runner_blocked`. A normal
process exit alone is insufficient evidence of conformance. Preserve failures,
`unsupported`, `not_covered` and runner blockers. Disabling a probe contributes
no execution evidence; installing its SDK does not replace the missing scenario.

`--focus=php-worker-cli-signal` produces a separate
`signals-queries-php-cli-signal-result.json` with
`broad_property_claimed: false` and `broad_confirmation_required: true`. This
[focused mode disables](https://github.com/durable-workflow/server/blob/c36710e860a44c5d51f016eadabd49f5b85c451e/scripts/conformance/signals-queries-published-artifacts.sh#L140)
the adversarial, replay/terminal, Rust and Waterline probes. Its result cannot
qualify the full matrix or a different artifact tuple. Keep the retained JSON
records with the owning run's evidence; leave unexecuted cells unqualified.

## Read complete histories and lists

PHP `workflowHistory` and Python `get_history` return one page. Their workflow
listing methods also return pages. Follow the opaque `next_page_token` until
the response reports no next page when collecting complete evidence. Keep the
original namespace, workflow/run IDs and list filters fixed. A single page can
be a valid API result without being the complete history or workflow list.

Rust 4.6.0 publishes one-page `Client::list_workflows` and
`Client::get_workflow_history`, plus lazy `Client::iter_workflows` and
`Client::iter_workflow_history` with `next().await` and optional Stream adaptation.
Its [published pagination API](https://github.com/durable-workflow/sdk-rust/blob/8f752e024576420f62030cc539a73176d1a5d099/src/pagination.rs)
also forwards visibility filters through `WorkflowListOptions::query`.
Constructors perform no I/O. Iteration keeps one page and the original
namespace, filters and selected workflow/run. Empty continuation pages are
followed; cycles and page failures return typed errors. History iteration does
not follow continue-as-new or subscribe indefinitely.

The [installed Rust 4.6.0 receipt](https://github.com/durable-workflow/sdk-rust/issues/122#issuecomment-6363352910)
records eight HTTP/Stream controls and published Server 2.11.0 acceptance with
three filtered runs across three list pages and twelve events across six
history pages. That tuple is separate from the recorded Sample App Rust 4.1.0 /
Server 2.10.0 cohort. The receipt does not qualify another SDK or newer tuple.

The existing [child reader](https://github.com/durable-workflow/sample-app/blob/main/polyglot/python_worker/scripts/sdk_children.py)
and activity-recovery/update readers join history pages explicitly and reject
repeated tokens. Their constructed reader controls, such as the child's
two-page test, verify observer behavior. They do not prove an SDK-provided
iterator or a multi-page result against a live published Server.

The published CLI's `workflow:history --output=json` collects all returned pages
into one document. `--output=jsonl` emits events page by page instead of
buffering the whole history. Check the command's final exit status before
accepting either output; an interrupted stream is partial evidence.

Force at least two actual pages for a claimed pagination qualification. Use a
controlled, stable data set for completeness claims. Verify the expected
identities, order, typed data and end condition with no omitted or duplicate
records. Preserve the declared observation budget. Repeated tokens, a
middle-page error or a missing end condition cannot become a pass from the
records already collected. For a running workflow, identify the observed
history prefix rather than claiming a terminal history.

The installed worker paged-tail/cache results in
[#124](https://github.com/durable-workflow/.github/issues/124) remain bound to
their recorded tuple and worker behavior. They do not qualify client history
or list iterators. Remaining SDK helpers and cross-SDK qualification stay in
[#247](https://github.com/durable-workflow/.github/issues/247). The separate Rust
receipt does not complete the PHP/Python requirement. Manual loops and
documentation corrections do not complete the accepted product capability.
Use each installed SDK's actual supported API.

## Run the published Nexus caller cases

The Server repository's
[Published Nexus SDK execution workflow](https://github.com/durable-workflow/server/blob/main/.github/workflows/published-nexus-sdk-callers.yml)
uses its declared frozen published tuple. Run it through GitHub Actions:

```sh
gh workflow run published-nexus-sdk-callers.yml --repo durable-workflow/server --ref main
```

Record the resulting run ID and runner commit. Review the execution step's
scenario assertions and the bounded `Nexus SDK outcomes` notices. Its
`nexus-sdk-callers-RUN_ID-ATTEMPT` artifact retains `pins.json`, `outcomes.json`,
bounded reports and the complete suite's exit code for one day. The report
budget is 2 MiB; `outcomes.json` lists reports omitted to preserve that bound.
It does not retain every probe's raw output. Maintainers may remove
completed reports after recording verified outcomes in the owning issue.
A passing focused workflow does not make every scenario in
`nexus-conformance-result.json` a pass. Missing cells keep their recorded
`not_covered` outcome.

The authored callers wait for terminal service history and preserve their
original namespace, run, call, target and operation sequence. Each of the four
PHP/Python caller/service directions runs in both same and cross namespaces.
Handled failure cases catch the service's typed exception at the original call
and complete with an error result. Separate uncaught cases rethrow that same
exception and require the public client's workflow-failure exception, the
original remote cause, one `ServiceCallFailed` and one caller `WorkflowFailed`.
They preserve the original endpoint, call/run/link, acceptance time and deadline
across all four directions and both namespaces, within each thirty-second budget.
Cancellation cases request cooperative
cancellation of the linked target directly, then deliver its cancelled outcome
to the waiting caller. Separate waiting-caller cases request cancellation of
the caller and require propagation to its linked target, preserving the
original request, call and deadline.

The recovery probes kill the original caller process and use a distinct
replacement to finish the same run. A separate probe kills and restarts MySQL
while the target has a pending timer. Require preserved history, original
identity and deadline, the expected service result, one terminal delivery and
clean replacement exits within the original budget. Backend readiness fails
during the outage and recovers after restart.

The external-payload cases send arguments and results larger than 4 MiB,
kill the waiting caller and finish the original call in a new process. Require
exact hashes, integer type, explicit null and Unicode, owner-namespace HTTP 200
with exact bytes, and unrelated-namespace HTTP 404. The PHP observer uses a
128 MiB limit and records its peak. Each original keeps its thirty-second budget.
Authored worker-only callers must receive the typed permission failure before
target dispatch, with no acceptance timestamp or linked target. A read-only
audit checks the actual stored principal roles.

Embedded execution has a separate
[normally installed Core qualification](https://github.com/durable-workflow/workflow/blob/main/examples/embedded-http/qualification/nexus.md)
using real database-queue processes. API/browser/CLI inspection uses the
[published service-catalog consumer](https://github.com/durable-workflow/waterline/blob/main/.github/workflows/published-service-catalog.yml).
These paths do not share a runtime acceptance result with the SDK workflow.
[Workflow #753](https://github.com/durable-workflow/workflow/issues/753#issuecomment-6247569474)
records the published-artifact and consumer acceptance. Each new affected tuple
needs its own execution. Native Server support remains separately qualified.

## Run and interpret Rust Nexus cases

Follow the Rust SDK's [Nexus HTTP qualification instructions](https://github.com/durable-workflow/sdk-rust/blob/main/tests/nexus/README.md)
for dependencies, the disposable state directory and isolated Compose backend.
The documented preparation builds `examples/nexus_cooperation.rs` from the
checkout. These are source qualification commands, not automatic
registry-installed acceptance:

```sh
bash tests/nexus/run.sh
bash tests/nexus/run.sh cross-outcomes
bash tests/nexus/run.sh acknowledgement
bash tests/nexus/run.sh admission
bash tests/nexus/run.sh cross-namespace
```

Choose a fresh backend and case identities for each selected profile as the
owning instructions require. The default profile checks cancellation across
the five Rust-involving directions plus a killed/cold Rust target.
`cross-outcomes` covers those five directions, both namespace directions and
success, typed failure, external values and missing operations. The
acknowledgement profile loses an actual recorded completion response across
all four namespace pairs, then requires cold replay of the original call.
Admission profiles exercise their declared ordinary/cold sync/async waiting
cells. A bounded selection is not the full admission matrix.

For installed acceptance, build the actor from the normally downloaded crate
example without a path dependency or source override. Record the registry
checksum, embedded source, actor identity, counterparts, image digest and each
executed profile. [Rust SDK #86](https://github.com/durable-workflow/sdk-rust/issues/86)
and its installed receipt distinguish the selected 72 originals from the
larger source admission cohort and retain earlier failed outcomes. That receipt
does not qualify a new tuple or the optional `catalog` browser profile.

Preserve the original call, target, histories and separate cleanup/service
deadlines. Lost-acknowledgement evidence must positively identify the original
physical task and attempt as completed before and after retirement. An
aggregate repair count cannot prove which task was recovered. Retire the
selected Compose backend and fixture state after recording sanitized results,
including after failure. Do not change the frozen Server lane to make these
separate results look like one experiment.

## Run and interpret a cell

1. Freeze the seven-component published tuple and runner revision. Select a
   supported capability from those installed artifacts, not a different checkout.
2. Follow the owning runner's `--help` or example README. Use its isolated project,
   worker/client credentials and queues. For Sample App timers, resolve the
   checked-in tuple and run `scripts/sdk-timers.sh` as documented in
   [`polyglot/timers/`](https://github.com/durable-workflow/sample-app/blob/main/polyglot/timers/README.md).
3. Observe the actual language, run identity, result and persisted lifecycle
   events. For retries/timeouts record attempts and original deadlines. For
   cancellation distinguish request, committed delivery, cleanup and terminal
   outcome. For recovery record the physical failure and replacement process.
4. Reject early timer fire, changed deadlines, lost acknowledged work, duplicate
   completion, unexecuted directions and drains that were not measured. Keep a
   harness failure separate from a product failure.
5. Remove the task stack and scratch state, including after failure. Report the
   exact command, UTC interval, tuple, runner SHA and scenario outcomes in the
   owning issue. Retain bounded diagnostic output through the existing GitHub
   Actions artifact mechanism when needed. Never commit generated run evidence.

The Nexus entry follows the existing published SDK execution workflow and its
individual probe reports. A new release still needs new runtime results for
its affected cells. This document is not a second release tracker.
