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
- Schedule creation follows the installed client's API. PHP and Python can
  create schedules targeting any of the three workflow languages. The Rust
  SDK currently has no schedule creation API. Do not invent a Rust creator.
- Nexus follows advertised support in the exact tuple. The current PHP/Python
  caller and service APIs give four meaningful directions. Rust has no Nexus
  API. A raw HTTP call from a Rust test process would not prove SDK support.
- Rust supports update handlers and clients but refuses synchronous pre-accept
  update validators. Exercise ordinary Rust updates and its explicit capability
  refusal. PHP/Python validator execution has its own supported directions.
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
| Authoring, inputs/results and remote activities: Sample App `scripts/polyglot.sh`, full matrix in `polyglot/README.md`; Server `activities-published-artifacts.sh` | Featured PHP → Python → Rust journey and the full nine-direction activity matrix are separate commands. Server's activity manifest primarily uses embedded PHP/Python activity cells, with a focused PHP SDK heartbeat-renewal shard. | The nine successful result directions do not prove Rust retry, timeout, duplicate completion or activity-attempt recovery. Run these behaviors with actual SDK workers and persisted attempts. |
| Child workflows: Server `child-workflows-published-artifacts.sh`; Sample App `polyglot/child-workflows/` | Server's four embedded PHP/Python parent-child directions and Sample App's nine PHP/Python/Rust SDK directions. | Sample App checks successful child result/history. Add Rust-involving child failures, restart/replay and cancellation. Do not project the Server runner's PHP/Python failure/restart cells onto Rust. |
| Heartbeats: Server `heartbeats-published-artifacts.sh`, `heartbeats-python-published-artifacts.sh`, `heartbeats-rust-published-artifacts.sh`, shared wave runner | All three actual SDK worker heartbeat loops, cadence, metrics, stale transitions and routing exclusion. | Use each runtime's scenario results. A worker heartbeat pass is separate from activity progress heartbeat and cancellation observation. |
| Timers: Server `timers-published-artifacts.sh`; Sample App `scripts/sdk-timers.sh` | Server's embedded PHP timer scenarios. Sample App supplies separate PHP/Python/Rust SDK completion, worker SIGKILL/cold replay, Server restart and cooperative cancellation cells. | Concurrent distinct deadlines and timer-bearing application upgrades need separate SDK execution. |
| Sagas: Server `sagas-published-artifacts.sh`; Sample App `polyglot/sagas/` | Server's PHP/Python workflow-compensation directions; Sample App's five Rust-involving directions, typed compensation failure and restart before compensation. | Process loss during an external compensation side effect, duplicate delivery and external-effect recovery require explicit side-effect fixtures. Restart before compensation does not establish them. |
| Schedules: Server `schedules-published-artifacts.sh`; Sample App `polyglot/schedules/` | PHP/Python creators and workers in Server; PHP and Python creators targeting Rust in Sample App. | The Rust examples check one automatic interval fire. Run cadence, restart, overlap/backfill and failure recovery for those directions. Calendar folds/gaps are temporal cases, not extra creator languages. |
| Signals and queries: Server `signals-queries-published-artifacts.sh` | PHP/Python/Rust clients and workers, including cross-language calls, Rust query immutability and cold-restarted instance state. | Read the direction-specific scenarios and histories. The crate pin alone proves none of them. |
| Workflow updates: Server `workflow-updates-published-artifacts.sh`; Sample App `scripts/sdk-updates.sh` | Server's embedded probe, PHP SDK client/worker process boundary, Python installed-package surface fixtures, CLI and Waterline diagnostics. The Python fixture uses simulated HTTP responses. Sample App separately executes all nine PHP/Python/Rust client-to-handler directions against a live published Server, plus Rust replacement, duplicate acceptance/completion, handler failure and validator refusal. | The nine result directions do not establish stateful update mutation, every command-ordering race or process loss during a handler's external effect. Rust refuses synchronous pre-accept validators. Retain the supported PHP/Python validation cells. |
| Deterministic replay: Server `replay-published-artifacts.sh` | Separate installed PHP, Python and Rust replay shards, command/history matching and codec behavior. | Corpus replay does not prove worker process recovery or migration. Pair affected histories with their runtime restart and upgrade cases. |
| Workflow lifecycle: Server `workflow-lifecycle-host-published-artifacts.sh` | Docker host wrapper builds the exact published Rust probe and starts the published Server; inner runner includes PHP/Python/Rust lifecycle surfaces. | Select real continuation, retry/timeout, cancellation and termination scenarios. Terminal cancellation and cooperative cleanup are separate contracts. |
| Worker versioning: Server `worker-versioning-published-artifacts.sh` | Actual PHP/Python build cohorts and mixed pinning, plus Python no-compatible-worker, replay and adversarial shards. | Rust build pinning, promotion, incompatible refusal, replacement and cold replay need an execution shard. |
| Namespaces: Server `namespaces-published-artifacts.sh` | Server authorization/routing, PHP and Python SDK paths, CLI and Waterline namespace surfaces. | Rust clients/workers need positive and negative namespace execution. A shared Server authorization assertion alone does not prove their header and credential composition. |
| Search attributes: Server `search-attributes-published-artifacts.sh` | PHP SDK, Waterline and PHP/Python codec shards, or supplied host matrix evidence. | Add Rust authoring/client filters and value round trips. Supplied evidence must come from a real worker run, not a hand-written passing result. |
| Nexus: Server `nexus-published-artifacts.sh` | Published PHP/Python caller/service execution, shared-service behavior, replay and cancellation probes. | Require all four supported caller/service directions and their actual async completion, typed failure and cancellation evidence. Rust is outside the current API scope. |
| 1.x → 2.x migration: Server `migration-published-artifacts.sh` | Supported 1.x PHP artifacts and their durable state, target PHP/Python and operator surfaces. | Rust has no 1.x source artifact to migrate. Rust starting against the migrated target is a meaningful post-migration case. SDK upgrades within 2.x/3.x are separate from this engine migration. |
| Compatibility skew: Server `skew-published-artifacts.sh` | CLI, PHP/Python SDK, Waterline and worker protocol pairings. | Add Rust's supported and refused protocol pairings. A major SDK package number is not itself a worker protocol compatibility boundary. |
| Principal attribution: Server `principal-attribution-published-artifacts.sh` | Named/anonymous/raw HTTP actors, PHP/Python clients, worker completion/failure, CLI and Waterline. | Rust SDK credentials and worker history need their own attribution and spoofing-refusal execution. |
| Cooperative cancellation and worker affinity: SDK integration suites, public qualification records and the timer command above | Source integration tests exist in every SDK. Published local-activity/session and mixed-cancellation qualifications are distinct release evidence. | Keep installed-package proof separate from source CI. Check current capabilities: Python/Rust local activities and sessions are released, while sticky execution remains refused and is owned by [.github #124](https://github.com/durable-workflow/.github/issues/124). Older affinity manifest expectations must not override the tested tuple's capabilities. |
| Failover and diagnosis: Server `single-region-failover-published-artifacts.sh`, `agent-operability-published-artifacts.sh`; [operator diagnosis drill](operator-diagnosis.md) | Published container/backend failover and public API/CLI/Waterline operator paths. | Backend recovery success is not three-language workflow continuity. Include affected workers and pending work when that is the customer claim. Embedded Laravel injection/testing remains a PHP framework-specific case. |
| Managed Cloud | Private Cloud repository's isolated qualification | Keep account, provisioning, provider chaos and commercial qualification private. Public SDK protocol coverage does not establish managed-plan capacity or Cloud recovery. |

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

This inventory was checked against Server `d97727113cef0d92228627eecb47988b0955aad9`
and the public Sample App timer change. A new release still needs new runtime
results for its affected cells. This document is not a second release tracker.
