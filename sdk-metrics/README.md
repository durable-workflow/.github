# SDK client and worker metrics

[`contract.json`](contract.json) is the shared list of SDK recorder names,
instrument types, units and tag keys for PHP, Python and Rust. The original six
instruments capture the inspected Python recorder surface. Revision 2 adds the
schedule-to-start histogram defined below. Implementation, installed acceptance
and exporter-guide delivery remain separate from publishing this list.

Rust's recorder and optional Prometheus adapter have an
[installed-package receipt](https://github.com/durable-workflow/sdk-rust/pull/131#issuecomment-6364178456)
and [exporter guides in all eight locales](https://github.com/durable-workflow/durable-workflow.github.io/issues/388#issuecomment-6364644418).
Python's recorder correction and Prometheus adapter have a
[normal registry-installed receipt](https://github.com/durable-workflow/sdk-python/pull/213#issuecomment-6368689818)
and a published [metrics and exporter reference](https://python.durable-workflow.com/reference/metrics/).
PHP's client and worker recorder is shipped, with
[normal registry-installed Worker acceptance](https://github.com/durable-workflow/sdk-php/actions/runs/43400585178)
and a published [OpenTelemetry/exporter guide](https://php.durable-workflow.com/operate/metrics/).
The original six-instrument feature in
[#233](https://github.com/durable-workflow/.github/issues/233#issuecomment-6839951301)
is complete. Later contract revisions and installed tuples retain their own
adoption and qualification receipts.
One SDK's delivery does not establish another SDK's adoption.

Consumers should pin the contract's Git commit. SDK tests load that one list
and compare observations from their actual client and worker recorder hooks.
Offline tests may vendor its exact JSON bytes with the upstream commit and
SHA-256 recorded and verified. Update that copy from the shared contract,
without a second hand-maintained language-specific vocabulary.
The reference commit identifies the inspected implementation of the original
six instruments, not a required package version, implementation of later
additions, or release qualification.

## Recorder observations

The client and worker accept a recorder with `increment(name, value, tags)`
and `record(name, value, tags)` operations. Language-specific method spelling
may differ. The default recorder discards observations. The worker uses its
explicit recorder, otherwise its client's recorder, otherwise the no-op.

The client-request, worker-poll and worker-task observations each increment
their counter by one and record one nonnegative monotonic duration in seconds
with the same tag map. The schedule-to-start instrument is a separate histogram
without a paired counter. Unit `1` is a count, and `s` is seconds. Tags are
strings and tag ordering is immaterial.
Only the listed tag keys belong to each core metric. Exporters may add resource
labels separately. Recorders should be fast and must handle their own exporter
failures without throwing into the client or worker.

| Scope | Count and duration mean |
| --- | --- |
| `client_request` | One instrumented client request, including its transport retries, backoff and response handling. This is not a count of individual HTTP attempts. |
| `worker_poll` | One observed poll result and its elapsed polling time. Empty polls, backpressure and errors remain distinct from a delivered task. |
| `worker_task` | One dispatch of a claimed workflow, activity, query or supported update-validation task and its processing time. A completed task does not establish a completed workflow. Replay and retries can produce more dispatches. |
| `worker_task_dispatch` | A valid Server-measured eligibility-to-lease duration for a workflow or activity task that this worker actually dispatches. This excludes delivery and processing time. |

These counters describe process observations. They are not durable execution
counts, exactly-once receipts, billing units or schedule-to-start latency.
Missing observations are not zero or healthy. Abrupt process loss can prevent
the final observation.

## Schedule-to-start observations

Revision 2 adds `durable_workflow_worker_task_schedule_to_start_seconds`, a
histogram recorded with `record` in seconds. It has exactly `task_kind` and
`task_queue` tags. Only `workflow` and `activity` dispatches belong to this
instrument. It has no outcome tag or paired counter. Existing instruments and
their meanings are unchanged.

The [accepted field and clock decision](https://github.com/durable-workflow/sdk-python/issues/188#issuecomment-6629640808)
requires `server_capabilities.claimed_task_ready_age` to be Boolean `true` and
optional, non-null `task.ready_age_ms`. The SDK accepts an actual integer from `0` through
`9007199254740991`, excludes booleans and coercion, and records the value divided
by `1000` on actual dispatch. It does not observe transport retries or empty,
denied, stale, query or update-validation answers. A replayed poll receipt keeps
the original lease's value. A genuinely new lease has its own ready origin.
These remain worker dispatch observations, not exactly-once execution counts.

Server measures from the claimed attempt's known eligibility instant to the
same committed lease timestamp used by its claim transaction. Scheduled delay
and retry backoff are excluded. New creation, retry, release and expired-lease
transitions must retain the appropriate origin. An old creation timestamp must
not stand in for an unknown later ready transition. Neither worker wall-clock
subtraction nor aggregate backlog age measures this boundary. Server clock
assumptions still apply across nodes.

An unsupported capability, missing value or unknown legacy origin produces no
sample. Malformed, negative, non-integral or out-of-range values produce no
sample and only a bounded diagnostic. Server checks a signed duration before
flooring valid nonnegative values to milliseconds. A real zero, including a
valid sub-millisecond duration quantized to zero, is recorded. Never replace
missing or invalid data with zero or clamp a negative duration. No workflow,
run, task, attempt, worker or session identity belongs in the metric tags.

Publishing this contract does not add the claim field to a Server, implement an
SDK hook, or qualify an installed package. Those gates remain on the owning
Server and SDK issues. SDKs pinned to revision 1 retain their existing six
instruments until they explicitly adopt a later contract commit.

## Tag values

Client metrics have `method`, `route`, `plane`, `status_code` and `outcome`:

- `method` is the uppercase HTTP method. `route` uses reviewed path templates
  without the `/api` prefix or query string. For example,
  `/workflows/{workflow_id}/signal/{name}` and `/schedules/{schedule_id}`
  preserve the Python reference's placeholders.
- `plane` is `control` or `worker`, according to the credential plane used by
  the request. Discovery using a worker credential uses `worker`.
- `status_code` is the response's decimal status string, or `none` when no
  response status was recorded.
- `outcome` includes `ok`, `http_error` and `bridge_rejected`. Other caught
  failures use language-specific exception or error categories. The pinned
  Python reference can also retain `pending` when cancellation bypasses its
  ordinary exception handler. These values are not an exhaustive portable
  error taxonomy. Dashboards should not assume those categories match between
  languages.

Worker poll and processing metrics have `task_kind`, `task_queue` and `outcome`.
The schedule-to-start histogram uses only the first two:

- `task_kind` identifies `workflow`, `activity`, `query` or supported
  `update_validation` work. Unsupported task kinds do not create new SDK
  capabilities merely because they appear here.
- `task_queue` is the configured queue name. Applications should use bounded
  queue naming rather than a new queue per run.
- Poll outcomes include `task`, `empty`, `backpressure` and `error`. Task
  outcomes describe processing, such as `completed`, `failed`, `expired` or
  `approved`, and can differ by task kind. Keep a task's outcome separate from
  its workflow's eventual terminal state.

Core tags must not contain workflow, run, task, worker or session IDs, payloads,
credentials, exception messages or raw URLs. Use placeholders for variable path
segments, and a bounded `unknown` route value for an unrecognized operation.
Queue names remain application-controlled. Exporter resource labels need their
own cardinality and privacy review.

The pinned Python reference predates normalization of update-validation task
and worker-session routes and retains literal IDs there. Those values are not
approved tag shapes. The correction has separate
[published-package and normal registry-installed acceptance](https://github.com/durable-workflow/sdk-python/pull/213#issuecomment-6368689818).
Use that receipt and the installed package's guide when qualifying consumers.
The JSON retains its original reference and records the inspected metric names,
instruments and tag keys. It does not certify bounded values or cross-SDK adoption.
Additional operations need explicit normalization and outcome review.

## Export and compatibility

The names in the JSON file are recorder names. A Prometheus counter exporter
can append `_total`, and a histogram exporter produces its normal bucket,
sum and count series. Those exporter conventions do not rename the recorder
contract. OpenTelemetry adapters use the listed instrument type and unit.
Histogram buckets, exporter resource labels and transport configuration are
application choices.

Treat adopted names, types, units, tag keys and their meanings as stable SDK
API. Renaming/removing a metric or tag key, changing an instrument or unit,
or changing an existing metric's required tag set needs an SDK major release
and migration guidance. Announce additional metrics and new or changed tag
values in the SDK changelog. An incompatible contract uses a new schema
identity. Compatible additions increment `revision` and preserve existing
entries. Python's current exception-type outcomes remain language-specific.

## SDK acceptance

Each SDK must exercise its actual recorder on successful and failed requests,
transport retry, normalized routes, empty/delivered/error/backpressure polls,
and supported task success/failure paths. Check the names, recorder operations,
tag keys and string values against the pinned contract. For the original three
scopes, require a counter increment of one and a matching nonnegative duration
observation for each completed observed operation. Compare deterministic outcomes between SDKs,
while keeping language-specific exceptions explicit. Exercise default no-op,
client-to-worker inheritance and an explicit worker override.

Include variable-ID route pairs for workflow/run/task/worker/session operations,
queries containing synthetic secrets and unknown paths. Changing an ID or
query must not create a new route series or expose its value. Never replace
this check with an assertion that the tag key is merely named `route`.

Use installed-package checks for the published adapters and examples. Record
each SDK's package and guide results on #233, preserving the completed Rust
and Python receipts and PHP's remaining work. Source inspection and this
contract's tests do not provide that runtime evidence.

The schedule-to-start addition also needs actual recorder and installed-package
checks for both task kinds, delayed/retried/released/expired attempts, valid zero,
unknown legacy origins, malformed and clock-invalid values, and receipt replay
versus a new lease. Verify exact values and the two tag keys, absence of samples
when unsupported, and no duplicate observation from HTTP retries. Retain normal
old-client behavior. Use the exact published Server and installed SDK before
calling this addition delivered.
