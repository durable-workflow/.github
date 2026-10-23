# SDK client and worker metrics

[`contract.json`](contract.json) is the shared list of SDK recorder names,
instrument types, units and tag keys for PHP, Python and Rust. It captures the
existing Python recorder surface. PHP/Rust implementation, SDK tests and user
guides remain tracked in [#233](https://github.com/durable-workflow/.github/issues/233).
Publishing this list does not establish that an SDK emits it.

Consumers should pin the contract's Git commit. SDK tests load that one list
and compare observations from their actual client and worker recorder hooks.
Do not maintain a second language-specific list of metric names and labels.
The reference commit identifies the inspected implementation, not a required
package version or release qualification.

## Recorder observations

The client and worker accept a recorder with `increment(name, value, tags)`
and `record(name, value, tags)` operations. Language-specific method spelling
may differ. The default recorder discards observations. The worker uses its
explicit recorder, otherwise its client's recorder, otherwise the no-op.

Each observed operation increments its counter by one and records one
nonnegative monotonic duration in seconds with the same tag map. Unit `1` is a
count, and `s` is seconds. Tags are strings and tag ordering is immaterial.
Only the listed tag keys belong to each core metric. Exporters may add resource
labels separately. Recorders should be fast and must handle their own exporter
failures without throwing into the client or worker.

| Scope | Count and duration mean |
| --- | --- |
| `client_request` | One instrumented client request, including its transport retries, backoff and response handling. This is not a count of individual HTTP attempts. |
| `worker_poll` | One observed poll result and its elapsed polling time. Empty polls, backpressure and errors remain distinct from a delivered task. |
| `worker_task` | One dispatch of a claimed workflow, activity, query or supported update-validation task and its processing time. A completed task does not establish a completed workflow. Replay and retries can produce more dispatches. |

These counters describe process observations. They are not durable execution
counts, exactly-once receipts, billing units or schedule-to-start latency.
Missing observations are not zero or healthy. Abrupt process loss can prevent
the final observation.

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
  exceptions use the language's exception type name. Python can also retain
  `pending` when cancellation bypasses its ordinary exception handler. These
  values are not an exhaustive portable error taxonomy. Dashboards should
  not assume exception class names match between languages.

Worker metrics have `task_kind`, `task_queue` and `outcome`:

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

The Python reference does not yet meet that route requirement for every newer
operation. In particular, update-validation task and worker-session paths retain
literal IDs. Those are implementation gaps in #233, not approved tag shapes.
The JSON list records Python's actual metric names, instruments and tag keys;
it does not certify bounded values or cross-SDK adoption. Additional operations
need explicit normalization and outcome review.

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
tag keys and string values against the pinned contract. Require a counter
increment of one and a matching nonnegative duration observation for each
completed observed operation. Compare deterministic outcomes between SDKs,
while keeping language-specific exceptions explicit. Exercise default no-op,
client-to-worker inheritance and an explicit worker override.

Include variable-ID route pairs for workflow/run/task/worker/session operations,
queries containing synthetic secrets and unknown paths. Changing an ID or
query must not create a new route series or expose its value. Never replace
this check with an assertion that the tag key is merely named `route`.

Use installed-package checks for the published adapters and examples. Keep
PHP/Rust adoption and all-locale Prometheus/OpenTelemetry guides open until
those results are recorded on #233. Source inspection and this contract's
tests do not provide that runtime evidence.
