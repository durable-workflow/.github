# Self-hosted operator diagnosis drill

This drill checks whether an operator can understand a stalled workflow and
recover it using published CLI, Server API, Waterline and documentation.
Use an isolated synthetic stack and published artifacts. Record their exact
versions and image digests. Keep the staged fault and reference state separate
from the investigator's observations.

## Start with the original workflow

Use the published CLI to inspect the workflow and the queue it actually targets:

```sh
dw workflow:describe WORKFLOW_ID --json
dw task-queue:describe TASK_QUEUE --json
dw doctor --output=json
dw workflow:history WORKFLOW_ID RUN_ID --output=json
```

Supply the Server endpoint, namespace and operator credential through the
CLI's documented connection options or profile. Inspect `/api/ready` for the
scope and outcome of its checks. In Waterline, use **Workers** for registrations,
queue affinity, heartbeat freshness and leases, then the original run's detail
page for activity attempts, history and pending recovery paths.

Keep the original run ID before acting. After recovery, verify its final status,
expected result and history. A process that is running, a readable dashboard
or a successful database connection alone does not establish that work is
being completed.

## Six cases

| Case | Evidence to inspect | Safe next action and expected behavior |
| --- | --- | --- |
| Absent application worker | Pending run, ready task, no active poller on its queue | Start a compatible worker with the workflow and activity registered on that queue. The original task should be claimed and the same run should complete. |
| Wrong queue | Run's target queue has ready work while a live worker polls another queue | Correct the worker's queue configuration and restart it. Check the advertised heartbeat window before treating a stopped worker's recent registration as current. Recover the original run. |
| Expired lease | Queue detail identifies the task, owner, expired deadline and repair candidate. Waterline shows expired leases. | Restore a compatible worker on the original queue and let the runtime reclaim the expired task. Inspect repair history and completion. Preserve lease fencing and keep activity side effects idempotent. |
| Retryable failed activity | Attempt failure, exception, retry limit and `retry_available_at` in history and Waterline | Restore the dependency and leave a healthy worker running. Allow the declared retry, then verify its attempt and the original result. Normal scheduled retries do not require a replacement workflow. |
| Backend interruption | Doctor/discovery reports an unavailable backend, readiness returns 503, Waterline cannot read health | Restore connectivity to the existing backend with its data intact. Recheck readiness and discovery, inspect the original run and queue, and resume its worker if needed. Inspect the outcome before retrying an ambiguous producer operation. |
| Database storage pressure | Failed write reports `database_storage_exhausted`, the resource and remediation. Readiness may still pass its connection check. | Stop avoidable writers and restore database or temporary-storage capacity. Preserve data and initial tablespace settings. Inspect the original operation before retrying. Verify acknowledged work and ensure rejected starts left no partial instance. |

The [Server storage recovery guide](https://github.com/durable-workflow/server/blob/main/docs/database-storage-recovery.md)
explains the bounded MySQL procedure and the limits of connection-only readiness.
Use the backend's documented recovery procedure for the actual storage system.
A full filler table can coexist with reusable allocations in other tables, so
record the actual failing durable operation rather than assuming every write
must fail.

## Record and repeat

For each case retain:

1. The clean reference, staged fault, exact published artifacts and resource limits.
2. Investigator commands, visible API/UI evidence, diagnosis and expected next behavior.
3. The chosen recovery action, original run identity, final result and history checks.
4. UTC start/end times for diagnosis and for recovery through verified state.
5. Product gaps, their owning fixes and the affected-case repeat after publication.

Count diagnosis from the first investigation command through the recorded
decision. Count recovery from the action through verification. Include policy
waits, heartbeat expiry and inspection delays. Report these as observations from
the recorded environment. A self-guided pass is not a blind investigator study
or a latency guarantee.

If another task interrupts a case, keep its interval separate from focused
timings. Preserve corrections in the work record. Retain sanitized results on
the owning issue or linked artifact, then remove the experiment's containers,
volumes and other resources. This drill does not replace protocol conformance
or qualify unexecuted SDK/runtime combinations.
