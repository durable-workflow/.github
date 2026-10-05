# Published DBOS cancellation behavior

This fixture uses the published Python SDK pinned in `requirements.txt` and
the digest-pinned Python image in `compose.yml`. SQLite stores synthetic
workflows in the container, and ordinary evidence files retain the observations.
No network service, application heartbeats or host ports are required.

The request explicitly sets `cancel_children=True`. Async work enables the
supported `preemptible=True` step option. Blocking work uses a synchronous
step through `asyncio.to_thread` so it does not block the event loop or the
cancellation observer.

## Run

```sh
mkdir -p evidence
chmod 0777 evidence
docker compose -p cancellation-dbos up -d
docker compose -p cancellation-dbos exec -T sdk sh -ec '
  python -m venv /tmp/venv
  /tmp/venv/bin/pip install --no-cache-dir --report /evidence/packages.json -r requirements.txt
  /tmp/venv/bin/python scenario.py
'
docker compose -p cancellation-dbos down -v --remove-orphans
```

Three repetitions of seven cases record the physical callback, stored workflow
status and durable step outcomes separately:

| Case | Observation |
| --- | --- |
| Preemptible async step with plain shielded cleanup | Work stops without heartbeats and its three-second cleanup completes while parent/child status is already CANCELLED |
| Blocking synchronous step | Runs its twelve-second sleep and performs a late effect, with no completed step checkpoint |
| Durable workflow steps in cancellation cleanup | Parent and child enter `finally`, but their cancelled workflow authority refuses the cleanup steps |
| Separately queued durable compensation | Completes with SUCCESS after the original parent/child are CANCELLED |
| Worker SIGKILL during plain step cleanup | A fresh worker does not automatically resume that cleanup in the four-second observation window, and the original runs remain CANCELLED |
| Worker SIGKILL during separately durable compensation | A fresh worker resumes its committed timer and completes compensation |
| Another cancellation during separately durable compensation | Original parent/child remain CANCELLED and compensation completes |

The separately durable compensation has a stable workflow ID derived from the
original parent. The controller starts it outside the cancelled ancestry after
observing the callback's exit. Its entered step and `DBOS.sleep` are committed
before SIGKILL. This is an application pattern using supported APIs. The
application explicitly starts compensation and manages its relationship to
the cancellation request.

`results.jsonl` records workflow statuses and public step inspection, process IDs,
request timestamps, callback exit and cleanup markers. Each run checks the
observed outcomes, and compensation finishes within thirty seconds of the
original request. That observed duration is separate from a native cancellation
budget. Physical stop is separate from an immediately recorded CANCELLED status.
The scenario retains raw results before an assertion fails.

The elapsed times locate callback exit and cleanup completion in each case.
The fixture demonstrates DBOS's useful async preemption and durable recovery pattern as well
as their operational boundaries. See the official
[workflow management guide](https://docs.dbos.dev/python/tutorials/workflow-management),
[preemptible step reference](https://docs.dbos.dev/python/reference/decorators),
and [recursive cancellation API](https://docs.dbos.dev/python/reference/contexts#cancel_workflow).
