# Published Restate cancellation experiment

This fixture supports [cancellation issue 136](https://github.com/durable-workflow/.github/issues/136). It exercises Restate Server 1.7.13 and Python SDK 1.0.5 through the documented cooperative cancellation API. It measures behavior, not runtime throughput.

The parent and child are durable Restate Workflows. The child calls a leaf service. Each handler catches `TerminalError`, performs durable compensation and rethrows, following [Restate's cancellation guidance](https://docs.restate.dev/services/invocation/managing-invocations).

## Cases

Three repetitions each:

- Cancel a durable wait and inspect all three invocation outcomes.
- Cancel an asynchronous `ctx.run_typed` callback, with no application heartbeat. Observe its actual exit and a possible late side effect.
- Cancel a blocking `ctx.run_typed` callback. Wait for actual callback exit even if the durable invocation already completed.
- SIGKILL the SDK endpoint after root cleanup starts. Start a fresh process and inspect journal replay and cleanup completion.
- Repeat cancellation while root cleanup awaits a durable timer. Inspect whether cleanup completes.

The callback duration is 12 seconds. Recovery and duplicate cases insert a three-second durable wait between two cleanup actions. Application markers and durable `sys_invocation` records are retained separately. A cancellation result cannot stand in for callback exit or completed compensation.

## Run

Use Docker Compose and a host checkout owned by UID/GID 1000. No host ports are published. The runtime is isolated and its database is disposable.

```sh
cd conformance/cancellation/restate
docker compose -p cancellation-restate up -d --wait
docker compose -p cancellation-restate exec -T sdk sh -ec '
  python -m venv /tmp/venv
  /tmp/venv/bin/pip install --no-cache-dir --report /experiment/packages.json -r requirements.txt
  /tmp/venv/bin/python scenario.py
  /tmp/venv/bin/python scenario.py duplicate
'
mkdir -p evidence
docker compose -p cancellation-restate cp sdk:/experiment/results.jsonl evidence/results.jsonl
docker compose -p cancellation-restate cp sdk:/experiment/events.jsonl evidence/events.jsonl
docker compose -p cancellation-restate cp sdk:/experiment/packages.json evidence/packages.json
docker compose -p cancellation-restate cp sdk:/experiment/service.log evidence/service.log
docker compose -p cancellation-restate logs runtime > evidence/runtime.log
docker compose -p cancellation-restate down -v --remove-orphans
```

Keep measured failures and successes. Setup and import failures do not establish cancellation behavior. Read each case's application observations and durable outcomes before drawing a conclusion. The fixture records observed behavior without requiring another product to satisfy Durable Workflow's contract.

The pinned images and installed-package report bind each run to published artifacts. This comparison does not qualify Durable Workflow's unpublished cancellation candidate or replace its required published mixed-language cascade.
