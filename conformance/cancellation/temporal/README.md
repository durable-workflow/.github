# Published Temporal cancellation behavior

This fixture tests a Python parent, child and activity with published Temporal
artifacts. Exact versions and the verified Linux amd64 CLI archive are in
`versions.json`. The CLI runs its embedded development Server with SQLite.
The Python SDK is pinned in `requirements.txt` and both container images are
pinned by digest in `compose.yml`.

The fixture uses explicit `WAIT_CANCELLATION_COMPLETED` policies for the child
and activity, `REQUEST_CANCEL` on parent close, shielded cleanup, and an explicit
workflow acknowledgement after an awaited operation returns. This last step
keeps a pending cancellation from becoming a normal successful workflow result
when an activity completes before observing the request.

Both workflow-task timeouts are two seconds. The workflow cache retains its SDK
default. Heartbeating remote activities configure a two-second heartbeat timeout
and 100 ms worker heartbeat throttles. These are deliberate comparison settings,
not a production sizing recommendation.

## Run

Use Docker Compose on Linux amd64. No host language tooling or published ports
are needed. Downloading the checksum-verified CLI requires access to GitHub.

```sh
mkdir -p evidence
chmod 0777 evidence
docker compose -p cancellation-temporal up -d
docker compose -p cancellation-temporal exec -T sdk sh -ec '
  python -m venv /tmp/venv
  /tmp/venv/bin/pip install --no-cache-dir --report /evidence/packages.json -r requirements.txt
  /tmp/venv/bin/python scenario.py
'
docker compose -p cancellation-temporal down -v --remove-orphans
```

The scenario waits for the Server and default namespace, then runs three
repetitions of six cases:

| Case | Physical callback observation | Durable outcome |
| --- | --- | --- |
| Async remote, application heartbeats | Stops before its late effect | Parent and child CANCELED, cleanup completes |
| Async remote, no application heartbeats | Runs twelve seconds and performs the late effect | Parent and child CANCELED after explicit acknowledgement, cleanup completes |
| Async local, no application heartbeats | Stops before its late effect | Parent and child CANCELED, cleanup completes |
| Blocking local, no application heartbeats | Thread exits after its twelve-second sleep, without the late effect | Parent and child CANCELED, cleanup completes |
| Worker SIGKILL during committed root cleanup timer | Fresh worker resumes the original timer, one cleanup entry | Parent and child CANCELED, cleanup completes |
| Another cancellation during committed root cleanup timer | One original request and reason, one original timer | Parent and child CANCELED, cleanup completes |

The last two cases also submit stale activity results while root cleanup is
running and require rejection. All remote cases submit another stale result
after workflow closure and require rejection. `results.jsonl` retains complete
parent/child histories, callback process IDs, physical exit markers, request
timestamps, cleanup outcomes and per-repetition elapsed times. A failed assertion
exits nonzero after preserving the observations.

These are cancellation semantics checks. Latency is recorded to distinguish
physical callback exit from durable acknowledgement, not to rank throughput or
production configurations. The original local comparison stopped heartbeating
remote callbacks in about one second and async local callbacks in about two
seconds. Recovery and repeated cancellation both completed durable cleanup.

Temporal documents the heartbeat requirement for remote activity cancellation
and the different local activity behavior in its
[Python cancellation guide](https://docs.temporal.io/develop/python/workflows/cancellation).
The fixture tests that documented distinction with explicit waiting policies.
It does not establish a general winner or describe another Temporal SDK's
callback execution model.
