# Replay-safe clock, version 1

Cross-SDK conformance case for [issue 215](https://github.com/durable-workflow/.github/issues/215).
The same history and the same `replay_clock` carrier
([`WorkerReplayClock` v1](https://github.com/durable-workflow/server/blob/main/docs/contracts/worker-replay-entry-clock.md))
must give the same replay-safe clock values in every binding:

| Binding | Clock | Replayed through |
| --- | --- | --- |
| `python` | `ctx.replay_now()` | `durable_workflow.testing.replay_history(..., replay_clock_entry=...)` |
| `rust` | `WorkflowContext::replay_now()` | `WorkflowHistory::replay_clock(...)` and `WorkflowEnvironment::replay` |
| `php` | `WorkflowContext::replayNow()` | `WorkerTestHarness::runWorkflow(..., task: ['replay_clock' => ...])` |
| `embedded-worker-protocol` | `Workflow::now()` | `WorkflowFiberRunner::forClass(..., replayClock: ...)` |

[`vectors-v1.json`](vectors-v1.json) holds:
- one history: a start, an activity and a two-second timer. Its `WorkflowStarted` insertion time is deliberately not the run's start;
- the cases;
- the expected observations.

Each runner reads the clock at entry (twice), after the activity and after the timer. Times are UTC RFC 3339 with six fractional digits and `Z`, and an unavailable read is `null`. The orchestrator computes the elapsed time between the two durable steps from the observed values.

## What the cases pin

- `carrier`: entry is the carrier's `started_at`, the run's canonical start. It is not the history insertion time. Repeated reads before a durable step return the same value. The activity and timer reads are their recorded times, so the elapsed time between the two steps is measurable.
- `no-carrier`: without a carrier the service SDKs report entry as unavailable, and later reads are unchanged.
- `carrier-for-another-run`, `carrier-low-precision` and `redrive-source-on-ordinary-history`: an unproved carrier is absent. No other time is substituted. The Rust offline history builder refuses the other-run and low-precision carriers up front, and the runner replays those cases without a carrier. It accepts the redrive-source carrier, and replay then leaves entry unavailable because the history is ordinary.

The embedded engine itself reads the run row's `started_at`, the column the carrier is built from, so its entry already equals the carrier.

`embedded-worker-protocol` covers `WorkflowFiberRunner`, the runner used by external PHP workers. It keeps the `WorkflowStarted` time when it gets no proved carrier, so runs already in flight replay unchanged. `binding_overrides` records that difference.

Applications should still order emitted events by stream offset, outbox sequence or a workflow-local counter rather than by timestamp.

## Run against published releases

The runner needs Python 3, Docker and network access to PyPI, crates.io and Packagist. Set each exact version from the selected release tuple:

```sh
DW_PYTHON_SDK_VERSION=... DW_RUST_SDK_VERSION=... \
DW_PHP_SDK_VERSION=... DW_WORKFLOW_PHP_VERSION=... \
python3 conformance/replay-clock/run.py --result-dir "$(mktemp -d)"
```

What the runner does:
- It installs each release in a throwaway `--rm` container (`python:3.12-slim`, `rust:1.86.0`, `composer:2.10.3` and `php:8.4-cli`), runs the binding's runner and compares every observation with the vectors.
- `--only` selects bindings.
- Each container runs as the invoking user with a private `--tmpfs /scratch` (mode 0700) holding the venv, source copy, `HOME`, `CARGO_HOME` and `COMPOSER_HOME`.
- A binding whose container fails or prints no observations is recorded as `"status": "error"` and the other bindings still run.
- The exit status is non-zero on any mismatch or error.
- `--container-prefix` sets the container name prefix (default `dw-replay-clock`).
- `requires_newer_than` names the last release of each binding that lacks the entry carrier. A release at or below it is reported as `not_yet_released` rather than failed, so the case can be run before the release round.

`--source BINDING=PATH` replays an unreleased checkout. It is for development only and is not release evidence.

Record the exact tuple and the per-binding `result.json` statuses on the release issue. `not_yet_released` is not a pass.
