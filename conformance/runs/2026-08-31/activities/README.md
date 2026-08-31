# Activities conformance

- Outcome: `pass`
- Started: `2026-08-31T16:16:21Z`
- Finished: `2026-08-31T16:16:21Z`
- Runner: `durable-workflow/server` commit
  `37aa3abeeadd4aa6d337c55e1a37f0abd206899a`
- Execution source: digest-pinned published Server container
- Local product checkouts used: `false`

## Frozen tuple

| Component | Version |
| --- | --- |
| Workflow | `2.0.0-rc.55` |
| Waterline | `2.0.0-rc.35` |
| Server | `2.0.0-rc.69` |
| CLI | `2.0.0-rc.36` |
| PHP SDK | `2.0.0-rc.54` |
| Python SDK | `2.0.0-rc.44` (PyPI `2.0.0rc44`) |
| Rust SDK | `2.0.0-rc.39` |

The activities runner exercises the Server, Workflow, Waterline, CLI, PHP SDK,
and Python SDK artifacts. Rust remains part of the frozen release tuple and is
exercised by the polyglot and SDK-matrix experiments.

## Command

The runner was invoked inside the exact Server image with:

```text
/app/scripts/conformance/activities-published-artifacts.sh --result-dir /result
```

The image was
`durableworkflow/server@sha256:92d78e4eaa61667eb02f4f238ba51cce322d832f23914d882e834e38e4e9f753`,
with the versions above supplied through the runner's documented environment
variables. No credentials are required by this experiment.

## Evidence

- `result.json` is the runner's bounded portable result.
- `record.json` is the concise run record.
- `run-metadata.json` records timing and published sources.
- `executed-distribution-identities.json` records the exact consumed bytes.
- `findings.json` is empty.

The unbounded raw host trace is intentionally excluded. It contains no
additional pass/fail authority; the bounded result retains every required
scenario status, decisive observation, and artifact identity.
