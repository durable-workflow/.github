# Heartbeats conformance

- Outcome: `pass`
- Cells: PHP, Python, Rust, and Waterline passed
- Findings: `0`
- Started: `2026-08-31T16:53:29Z`
- Finished: `2026-08-31T16:57:04Z`
- Wall time: `215` seconds (budget: `540` seconds)
- Server runner commit: `37aa3abeeadd4aa6d337c55e1a37f0abd206899a`
- Waterline runner commit: `4b4323677feecfd1a4f05069dc3012127a92b821`
- Product execution source: digest-pinned published Server container and published packages
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

## Coverage

The shared wave bootstraps one clean Server and runs four isolated cells in
parallel. The PHP, Python, and Rust cells each prove successive acknowledged
heartbeats, stale-worker exclusion, fresh-peer eligibility, and real workflow
completion. The Waterline cell proves the corresponding operator projection.
The wave then verifies namespace and identity isolation, settles every child
process, and removes every owned container, volume, network, and scratch
artifact.

## Command

The public Server runner was invoked with the Waterline runner from the exact
commits above:

```text
HOSTNAME=<executor-container-hostname> \
DW_SERVER_IMAGE=durableworkflow/server@sha256:92d78e4eaa61667eb02f4f238ba51cce322d832f23914d882e834e38e4e9f753 \
DW_SERVER_VERSION=2.0.0-rc.69 \
DW_CLI_VERSION=2.0.0-rc.36 \
DW_PHP_SDK_VERSION=2.0.0-rc.54 \
DW_PYTHON_SDK_VERSION=2.0.0-rc.44 \
DW_RUST_SDK_VERSION=2.0.0-rc.39 \
DW_WORKFLOW_PHP_VERSION=2.0.0-rc.55 \
DW_WATERLINE_VERSION=2.0.0-rc.35 \
DW_HEARTBEATS_WATERLINE_RUNNER=<waterline-runner>/scripts/conformance/worker-status-published-artifacts.sh \
DW_WATERLINE_HOST=<docker-host-gateway> \
./scripts/conformance/heartbeats-wave-published-artifacts.sh --result-dir <result-dir>
```

The executor used a clean system `PATH` so each cell verified its own pinned CLI
installation. No credentials are required by this experiment.

## Evidence

- `result.json` is the bounded shared-wave result.
- `record.json` is the concise run record.
- `run-metadata.json` records timing, runner revisions, and the frozen tuple.
- `executed-distribution-identities.json` records consumed CLI, Server, and SDK bytes.
- `waterline-source-hygiene.json` records exact Packagist distribution references.
- `child-processes.json` proves all four process groups exited without forced signals.
- `isolation.json` proves each cell remained in its assigned namespace and identity prefixes.
- `findings.json` is empty.

The original result SHA-256 is
`582c09e240b1e783686d6a5d6bb9c5424b0d3e14b1fb514421ef2dc7a55a9286`.
The retained result SHA-256 is
`ee15558defec68781c66c0a4f5d377e26781ec4b78e0568ed2699eec35377db4`.
The retained copy removes only executor-specific Docker inspection commands and
output. Cell outcomes, heartbeat observations, isolation checks, artifact
identities, findings, and cleanup status are unchanged.
