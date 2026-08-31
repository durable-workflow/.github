# Replay conformance

- Outcome: `pass`
- Required scenarios passed: `31/31`
- Product findings: `0`
- Runner blocked: `false`
- Started: `2026-08-31T18:12:21Z`
- Finished: `2026-08-31T18:17:40Z`
- Runner: `durable-workflow/server` commit
  `37aa3abeeadd4aa6d337c55e1a37f0abd206899a`
- Product execution source: published packages, crate, release asset, and the
  digest-pinned Server container
- Local product checkouts used as artifacts: `false`

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

All required replay scenarios passed:

- thirteen PHP, Python, and Rust worker-restart scenarios;
- eleven completed-history replay scenarios covering activities, signals,
  updates, waits, version markers, sagas, and Rust side effects;
- four malformed-history, mutation, and code-divergence refusal scenarios;
- two in-flight signal restart timing scenarios; and
- one published-artifact installation and identity scenario.

The result includes runtime evidence from PHP, Python, and Rust. Every package,
crate, release asset, and OCI manifest consumed by the run has a retained
distribution identity.

## Command

```text
DW_SERVER_IMAGE=durableworkflow/server@sha256:92d78e4eaa61667eb02f4f238ba51cce322d832f23914d882e834e38e4e9f753 \
DW_SERVER_VERSION=2.0.0-rc.69 \
DW_PHP_SDK_VERSION=2.0.0-rc.54 \
DW_WORKFLOW_PHP_VERSION=2.0.0-rc.55 \
DW_PYTHON_SDK_VERSION=2.0.0rc44 \
DW_RUST_SDK_VERSION=2.0.0-rc.39 \
DW_CLI_VERSION=2.0.0-rc.36 \
DW_WATERLINE_VERSION=2.0.0-rc.35 \
./scripts/conformance/replay-published-artifacts.sh --result-dir <result-dir>
```

No external credentials are required by this experiment.

## Evidence

- `result.json` is the complete sanitized replay result.
- `record.json` is the concise release-gate record.
- `run-metadata.json` records the runner revision and execution window.
- `pins.json` records the resolved published versions and channels.
- `artifact-install-evidence.json` records seven passing artifact checks.
- `distribution-identities.json` records the consumed distribution hashes.
- `findings.json` is empty.

The original result SHA-256 is
`29b1101619e924e213f17ef7d412cd54df1f2637eccd0fc4c482b3f55733de8a`.
The retained result SHA-256 is
`25b00bba1db4965d63a497b22c1d22e5d3a368055dd61147390125f0edb110d4`.
The retained copy replaces only the local Compose project and loopback address.
Scenario outcomes, observations, artifact identities, and findings are
unchanged.
