# Polyglot conformance

- Outcome: `pass`
- Required surfaces passed: `9/9`
- Product findings: `0`
- Runner blocked: `false`
- Started: `2026-08-31T17:47:19Z`
- Finished: `2026-08-31T17:50:52Z`
- Runner: `durable-workflow/sample-app` commit
  `eb960549b4bf2da769933a386bbe3b510a8f0979`
- Product execution source: published packages, crates, release assets, and the
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

All required Polyglot surfaces passed:

- PHP, Python, and Rust task-codec rejection boundaries;
- the featured PHP workflow to Python activity to Rust activity journey;
- all nine PHP, Python, and Rust workflow/activity runtime cells;
- CLI start and result handling for all runtime cells;
- ten portable Avro value cases across six cross-language directions,
  including binary-versus-text fidelity;
- cross-language typed failures;
- CLI-driven signals and queries against PHP, Python, and Rust workflows; and
- Waterline event rendering, payload rendering, and worker attribution.

The same digest-pinned Server container stayed healthy for the complete run.
The official Avro implementations were `apache/avro` `1.12.2` for PHP,
`fastavro` `1.12.2` for Python, and `apache-avro` `0.21.0` for Rust.

## Command

```text
COMPOSE_PROJECT_NAME=<isolated-project> \
DURABLE_SERVER_IMAGE=durableworkflow/server:2.0.0-rc.69@sha256:92d78e4eaa61667eb02f4f238ba51cce322d832f23914d882e834e38e4e9f753 \
DURABLE_WORKFLOW_CLI_VERSION=2.0.0-rc.36 \
DURABLE_WORKFLOW_PHP_SDK_PIN=durable-workflow/sdk:2.0.0-rc.54@beta \
DURABLE_WORKFLOW_PHP_SDK_VERSION=2.0.0-rc.54 \
DURABLE_WORKFLOW_PYTHON_SDK_VERSION=2.0.0rc44 \
DURABLE_WORKFLOW_RUST_SDK_VERSION=2.0.0-rc.39 \
DURABLE_WORKFLOW_WORKFLOW_PIN=durable-workflow/workflow:2.0.0-rc.55@beta \
DURABLE_WORKFLOW_WORKFLOW_VERSION=2.0.0-rc.55 \
DURABLE_WORKFLOW_WATERLINE_PIN=durable-workflow/waterline:2.0.0-rc.35@beta \
DURABLE_WORKFLOW_WATERLINE_VERSION=2.0.0-rc.35 \
POLYGLOT_BUILD_CACHE_MODE=warm-cache \
./scripts/polyglot-validation.sh
```

No external credentials are required by this experiment.

## Evidence

- `result.json` is the complete sanitized structured result.
- `record.json` is the concise release-gate record.
- `run-metadata.json` records the runner revision and execution window.
- `pins.json` records the resolved published versions and channels.
- `artifact-install-evidence.json` records the artifact and Avro checks.
- `findings.json` is empty.

The original structured-result SHA-256 is
`90eccd6fc788a1f1a8b35c9762212caa94e605266ec224fe79e3cfe163c6e1d3`.
The retained result SHA-256 is
`99f1bfd64b8ef4ea57b734872b49589b4723ee38cd455ca34d81b9050f53ed93`.
The retained copy omits only the local runner attempt ordinal. Product
observations, artifact identities, outcomes, and findings are unchanged.
