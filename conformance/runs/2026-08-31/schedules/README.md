# Schedules conformance

- Outcome: `pass`
- Required scenarios passed: `15/15`
- Product findings: `0`
- Runner blocked: `false`
- Started: `2026-08-31T18:28:26Z`
- Finished: `2026-08-31T19:20:12Z`
- Product runner: `durable-workflow/server` commit
  `37aa3abeeadd4aa6d337c55e1a37f0abd206899a`
- Runner-only correction: `durable-workflow/server` commit
  `8ce22545c140deea487cb338f5f33090c45c67fc`
- Product execution source: published packages, release asset, and the
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

All required schedule scenarios passed:

- cron and fixed-rate cadence;
- list and describe visibility;
- pause, resume, delete, and no-fire windows;
- missed-fire policy and Server restart survival;
- CLI, PHP SDK, and Python SDK schedule surfaces;
- Python-created PHP and PHP-created Python scheduled workflows;
- invalid-cron refusal; and
- the observable outcome for a schedule targeting an unregistered workflow.

The first execution proved the product scenarios except the generated Python
probes, whose worker registrations omitted the required capability manifest.
That was a runner-only defect fixed in
[`durable-workflow/server#70`](https://github.com/durable-workflow/server/pull/70).
The affected Python and cross-language scenarios were rerun against the same
published product tuple. No product source or artifact changed, so no new RC
was created.

An invocation attempt between those runs did not discover Docker Compose
because its temporary user environment retained the wrong home directory. It
started no product containers, produced no product evidence, and is omitted.

## Command

```text
DW_SERVER_IMAGE=durableworkflow/server@sha256:92d78e4eaa61667eb02f4f238ba51cce322d832f23914d882e834e38e4e9f753 \
DW_SERVER_VERSION=2.0.0-rc.69 \
DW_PHP_SDK_VERSION=2.0.0-rc.54 \
DW_PYTHON_SDK_VERSION=2.0.0rc44 \
DW_CLI_VERSION=2.0.0-rc.36 \
DW_WATERLINE_VERSION=2.0.0-rc.35 \
DW_ARTIFACT_INSTALL_EVIDENCE=<artifact-install-evidence.json> \
./scripts/conformance/schedules-published-artifacts.sh --result-dir <result-dir>
```

No external credentials are required by this experiment.

## Evidence

- `result.json` is the complete sanitized result assembled from the initial
  product run and the focused corrected-run shards.
- `record.json` is the concise release-gate record.
- `run-metadata.json` records both runner revisions and the execution window.
- `pins.json` records the frozen tuple and consumed published artifacts.
- `artifact-install-evidence.json` records five passing artifact checks.
- `findings.json` is empty.

The initial raw result SHA-256 is
`467c7a62e4a8d338a62bd1d47a310d61fdca888372167157b473afdb27643002`.
The focused corrected-run result SHA-256 is
`3c3e484ccabed49049b1ce14561c0cf5372ace5796d7bc41aaf8ae35e39b408c`.
The retained combined result SHA-256 is
`36f2ecc182571487f961e873cda122bdddedade21eabcbb72b3a20b4993ca28d`.
The retained copy replaces only local Compose identities and loopback
addresses. Scenario outcomes, observations, artifact evidence, and findings
are unchanged.
