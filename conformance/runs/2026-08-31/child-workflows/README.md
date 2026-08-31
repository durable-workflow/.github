# Child-workflows conformance

- Outcome: `pass`
- Scenarios: `11/11` passed
- Findings: `0`
- Started: `2026-08-31T16:31:41Z`
- Finished: `2026-08-31T16:32:00Z`
- Product execution source: digest-pinned published Server container
- Product Server commit: `37aa3abeeadd4aa6d337c55e1a37f0abd206899a`
- Runner commit: `8193e7a131a0e26059b231e3cc32481b4080717d`
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

The runtime matrix executes PHP and Python parent/child combinations using the
published Server, Workflow, Waterline, and Python SDK artifacts. Its install
probe also verifies the pinned CLI and Rust SDK distributions. The PHP SDK
remains part of the frozen release tuple and is exercised by the polyglot and
SDK-matrix experiments.

## Runner correction

The first invocation exposed a conformance-driver defect: its synthetic PHP
worker registration omitted the required capability manifest. The driver was
corrected in `durable-workflow/server` commit
`8193e7a131a0e26059b231e3cc32481b4080717d`. The complete conformance directory
from that immutable public commit was mounted read-only over the runner path in
the unchanged `2.0.0-rc.69` image. No product code or product artifact changed.

## Command

The confirming runner invocation was equivalent to:

```text
docker run --rm \
  --mount type=bind,src=<runner-commit>/scripts/conformance,dst=/app/scripts/conformance,readonly \
  --mount type=bind,src=<result-dir>,dst=/result \
  <documented artifact-version environment> \
  durableworkflow/server@sha256:92d78e4eaa61667eb02f4f238ba51cce322d832f23914d882e834e38e4e9f753 \
  /app/scripts/conformance/child-workflows-published-artifacts.sh --result-dir /result
```

No credentials are required by this experiment.

## Evidence

- `result.json` retains all 11 scenario results and decisive observations.
- `record.json` is the concise run record.
- `run-metadata.json` records timing and published sources.
- `artifact-install-evidence.json` records artifact identity and install status.
- `findings.json` is empty.

The original result SHA-256 is
`532e842c7e21a6048f2f5aa8a3dae04523175fc9c05665cb67a66972f9bf00e3`.
The retained result SHA-256 is
`eb68b4a472cdc8c417f5abeb6b6d19287e36059726174636bbba39b5b395162c`.
The retained copy removes only verbose package-registry command and output
samples; artifact versions, sources, statuses, all scenario evidence, and the
experiment outcome are unchanged. The separately emitted raw matrix file is
excluded because the bounded result already contains the same matrix evidence.
