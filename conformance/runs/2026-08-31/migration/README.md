# Migration conformance

- Outcome: `pass`
- Required scenarios accepted: `16/16`
- Product findings: `0`
- Runner blocked: `false`
- Started: `2026-08-31T17:06:02Z`
- Finished: `2026-08-31T17:13:58Z`
- Wall time: `476` seconds
- Runner: `durable-workflow/server` commit
  `37aa3abeeadd4aa6d337c55e1a37f0abd206899a`
- Product execution source: published packages, release assets, and the
  digest-pinned Server container
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

The run upgraded the latest supported published embedded v1 baseline,
Workflow `1.0.82` and Waterline `1.0.18`, from Sample App commit
`e769ac5f4147498c652445f517ae724d73afa4de`. It preserved completed history,
an in-flight signal wait, a delayed activity retry and its queue identity, and
Waterline visibility. It also started a new v2 workflow, exercised the
documented rollback contract, and used a separate published rc.69 Server to
prove post-upgrade CLI projection, schedule creation, worker registration, and
worker polling.

The embedded v1 runtime has no durable schedule projection, worker-registration
projection, or standalone remote endpoint. The public scenario manifest
therefore classifies the corresponding two continuity cells and the
cross-generation standalone skew matrix as `not_applicable`, with explicit
capability reason codes and no attempted durable-state mutation. The other
thirteen required scenarios passed.

## Command

The maintainer host run created the published v1 state and supplied its bounded
evidence to the cataloged Server runner:

```text
DW_MIGRATION_EVIDENCE_JSON=<published-artifact-foundation-evidence> \
DW_MIGRATION_RUN_FOUNDATION_PLAN=1 \
DW_SERVER_IMAGE=durableworkflow/server@sha256:92d78e4eaa61667eb02f4f238ba51cce322d832f23914d882e834e38e4e9f753 \
DW_SERVER_VERSION=2.0.0-rc.69 \
DW_CLI_VERSION=2.0.0-rc.36 \
DW_PHP_SDK_VERSION=2.0.0-rc.54 \
DW_PYTHON_SDK_VERSION=2.0.0-rc.44 \
DW_WORKFLOW_PHP_VERSION=2.0.0-rc.55 \
DW_WATERLINE_VERSION=2.0.0-rc.35 \
./scripts/conformance/migration-published-artifacts.sh --result-dir <result-dir>
```

No credentials are required by this experiment.

## Evidence

- `result.json` is the sanitized, bounded result.
- `record.json` is the concise release-gate record.
- `run-metadata.json` records timing, runner revision, and published sources.
- `scenario-statuses.json` records all required scenario dispositions.
- `findings.json` is empty.

The original bounded host result SHA-256 is
`3d7cfb20500443cc3389fe2916525214e7fd64a8be44b2da2d2b03f246df4f1e`.
The retained result SHA-256 is
`b7fc82ce5f2c6b54aad5cf2d8be9c0eb7d366393de0a7eccf16bfb3b00d37361`.
The retained result removes only ephemeral worker, queue, and Compose project
identifiers. Outcome, artifact versions, scenario dispositions, observations,
and product findings are unchanged.
