# Namespaces conformance

- Outcome: `pass`
- Required scenarios passed: `14/14`
- Product findings: `0`
- Runner blocked: `false`
- Started: `2026-08-31T17:21:55Z`
- Finished: `2026-08-31T17:23:15Z`
- Runner: `durable-workflow/server` commit
  `37aa3abeeadd4aa6d337c55e1a37f0abd206899a`
- Product execution source: published packages, release assets, and the
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

The namespaces runner directly exercises Server, Workflow, Waterline, CLI, PHP
SDK, and Python SDK artifacts. Rust remains frozen in the release tuple and is
exercised by the polyglot and SDK-matrix runs.

## Coverage

All required namespace cells passed:

- create, update, describe, list, delete, and clean recreation;
- cross-namespace workflow visibility and mutation isolation;
- PHP worker task-queue isolation and PHP/Python SDK namespace parity;
- explicit and default CLI namespace context;
- search-attribute schema and value-query isolation;
- schedule isolation;
- Waterline list, detail, and operator projection isolation;
- explicit Nexus cross-namespace invocation;
- reserved-name refusal; and
- complete result/finding routing.

## Command

```text
DW_NAMESPACES_SERVER_BIND_HOST=0.0.0.0 \
DW_NAMESPACES_SERVER_URL=http://<docker-host-gateway>:<port> \
DW_SERVER_IMAGE=durableworkflow/server@sha256:92d78e4eaa61667eb02f4f238ba51cce322d832f23914d882e834e38e4e9f753 \
DW_SERVER_VERSION=2.0.0-rc.69 \
DW_CLI_VERSION=2.0.0-rc.36 \
DW_PYTHON_SDK_VERSION=2.0.0rc44 \
DW_PHP_SDK_VERSION=2.0.0-rc.54 \
DW_WORKFLOW_PHP_VERSION=2.0.0-rc.55 \
DW_WATERLINE_VERSION=2.0.0-rc.35 \
./scripts/conformance/namespaces-published-artifacts.sh --result-dir <result-dir>
```

No credentials are required by this experiment.

## Cleanup reconciliation

The runner wrote its complete passing record before its exit trap. The trap
then returned nonzero because disposable Waterline and PHP-shard files created
through bind-mounted containers were owned by the container default user. No
containers or volumes remained, the retained record was complete, and all
fourteen product scenarios had already passed. This runner-only false failure
is tracked by `durable-workflow/server#67` and fixed by
`durable-workflow/server#68`; it does not change a product artifact or require
a replacement release candidate.

## Evidence

- `result.json` is the complete sanitized namespace result.
- `record.json` is the concise release-gate record.
- `run-metadata.json` records the runner revision and published sources.
- `pins.json` records the resolved published versions.
- `artifact-install-evidence.json` records the artifact installation checks.
- `findings.json` is empty.

The original result SHA-256 is
`e80d2ca30d9f562de18789888cdcc92a5531ebb4f51a2f117ffb79c06d6d31f3`.
The retained result SHA-256 is
`fc617975ecc7f58d97c33880995dde93f53d982956d6d9c279bcefdc3d53e23c`.
The retained copy replaces only executor paths and the Docker host address.
Scenario outcomes, observations, artifact identities, and findings are
unchanged.
