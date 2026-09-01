# Durable Workflow

Durable Workflow is a durable execution platform for PHP, Python, and Rust.
It supports embedded Laravel applications, self-hosted Server deployments, and
the managed Durable Workflow Cloud runtime.

## Project coordination

GitHub issues record accepted work, priority, decisions, and blockers. Pull
requests contain implementation and review, repository Actions run ordinary
checks and publication, and releases identify published artifacts. There is no
separate work tracker or cross-repository lifecycle controller.

Organization-wide working rules are in [`AGENTS.md`](AGENTS.md), and contributor
guidance is in [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Shared contracts

- [`qualification/`](qualification/) defines the reviewed GitHub Actions and
  workflow trust policy used by repository CI.
- [`conformance/`](conformance/) describes product experiments used to qualify
  releases and important compatibility changes.
- [`regression-corpus/`](regression-corpus/) defines the shared evidence format
  for replay and payload-codec regressions.
- [`visual-evidence/`](visual-evidence/) contains the bounded browser-evidence
  contract used by the Rust SDK documentation workflow.

Historical tags and GitHub Releases remain available as immutable release
history. They are not active project state.
