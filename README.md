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

- [`conformance/`](conformance/) describes the product experiments used to
  qualify releases and important compatibility changes.
- [`regression-corpus/`](regression-corpus/) defines the shared evidence format
  for replay and payload-codec regressions.
- [`product-train/`](product-train/) currently supplies the version authority
  consumed by the documentation site while stable-version discovery is being
  simplified.
- [`visual-evidence/`](visual-evidence/) contains the bounded browser-evidence
  contract used by the Rust SDK documentation workflow.

Historical prerelease tags and GitHub Releases remain available as immutable
launch history. They are not active project state and no scheduled workflow
advances or repairs them.
