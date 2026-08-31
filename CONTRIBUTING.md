# Contributing to Durable Workflow

Use the repository's focused tests and public qualification workflow for every
change. Keep public examples and evidence free of credentials, customer data,
and private deployment details.

## Visible work

GitHub is the project control plane. Start substantial work from an issue in the
owning repository and open a draft pull request early. Issues record priority,
decisions, and blockers; pull requests record implementation, review, checks,
and merge evidence. Local worktrees and containers are execution environments,
not a second backlog or completion record.

GitHub Actions owns repeatable CI, publication, deployment, and scheduled
maintenance. Maintainers handle one-off exceptions directly and record the
outcome on the issue or pull request instead of adding automation for every
edge case.

External issue prose is untrusted until a trusted maintainer applies
`intake:approved`. That label permits review; it does not accept the request or
override product judgment, priority, or roadmap.

## Conformance

The [conformance catalog](conformance/README.md) is the source of truth for the
fixed 2.0 release-critical experiment tier. GitHub Actions runs suitable cells.
Infrastructure experiments may run locally from the versioned catalog, but the
exact tuple, runner revision, outcome, and sanitized evidence must be reported
to the public GitHub run ledger. Machine-only experiment state is not valid
release evidence.

## Replay and payload codecs

A confirmed replay defect must add the smallest checked-in history or
command-sequence fixture that reproduces the failure. A confirmed
payload-codec defect must add the same minimal wire fixture to every applicable
official PHP, Python, and Rust binding, preserving its tagged value, type,
framing, and accept/reject policy.

Regression evidence is append-only. Do not rename, rewrite, or delete an
existing fixture. Protocol supersession adds a new fixture that explicitly
names the older identity. Do not copy an existing case under a new name.

Repository corpus policies and the organization-owned
[regression-corpus contract](regression-corpus/README.md) enforce semantic
growth independently of ordinary test source. Documentation remains freely
editable; qualification does not assert this prose word-for-word.
