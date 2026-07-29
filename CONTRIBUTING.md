# Contributing to Durable Workflow

Use the repository's focused tests and public qualification workflow for every
change. Keep public examples and evidence free of credentials, customer data,
and private deployment details.

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
