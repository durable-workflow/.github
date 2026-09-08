# Replay and codec regression corpora

Confirmed replay and payload-codec defects must add the smallest durable,
language-neutral reproducer before their fixes complete. A test that rebuilds
the same inputs from implementation details is useful coverage, but is not
regression-corpus evidence.

Each participating repository declares guarded implementation paths and
checked-in fixture locations in `regression-corpus-policy.json`. The validator:

- inventories individual semantic cases rather than test methods;
- rejects duplicate identities and duplicate evidence;
- prevents existing evidence from being changed, moved, or removed;
- requires a replay or codec corpus count to grow when guarded implementation
  behavior changes, except for the Server review distinction below; and
- permits an equal count only when the change is unrelated to that category.

Protocol evolution is append-only. A new fixture may name an older fixture in
`supersedes`, but the old fixture remains available and the new fixture must
declare a different protocol version.

## Fixture choice

Replay fixes should use an existing official golden-history bundle format when
the runtime already consumes it. Otherwise add one
`durable-workflow.replay-regression/v1` history or command-sequence fixture per
defect.

Codec fixes add the same `durable-workflow.codec-regression/v1` wire fixture to
every applicable official binding. The fixture records the tagged value, Avro
schema version and fingerprint, exact framing, stable accept/reject policy, and
the PHP, Python, and Rust bindings to which it applies.

In a participating implementation repository, run its normal focused runtime
test and:

```bash
python scripts/ci/validate-regression-corpus.py \
  --base-ref <target-branch-or-commit>
```

The policy and evidence schemas are machine-owned. Contributor prose is not
tested for exact wording.

## Server Transport And Resource Changes

Server's broad payload-path classifier identifies code that needs review; it
cannot determine whether a change fixes a wire-format defect. Request-body
limits, streaming storage, reference retention, and metadata-only reads need
HTTP, integrity, resource-limit, and recovery tests. Do not add an unrelated wire
fixture merely to satisfy a count, or claim that rewriting source around a tiny
fixture proves a large-request memory bound.

When no wire fixture is added, Server reports the affected paths for maintainer
review without requiring corpus growth or per-file source-instrumented proof.
The PR must explain why existing wire semantics remain intact and link the
defect-specific regression: reproduce the original failure, exercise the actual
changed surface, and verify resource limits and recovery where relevant. Review
this before merging; a green inventory check alone does not prove the fix.

Confirmed wire-format, type-identity, framing, or codec acceptance defects still
require the smallest applicable portable fixture. Existing fixtures remain
immutable and execute in the normal suite. New Server wire fixtures retain the
counterfactual checks below. This distinction does not relax product tests or
authorize skipping a failing reproduction.

Server codec regressions use a single counterfactual proof for one defect. Its
`boundaries` list names each changed pre-existing public boundary, and the
Server validator executes and attributes that proof independently for every
listed source path. Newly added guarded abstractions have candidate-focused
coverage instead because they do not have a real base implementation to
revert. The proof document is defined by
`server-codec-counterfactual-schema.json`.
