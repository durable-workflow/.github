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
  behavior changes; and
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
