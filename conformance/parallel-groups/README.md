# Parallel group failure policy, version 1

Proposal for [issue 232](https://github.com/durable-workflow/.github/issues/232).
Workflow acknowledged sdk-python's handoff for this contract and fixture slice.
Workflow retains embedded producer admission, Server retains native admission,
and the first-party bindings retain authoring and replay.

This document defines a proposed wire contract. It does not advertise runtime
support or qualify a release. Producers and consumers require review and
published-artifact qualification before enabling it.

## Recorded discriminator

Each canonical group metadata entry may contain `parallel_group_policy` with
exactly one of `propagate`, `cancel_remaining` or `settle`. It appears in every
applicable frame of `parallel_group_path`; the top-level flattened fields match
the innermost frame, as the other group fields do today.

The policy belongs to a group identity and is immutable after admission. Every
member's frame for that group must agree, including presence versus absence.
An unknown, null, empty or inconsistent value is refused before writes.
Policy is refused on selection frames (`parallel_group_mode: select`). An
enclosing ordinary all-group frame may carry its own policy; that does not
change the selection frame's winner/handle contract.

Absence preserves the recording binding's legacy behavior, including failure
selection and replay clock. In particular, legacy Python list groups wait for
every member and select the first failure in member order. A replacement worker
must not reinterpret that history as explicit `propagate`.

Newly admitted version-1 groups record their chosen policy, including the default
`propagate`. Replay uses the recorded policy, not a new worker's default. An
already-open legacy group keeps absence even when replayed by a newer worker.

## Capability admission

The proposed discovery field is
`worker_protocol.server_capabilities.parallel_group_policies`:

```json
{"supported": true, "version": 1, "policies": ["propagate"]}
```

`policies` is a nonempty unique subset of the three policy names. Producers may
admit one policy before the others, and list only policies actually implemented
and qualified. Wrong types, unknown versions or names, duplicates, missing
fields and `supported: false` do not authorize admission.

Worker registration uses the existing `POST /worker/register` body fields:

```json
{
  "capabilities": ["parallel_group_policies"],
  "capability_manifest": {
    "parallel_group_policies": {"supported": true, "version": 1, "policies": ["propagate"]}
  }
}
```

The structured descriptor is exactly at
`capability_manifest.parallel_group_policies`, separate from the existing flat
string array `capabilities`. The flag and descriptor must both be present.
Neither alone establishes policy support. A legacy worker omits both. An object
inside `capabilities`, a misplaced descriptor, an invalid descriptor, or a
flag/descriptor mismatch refuses registration before normalization or writes.
Other existing capability entries retain their contracts.

The producer validates and persists this entry as structured metadata. It must
not discard the descriptor during registration normalization or route it through
the flat string-list normalizer. It validates exact version and policy names, rejects
duplicates, and canonicalizes the policy list in `propagate`, `cancel_remaining`,
`settle` order. The canonical descriptor participates in registration identity,
held-poll snapshots and in-transaction claim/confirmation fences. A descriptor
change during a held poll makes that old poll stale, even if its flat flag is
unchanged. It cannot become the replacement process's claim authority.

Producer discovery alone does not establish consumer support. Admission requires
both sides to support the selected policy. A worker must not advertise a policy
implemented only by a test flag or source proposal.

The same fence applies to replacement-worker claim and replay eligibility.
Before assigning or confirming a claim, the producer verifies that the worker
supports every explicit policy needed by that run's retained history. A legacy
worker must not claim an explicit-policy run merely because it supports the
workflow type. If no eligible worker exists, keep the run waiting with an
operator-visible capability reason. Never strip recorded policy or downgrade
it during repair, registration replacement, retry or cold replay. Completion
also retains the existing current-worker, lease and attempt fences.

If either side lacks the selected policy, refuse explicit admission before
recording commands. Never drop the policy, silently downgrade it to legacy
behavior or partially admit the member batch. Existing absent-policy histories
remain replayable under their original semantics.

## Outcomes and replay boundaries

`propagate` raises the first member failure in durable history order. It does
not wait for open siblings or issue sibling cancellation. Successful groups
still return values in member order after every member succeeds. A later
sibling result cannot become an outcome for a successor authored call.

`cancel_remaining` uses the same first-failure boundary and requests cancellation
for unfinished siblings in member order before raising the initiating failure.
It preserves existing operation cancellation policies, ownership and deadlines.
Cancellation is recorded and replayed; replay never sends another request for
the same recorded cancellation. This policy needs a producer-reviewed mapping
to existing operation cancellation commands before it can be advertised. The
fixture specifies required targets, not a new unreviewed command kind.

`settle` waits for every member and returns an ordered outcome per member. Each
outcome distinguishes success (including a null value) from failure; a member
failure is not thrown at the group call. The language-neutral outcome envelope
requires binding/producer review before this policy is advertised.

First-failure ties follow durable event order, never member position or a sort
of timestamps. The explicit-policy failure continuation receives only the
selected failure's qualified event clock. Later sibling results and later
signals cannot supply that boundary's time. Absent-policy histories keep their
binding's original clock rule. A terminal run-close settlement is not a member
outcome, as defined by the existing run-close contract.

Activity-group failure clocks keep the established canonical-v1 millisecond
normalization. If resource identity or timestamp checks cannot prove the selected
boundary, the clock remains unavailable rather than borrowing another event.

Nested groups record policy per group frame. Initial consumers may support only
uniform explicit `propagate` frames; mixed nested policies must remain refused
until their outcome composition is qualified. Local/prepared operations need
their own atomic admission support and must not inherit support merely because
remote activities work.

## Fixtures and remaining decisions

[`fixtures-v1.json`](fixtures-v1.json) contains synthetic canonical history
prefixes and expected semantic outcomes. Binding owners copy applicable inputs
into their existing replay suites and retain legacy fixtures unchanged. These
source vectors are not an installed conformance result.
Registration/claim vectors separately cover the exact manifest placement,
legacy eligibility, malformed or incomplete declarations, retained-policy
requirements and a capability change during a held poll.

The propagate wire discriminator and proposed per-policy capability can be
reviewed independently of the producer mappings for `cancel_remaining` and
`settle`. Those two policies stay unadvertised until their cancellation command
mapping and ordered outcome envelope are agreed and implemented. No runtime
change or release is authorized by a passing fixture-only check.
