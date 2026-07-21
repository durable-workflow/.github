# Protected beta authorization

The `Beta authorization` workflow is the only repository-owned writer for an
immutable `beta-authorization/*` decision. A product owner dispatches the
workflow with one JSON request conforming to
[`request-schema.json`](request-schema.json), and the `beta-authorization`
environment must approve the job before it can receive write authority.

The request identifies the proposed beta release-plan name and exact seven
component versions and source commits. Workflow and Waterline must use exact
`2.0.0-beta.N` versions. It also cites immutable Git records for the qualified
artifact candidate, retained passing conformance, and the completed and
scheduled-no-op continuity phases.

Before dispatch, add a comment to the public beta authority issue containing
this marker, where the digest is SHA-256 over the canonical, indented and
key-sorted `authorization` object including its trailing newline:

```text
<!-- durable-workflow-beta-decision: authorize sha256:<AUTHORIZATION_SHA256> -->
```

The request names that comment ID. The workflow verifies that the comment was
created by the dispatching organization member or collaborator, that the
authority issue is still the open classified beta gate, and that no other open
public issue in the governed repository inventory has a `priority:P0` or
`priority:P1` label.

For a new authorization, the protected job independently runs the public target
qualification audit pinned to all seven intended source commits. It retains the
complete resulting `target-qualification-evidence.json` in the authorization
record and rechecks the exact branch heads immediately before publication. This
qualification is deliberately independent from the earlier continuity drill's
accepted-phase qualification, because continuity proves release recovery rather
than the current candidate's source identity.

The writer also verifies every cited record and its live immutable tag.
Candidate artifacts and retained conformance must bind all seven intended
source commits. The configured continuity drill must retain its exact
completion and later scheduled no-op authority. The environment must require
reviewers and allow only the `main` branch, and the record retains both the
dispatching actor and the approving GitHub user.

The authoritative tag is `beta-authorization/<release-plan-name>`. Its root
commit contains the minimal `beta-authorization.json` consumed by release
plans, a detailed `beta-authorization-evidence.json`, and the exact
`target-qualification-evidence.json`. A GitHub Release with the same tag mirrors
all three files. Repeating an identical request compares and recovers that
record; a changed request or an occupied conflicting tag fails closed. The
action authorizes only the beta channel. Stable 2.0 remains a separate decision.
