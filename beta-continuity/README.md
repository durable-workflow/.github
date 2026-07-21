# Workspace-unavailable beta continuity

The `Beta continuity` workflow is the GitHub-owned driver for the final remote
continuity drill. It reads the authoritative public issue and qualified target
branches, allocates seven component versions from public release tags, and
stores that selection in an immutable Git tag before routing any source-version
blocker. A fresh drill never inherits version allocations from blockers created
by an earlier drill. When a selected version publishes while its blocker is
being repaired, later runs for the same drill bind the release plan to that
tag's source commit instead of allocating a successor.

Acceptance records which exact-plan components are already public and which are
still pending. The controller deliberately ends one run only after a component
that was pending at acceptance becomes public through its repository-owned
recovery workflow for the exact immutable plan. Baseline artifacts remain valid
members of the final tuple, but cannot trigger the interruption. A later
scheduled run reads the append-only interruption record, dispatches the
identical plan to all seven repository-owned recovery workflows, and continues
from public GitHub and registry state. Component repositories retain their own
scheduled and manual recovery entry points and their own publication
environments; this workflow coordinates those paths but does not replace them.

Each durable phase is an immutable Git tag:

```text
beta-continuity-selection/<drill>
beta-continuity/<plan>/accepted
beta-continuity/<plan>/interrupted
beta-continuity/<plan>/resumed
beta-continuity/<plan>/conformance-requested
beta-continuity/<plan>/complete
beta-continuity/<plan>/no-op-confirmed
```

The selection tag contains `continuity-selection.json`. Every phase contains
`continuity-evidence.json` and the canonical
`release-plan.json`. The accepted phase also retains exact target qualification
evidence. The authoritative issue receives links to these records. Completion
requires the immutable release candidate record, seven public component
releases, and a passing clean-runner conformance Release for the same tuple. The
controller dispatches conformance only when no matching execution exists. Once
a matching run is complete, it requests the retention-only workflow with that
exact run ID and attempt; a failed publication step therefore cannot cause the
experiment matrix to run again. The repository-scoped `GITHUB_TOKEN` performs
these same-repository dispatches, while cross-repository product authority
remains confined to the protected environment.
Automatic completion-triggered and manual recovery runs are deduplicated by
that source identity. After one failed retention retry, the controller reports
terminal publication failure in its retained observation instead of looping.

The authority issue remains open after completion until a later scheduled run
retains a successful no-op phase. At that terminal boundary, the controller
revalidates the exact plan, source releases, public verification, protected
qualification, conformance, and no-op records before changing issue state. It
then comments and closes trusted component blockers, followed by the configured
evidence work items, and only then comments and closes the parent authority.
Each closure comment links the same immutable evidence, and retries reuse the
exact existing report instead of duplicating it.

Earlier interruptions and their routed blockers remain available as immutable
diagnostic evidence. The corrected drill uses a new selection and plan identity,
allocates from current public release tags, and links the superseded diagnostic
phase from its accepted evidence; existing tags are never rewritten.

Planning pauses after the immutable version selection when a component cannot
accept its selected public version. The protected GitHub issue authority then
files an idempotent, repository-owned release blocker with the exact source and
version mismatch. The drill remains open until that focused dependency lands.
