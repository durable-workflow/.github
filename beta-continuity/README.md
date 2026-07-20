# Workspace-unavailable beta continuity

The `Beta continuity` workflow is the GitHub-owned driver for the final remote
continuity drill. It reads the authoritative public issue and qualified target
branches, selects seven component versions once, and stores that selection in
an immutable Git tag before routing any source-version blocker. When a selected
version publishes while its blocker is being repaired, later runs bind the
release plan to that tag's source commit instead of allocating a successor.

The controller deliberately ends one run after the first public component
release is observed. A later scheduled run reads the append-only interruption
record, dispatches the identical plan to all seven repository-owned recovery
workflows, and continues from public GitHub and registry state. Component
repositories retain their own scheduled and manual recovery entry points and
their own publication environments; this workflow coordinates those paths but
does not replace them.

Each durable phase is an immutable Git tag:

```text
beta-continuity-selection/<drill>
beta-continuity/<plan>/accepted
beta-continuity/<plan>/interrupted
beta-continuity/<plan>/resumed
beta-continuity/<plan>/conformance-requested
beta-continuity/<plan>/complete
```

The selection tag contains `continuity-selection.json`. Every phase contains
`continuity-evidence.json` and the canonical
`release-plan.json`. The accepted phase also retains exact target qualification
evidence. The authoritative issue receives links to these records. Completion
requires the immutable release candidate record, seven public component
releases, and a passing clean-runner conformance Release for the same tuple.

Planning pauses after the immutable version selection when a component cannot
accept its selected public version. The protected GitHub issue authority then
files an idempotent, repository-owned release blocker with the exact source and
version mismatch. The drill remains open until that focused dependency lands.
