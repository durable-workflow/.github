# GitHub issue authority

GitHub Issues is the durable authority for new public product defects, features,
release blockers, and cross-repository work entering the 2.0 beta line. The
organization issue forms capture source evidence, acceptance criteria,
dependencies, and public-safe context at intake.

`policy.json` owns the public repository inventory and the shared label and
milestone vocabulary. `backlog.json` records the deliberate review of the
unresolved alpha queue and contains only the work selected for migration. A
review disposition does not copy the excluded issue or its operational history
to GitHub.

## State direction

An issue's GitHub `open` or `closed` state always wins. Status labels are
derived triage aids: the audit changes stale open labels to `status:done` when
GitHub closes an issue, but never reopens it. External automation may read or
mirror GitHub state; it must not send lifecycle state back to this workflow.

Every migrated issue contains exactly one stable `beta-work-id` marker, and each
work ID identifies exactly one issue. Migration first searches open and closed
issues across the complete public inventory. One match preserves its current
title, maintainer-authored body, labels, and lifecycle state. The only
source-owned body field reconciled on replay is the bounded unblock-condition
section for a blocked migration. A repeated identity across issues or multiple
distinct identities on one issue receives `authority:conflict` and makes the
workflow fail. Replaying migration therefore cannot alias lifecycle or blocker
state, duplicate an issue, or make completed GitHub work pending again.

A blocked migration must name either an earlier migrated dependency or an
explicit public-safe unblock condition. The renderer links migrated dependencies
and publishes external decision gates under an `Unblock condition` heading, so a
consumer can tell what must change before the work becomes ready.

The scheduled audit also fails when a selected item is missing, when a marker
appears in the wrong repository, when an open authoritative issue has ambiguous
status labels, or when migrated ownership, beta classification, or milestone
metadata becomes incomplete. Bounded evidence is retained as a GitHub Actions
artifact on both successful and failed runs.

## Credential boundary

Cross-repository metadata and issues are written with the
`BETA_PRODUCT_WORK_TOKEN` secret in the protected `beta-product-work` GitHub
environment. The credential needs repository metadata read and Issues
read/write access only for the public repositories in `policy.json`. It does
not need source, package, release, environment, or private repository access.

Private Cloud implementation work is outside this inventory. If public
components need a Cloud-facing contract, the public issue describes only that
contract and links no private implementation detail.
