# GitHub issue authority

GitHub Issues is the durable authority for new public product defects, features,
release blockers, and cross-repository work entering the 2.0 beta line. The
organization issue forms capture source evidence, acceptance criteria,
dependencies, and public-safe context at intake.

## Vetted revisions

Issue text is inert until its current revision has trusted intake authority.
Issues created by `rmcdaniel` or `durable-workflow-ops` are trusted at creation.
Every other issue must carry `intake:approved`, and the most recent transition
of that label must have been performed by one of those maintainers after the
most recent title or body edit. An edit invalidates an earlier approval. Label
removal also invalidates approval, while a later trusted reapplication binds a
new SHA-256 digest of the complete title and body.

Before any environment-backed job is considered, a metadata-only, read-only
pass reconstructs these decisions from the issue author, last edit time, and
approval-label timeline. It fetches title and body only after that pass accepts
the revision, then binds the content digest. The resulting manifest contains
issue coordinates, approval evidence, and revision digests, but no issue text.
The lifecycle job directly refetches every manifest-selected issue and requires
its identity, approval actor, approval time, approval mode, and revision digest
to remain exact before processing the vetted issue bodies. A selected issue's
edit, approval change, or disappearance between those jobs therefore fails
closed before mutation. A newly created or newly visible issue that was absent
from the manifest remains inert until a later discovery run.
Lifecycle evidence retains the matched approval records and revision digests
for review, but later runs reconstruct authority from GitHub instead of
consuming an earlier artifact.

Only issue title and body revisions participate in intake. Comments,
pull-request text, workflow logs, artifacts, and attachments are not queried or
interpreted as issue instructions.

`policy.json` owns the public repository inventory and the shared label and
milestone vocabulary. `backlog.json` records the deliberate review of the
unresolved alpha queue and contains only the work selected for migration. A
review disposition does not copy the excluded issue or its operational history
to GitHub.

## State direction

GitHub owns both lifecycle state and completion approval. Every new or still-open
authoritative issue carries `completion:evidence-required`. Landing source or
passing qualification does not satisfy that gate when the issue's acceptance
criteria also require publication, installable-artifact verification, an
operational drill, or another later observation. After those criteria are
publicly demonstrated, a maintainer records `completion:evidence-verified`; for
a defect, the public report must name the fixed version or source identity.

Status labels remain derived triage aids. The audit changes stale labels to
`status:done` only when a closed issue has satisfied its explicit completion
gate. A premature close is reopened on GitHub and remains in its previous open
status (or returns to triage when that status is unavailable). Closed issues
that predate the gate are preserved unless they are reopened, at which point
the audit enrolls them in the current completion contract. External automation
may read or mirror GitHub state; it must not send lifecycle state back to this
workflow.

Every migrated issue contains exactly one stable `beta-work-id` marker, and each
work ID identifies exactly one issue. Migration first searches open and closed
issues across the complete public inventory. One match preserves its current
title, maintainer-authored body, labels, and lifecycle state. The only
source-owned body field reconciled on replay is the bounded unblock-condition
section for a blocked migration. When review advances a dependency-free item
from blocked to ready, migration consumes that bounded section as transition
proof, removes it, and replaces `status:blocked` with `status:ready` on the same
open issue. Once the section is gone, later replays preserve GitHub lifecycle
changes. A repeated identity across issues receives `authority:conflict` and
makes the workflow fail. Multiple distinct identities on one issue fail a
read-only preflight before shared labels, milestones, issue labels, issue bodies,
or issue creation can change. Replaying migration therefore cannot alias
lifecycle or blocker state, duplicate an issue, or make completed GitHub work
pending again.

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

The workflow's repository-scoped `GITHUB_TOKEN` performs discovery with only
Contents read and Issues read permissions. GitHub's public repository graph is
available to that token across the explicit inventory in `policy.json`; no
operator-provisioned cross-repository discovery credential is required. The
token runs outside the protected environment and cannot change issue or
authority state.

Cross-repository metadata and issues are written separately with
`BETA_PRODUCT_WORK_TOKEN` in the protected `beta-product-work` GitHub
environment. That lifecycle credential needs repository metadata read and
Issues read/write access only for the same public repositories. It does not
need source, package, release, environment, or private repository access, and
it is never exposed to an event whose current issue revision failed intake.

Private Cloud implementation work is outside this inventory. If public
components need a Cloud-facing contract, the public issue describes only that
contract and links no private implementation detail.
