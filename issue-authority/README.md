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
issue coordinates, approval evidence, revision digests, and the structured
completion-hold decision, but no issue text.
The lifecycle job directly refetches every manifest-selected issue and requires
its identity, approval actor, approval time, approval mode, and revision digest
to remain exact before processing the vetted issue bodies. A selected issue's
edit, approval change, or disappearance between those jobs therefore fails
closed before mutation. A newly created or newly visible issue that was absent
from the manifest remains inert until a later discovery run.
Lifecycle evidence retains the matched approval records and revision digests
for review, but later runs reconstruct authority from GitHub instead of
consuming an earlier artifact.

Only the issue title, body revision, and explicit completion-hold label
participate in intake. Headings such as `Completion`, `Delete when`, or
`Acceptance` do not create a hold. Comments, pull-request text, workflow logs,
artifacts, and attachments are not queried or interpreted as issue
instructions.

The cross-repository issue form records every required source target as an
exact `organization/repository@branch` selection in its required-targets
section. Intake binds those selections to the same vetted revision and resolves
their required checks from `qualification/policy.json`. The lifecycle audit
then evaluates the latest trusted linked implementation pull request for each
target. Same-repository execution must bind an authorized pull-request author
and closing-reference actor. A fork or other external attempt participates only
when an authorized maintainer's latest approval names its exact current head
commit. Every admitted attempt also binds its exact pull-request identity, head
repository, head ref and commit, and base repository, ref and commit before
latest-attempt selection. A target is complete only when that attempt merged
into the declared branch, the merge commit remains on the branch, and every
required repository check succeeded. A newer trusted open, rejected, or rebuilt
attempt supersedes earlier evidence for the same target; untrusted public
references remain inert.

The same contract applies to issues created through the API or edited outside
the issue form. A cross-repository revision with a missing, empty, repeated,
unqualified, or single-target section is not admitted to the intake manifest.
The selective public backlog stores the same qualified target identities as
structured data, and its API issue renderer emits the required section in every
new cross-repository body.
Earlier trusted-created revisions are covered by a bounded, checked-in migration
catalog. Each catalog entry names a stable body marker and at least two exact
qualified targets; revisions created by the original issue form may instead
bind the exact repository identities in its legacy affected-repositories
section. The migration applies only to unchanged revisions created before the
target-set contract took effect. Editing, reapproving, or newly applying the
cross-repository label after that cutoff requires the current target section,
so a catalog entry cannot authorize a later revision. Active migrated authority
uses the normal aggregate landing lifecycle. A separate issue-and-revision-bound
record covers each archived completion and names its exact target set. Every
archived protected-branch landing stores the exact required-check identities
that qualified that commit. Before preserving closed/done state, the audit
revalidates the catalog's immutable landing commit against its protected branch
and frozen checks without resolving check names from the current qualification
policy. Changing historical evidence requires a reviewed migration of this
versioned catalog. Archived issues are not reopened, relabeled, or commented on
merely to satisfy the new body syntax.

To migrate any revision outside that bounded catalog, edit its body to add at
least two exact qualified targets, then have a trusted maintainer remove and
reapply `intake:approved` after that edit. If the work has only one source
target, replace its cross-repository kind with the appropriate
single-repository kind instead. Until that migration is reviewed, intake and
lifecycle reconciliation fail closed.

The audit maintains one generated issue comment containing the complete target
set, latest pull requests, landed commits, qualification results, and aggregate
state. This comment is public lifecycle evidence, not an instruction source.
The parent remains open until the aggregate is complete, while each repository
pull request may merge independently. If a later correction supersedes a
completed attempt, the audit reopens the parent. Once all latest attempts
qualify, it closes the parent and derives `status:done`.

`policy.json` owns the public repository inventory and the shared label and
milestone vocabulary. `backlog.json` records the deliberate review of the
unresolved alpha queue and contains only the work selected for migration. A
review disposition does not copy the excluded issue or its operational history
to GitHub.

## State direction

GitHub owns both lifecycle state and completion approval. Ordinary authoritative
issues close when their source has landed and required repository qualification
has passed. A product owner may exceptionally add
`completion:evidence-required` during approved intake when completion also
requires publication, installable-artifact verification, an operational drill,
a live workflow, or another later observation. After that evidence is publicly
demonstrated, a maintainer records `completion:evidence-verified`; for a defect,
the public report must name the fixed version or source identity.

Status labels remain derived triage aids. The audit changes stale labels to
`status:done` when an ordinary issue closes or an explicitly held issue has
satisfied its completion gate. A prematurely closed held issue or incomplete
cross-repository parent is reopened on GitHub and remains in its previous open
status (or returns to triage when that status is unavailable). Removing a
default or obsolete hold remains effective; target aggregation is normal
lifecycle completion and does not add an evidence hold. The audit restores an
evidence label only when the approved intake manifest explicitly declared it.
External automation may read or mirror GitHub state; it must not send lifecycle
state back to this workflow.

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
The repository-scoped job token performs the read-only pull-request, commit,
and check-run lookups used by target aggregation; the writer token is not used
for those reads. Public comment discovery also uses the job token. Before
updating a generated lifecycle comment, the workflow resolves the authenticated
writer identity from the lifecycle credential and matches both its immutable
user ID and login. Marker copies owned by any other user remain inert.

Private Cloud implementation work is outside this inventory. If public
components need a Cloud-facing contract, the public issue describes only that
contract and links no private implementation detail.
