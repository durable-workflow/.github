# Release plans

A release plan is the immutable, pre-publication identity for one coherent
seven-component release. The `Release plan` workflow validates a supplied JSON
document against [`schema.json`](schema.json), proves its public branch and tag
preconditions, and records it at `release-plan/<plan>` in Git and as a GitHub
Release asset.

Before recording the plan, the workflow also prepares exact dated release
notes for every component. The resulting record, validated by
[`preparation-schema.json`](preparation-schema.json), is stored in the same
immutable Git record and mirrored on the same GitHub Release. Each entry binds
the planned version, the original source commit, the note text and digest, and
the immutable public source from which the text was derived. Repositories with
a maintained `CHANGELOG.md` use its `Unreleased` section; other release
surfaces use the planned source commit message. Product contributors therefore
keep describing unreleased changes without selecting the automatically planned
patch version.

The preparation record is structured release-note authority; it does not
create a component commit or update a component default branch. Replaying the
same plan recovers the first immutable preparation record even if the retry is
on a later date. Component recovery and publication can compare the plan tag,
plan digest, component version, source commit, note digest, and source evidence
before creating a version tag or publishing. Preparation consequently cannot
look like new component source, recursively allocate another patch, or resume
with notes prepared for another version.

Plans contain only public source identities, intended versions, their release
channel, and immutable authorization references. They never contain registry
credentials. Each component repository discovers these records on its own
schedule and uses its own GitHub token and publication environment to resume
its release.

For the workspace-unavailable continuity drill, scheduled component recovery
recognizes the public `beta-continuity/<plan>/accepted` record and waits until
the matching `resumed` record exists. An explicit recovery dispatch naming the
exact plan remains available in every component repository and bypasses that
scheduled pause. The controller can therefore publish one component, retain a
provably partial interruption, and later resume the same plan, while each
repository keeps an independent exact-plan recovery path.

The fixed dependency order is enforced through public artifact verification:

| Tier | Components | Required public predecessors |
| --- | --- | --- |
| 0 | Workflow, PHP SDK | None |
| 1 | Waterline, server | Workflow; Waterline also requires the PHP SDK |
| 2 | CLI, Python SDK, Rust SDK | server |

Workflow and Waterline use exact `2.0.0-alpha.N` versions in an alpha plan and
exact `2.0.0-beta.N` versions in a beta plan. A beta plan additionally names an
immutable `beta-authorization/*` record whose candidate and seven-component
tuple match the plan exactly. The protected
[`Beta authorization`](../beta-authorization/README.md) action is the
repository-owned producer and recovery path for that record. An alpha plan
cannot name or satisfy that gate.

Before a plan is recorded, GitHub must report `v2` as the effective default
branch for Workflow and Waterline and `main` for the other five repositories.
This is what makes their scheduled recovery entry points authoritative.

Only one plan may be recoverable and incomplete at a time. Recording a
different plan fails closed until every earlier `release-plan/*` Git tag has
either its matching immutable `release-candidate/<channel>/*` completion record
or a protected `release-plan-failure/*` terminal record. Ordinary interrupted
plans remain blocking and continue through their repository recovery actions.
The only continuity-drill exception is an exact successor whose immutable
`beta-continuity/<successor>/accepted` record identifies the prior diagnostic
interruption by tag, commit, evidence digest, and plan digest. Preflight reads
both immutable records and verifies the prior plan-record commit before it
treats that invalid interruption as superseded; unrelated incomplete plans
remain blocking.

The `Release plan supersession` action is the narrow exception for allocations
that cannot be published without mutating public history. This includes a
version already public from a different source commit and an intended source
whose authoritative package manifest declares a different version. Python
`pyproject.toml` project metadata and Rust `Cargo.toml` package metadata are
verified before a plan is recorded and again during supersession. The action
runs through the `release-plan-supersession` environment and requires that the
live environment allow only a custom `main` branch policy. It verifies public
release and distribution identities for existing-version conflicts and
immutable source manifest identities for manifest conflicts. It also verifies
the dispatched workflow run and its approved environment review through GitHub,
retaining both the dispatching actor and approving user identities in the
terminal record. All mutable conflict, successor-version, environment-policy,
and approval evidence is rechecked immediately before the immutable record is
published. Once published, the Git record is the durable authority, so later
policy or reviewer changes cannot invalidate the bound successor.

The immutable record retains every independently proven conflict and the exact
successor document as `successor-release-plan.json`. The successor must keep
every unaffected component unchanged and resolve every affected allocation. An
existing-version conflict retains the intended source commit and allocates the
immediate next version. A source-manifest conflict retains the intended version,
replaces the incompatible source commit, and proves the successor manifest
declares that version. When the incompatible planned source already occupies its
immutable version tag but has no GitHub Release or public distribution, the
successor allocates the immediate next version, replaces the incompatible
commit, and proves its manifest declares the new version. Repeating the action
compares the existing record; it cannot replace its conflicts, approval
evidence, or successor.

The `Release plan observer` workflow derives progress from the real public
surfaces and retains `release-state.json` on the plan's GitHub Release. Once all
seven components are public, it invokes the existing candidate verifier and
records `release-candidate/<channel>/<plan>` with the channel in the immutable
record itself. This prevents an alpha recovery proof from becoming beta
authorization. A
rerun never needs an Actions artifact or a local checkout from an earlier run.
When an observer encounters a terminal record, `release-state.json` identifies
all conflicting components and their evidence and directs recovery to the exact
stored successor plan rather than retrying an unrecoverable publication.
