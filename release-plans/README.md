# Release plans

A release plan is the immutable, pre-publication identity for one coherent
seven-component release. The `Release plan` workflow validates a supplied JSON
document against [`schema.json`](schema.json), proves its public branch and tag
preconditions, and records it at `release-plan/<plan>` in Git and as a GitHub
Release asset.

Plans contain only public source identities, intended versions, their release
channel, and immutable authorization references. They never contain registry
credentials. Each component repository discovers these records on its own
schedule and uses its own GitHub token and publication environment to resume
its release.

The fixed dependency order is enforced through public artifact verification:

| Tier | Components | Required public predecessors |
| --- | --- | --- |
| 0 | Workflow, PHP SDK | None |
| 1 | Waterline, server | Workflow; Waterline also requires the PHP SDK |
| 2 | CLI, Python SDK, Rust SDK | server |

Workflow and Waterline use exact `2.0.0-alpha.N` versions in an alpha plan and
exact `2.0.0-beta.N` versions in a beta plan. A beta plan additionally names an
immutable `beta-authorization/*` record whose candidate and seven-component
tuple match the plan exactly. An alpha plan cannot name or satisfy that gate.

Before a plan is recorded, GitHub must report `v2` as the effective default
branch for Workflow and Waterline and `main` for the other five repositories.
This is what makes their scheduled recovery entry points authoritative.

Only one plan may be recoverable and incomplete at a time. Recording a
different plan fails closed until every earlier `release-plan/*` Git tag has
either its matching immutable `release-candidate/<channel>/*` completion record
or a protected `release-plan-failure/*` terminal record. Ordinary interrupted
plans remain blocking and continue through their repository recovery actions.

The `Release plan supersession` action is the narrow exception for allocations
that cannot be published without mutating public history. This includes a
version already public from a different source commit and an intended source
whose package manifest declares a different version. The action runs through
the `release-plan-supersession` environment and requires that the live
environment allow only a custom `main` branch policy. It verifies public release
and distribution identities for existing-version conflicts and immutable source
manifest identities for manifest conflicts. It also verifies the dispatched
workflow run and its approved environment review through GitHub, retaining both
the dispatching actor and approving user identities in the terminal record.

The immutable record retains every independently proven conflict and the exact
successor document as `successor-release-plan.json`. The successor must keep
every unaffected component unchanged and resolve every affected allocation. An
existing-version conflict retains the intended source commit and allocates the
immediate next version. A source-manifest conflict retains the intended version,
replaces the incompatible source commit, and proves the successor manifest
declares that version. Repeating the action compares the existing record; it
cannot replace its conflicts, approval evidence, or successor.

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
