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

Only one plan may be incomplete at a time. Recording a different plan fails
closed until every earlier `release-plan/*` Git tag has its matching immutable
`release-candidate/<channel>/*` completion record. Scheduled newest-plan
discovery therefore cannot strand an interrupted older plan; the older plan
continues to be the only discoverable incomplete identity until it completes.

The `Release plan observer` workflow derives progress from the real public
surfaces and retains `release-state.json` on the plan's GitHub Release. Once all
seven components are public, it invokes the existing candidate verifier and
records `release-candidate/<channel>/<plan>` with the channel in the immutable
record itself. This prevents an alpha recovery proof from becoming beta
authorization. A
rerun never needs an Actions artifact or a local checkout from an earlier run.
