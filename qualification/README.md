# Public target qualification

`policy.json` is the machine-readable authority for source qualification before
a beta candidate can be initiated. Every listed workflow runs from its product
repository, on its public target branch, and can be rerun directly in GitHub.

The scheduled qualification audit resolves each target branch to an exact
commit, requires successful check runs for that commit, and queries GitHub's
active branch rules. A target is eligible only when its required check contexts
are enforced with strict status checks. The audit does not use a workspace,
Forgejo, private databases, or repository mutation credentials.

The documentation check covers builds, links, version routing, and generated
retrieval surfaces. Editorial wording is deliberately outside this policy.
