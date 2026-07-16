# Public target qualification

`policy.json` is the machine-readable authority for source qualification before
a beta candidate can be initiated. Every listed workflow runs from its product
repository, on its public target branch, and can be rerun directly in GitHub.

The scheduled qualification audit resolves each target branch to an exact
commit, requires successful check runs for that commit, and queries GitHub's
active branch rules. A target is eligible only when its required check contexts
are enforced with strict status checks. The audit does not use a workspace,
Forgejo, private databases, or repository mutation credentials.

The policy also owns the approved release references for actions used by public
workflows. The audit reads every workflow at the resolved target commit,
resolves each action release to its exact commit, and checks the action manifest
against the supported JavaScript runtime set. Action commits, declared
references, runtimes, and consuming workflow paths are retained in the audit
evidence. Product repositories continue to own and run their workflows
directly, including manual recovery entry points.

The documentation check covers builds, links, version routing, and generated
retrieval surfaces. Editorial wording is deliberately outside this policy.
