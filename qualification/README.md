# Public target qualification

`policy.json` is the machine-readable authority for source qualification before
a beta candidate can be initiated. Every listed workflow runs from its product
repository, on its public target branch, and can be rerun directly in GitHub.

The scheduled qualification audit resolves each target branch to an exact
commit, requires successful check runs for that commit, and queries GitHub's
active branch rules. A target is eligible only when its required check contexts
are enforced with strict status checks. The audit does not use a workspace,
Forgejo, private databases, or repository mutation credentials.

The policy also owns the immutable commits and readable release labels for
actions used by public workflows. The audit reads every workflow at the
resolved target commit, rejects mutable references, and checks action manifests
against the supported JavaScript runtime set. Container actions use approved
OCI manifest digests. Action commits, release labels, runtimes, consuming
workflow paths, permissions, and trust-boundary findings are retained in the
audit evidence.

The same scanner can qualify any checked-out public repository without GitHub
credentials:

```sh
python scripts/qualification_policy.py validate \
  --target server \
  --workflow-directory ../server/.github/workflows
```

Every workflow must declare read-only or empty top-level token permissions.
Write access is job-local, pull-request jobs cannot reference environments or
secrets, and pull-request caches have separate event namespaces and narrow
dependency paths rather than workspace or home-directory roots. Privileged
manual-dispatch jobs must fail closed outside the repository's protected target
ref. The scanner rejects `pull_request_target`, mutable container images,
unreviewed `workflow_run` consumers, and privileged artifact consumers without
an exact producer and digest provenance. Reviewed source-identity and artifact
digest validators must be the first shell execution after their exact
policy-declared sequence of immutable setup or download Action steps, including
each step's complete input map. Each validator's complete shell command and
arguments are policy-declared and matched exactly. Validator jobs must use the
policy-declared GitHub-hosted runner without job containers or services, and the
validators run in the default shell and working directory with only their
policy-declared environment names effective. Product
repositories continue to own and run their qualification, documentation deployment,
publication, and recovery workflows directly.

The documentation check covers builds, links, version routing, and generated
retrieval surfaces. Editorial wording is deliberately outside this policy.
