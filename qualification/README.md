# GitHub Actions policy

`policy.json` is the reviewed organization policy for GitHub Actions references
and workflow trust boundaries. Product repositories load it during pull-request
checks and validate their own checked-out workflow files.

The policy binds allowed Action releases to immutable commits and records the
supported JavaScript runtimes. It also defines the restrictions applied to
privileged workflows, artifact handoffs, token permissions, caches, containers,
and pull-request execution.

Validate any checked-out public repository without GitHub credentials:

```sh
python scripts/qualification_policy.py validate \
  --target server \
  --workflow-directory ../server/.github/workflows
```

Every governed product repository runs this validator in GitHub Actions. It
fails when a workflow uses an unknown or mutable Action reference or crosses a
trust boundary that the policy does not allow.

Workflows must declare read-only or empty top-level token permissions. Write
access is job-local, and pull-request jobs cannot use environments, secrets, or
privileged caches. The scanner rejects `pull_request_target`, mutable container
images, unreviewed `workflow_run` consumers, and privileged artifact consumers
without exact producer and digest provenance.

Product repositories own their tests, documentation deployment, publication,
and deployment workflows. Editorial wording is outside this policy.
