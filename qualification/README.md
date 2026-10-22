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
privileged caches. The sole secret exception is an isolated Sonar analysis job
on a branch in the same repository: a credential-free checkout and the official
scanner, with the analysis token only on the final scanner step. It may produce
coverage first using trusted repository code and approved actions. Other steps
cannot reference secrets; existing cache restrictions still apply. Forks do
not run this job.
The scanner rejects `pull_request_target`, mutable container
images, unreviewed `workflow_run` consumers, and privileged artifact consumers
without exact producer and digest provenance.

Product repositories own their tests, documentation deployment, publication,
and deployment workflows. Editorial wording is outside this policy.

## Clean trust for dependency requests

Linux jobs that fetch Composer dependencies use this order after checkout:

```yaml
- uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6
  with:
    python-version: '3.13'
- uses: durable-workflow/.github/.github/actions/bootstrap-patched-pip@4414f6fcdbb8cca75dac1358db5af9aadd8c65f6 # clean-trust
  with:
    clients: pip,python,composer,curl,git
- uses: shivammathur/setup-php@f3e473d116dcccaddc5834248c87452386958240 # v2
  with:
    php-version: '8.3'
    tools: composer:2.10.3
- uses: durable-workflow/.github/.github/actions/verify-composer-trust@4414f6fcdbb8cca75dac1358db5af9aadd8c65f6 # clean-trust
- run: composer install --prefer-dist --no-interaction
```

The bootstrap authenticates the pip wheel by SHA-256 before exporting its
verified CA bundle. It selects both a file and an empty directory because pip's
default truststore can otherwise add roots from the operating system even when
`PIP_CERT` points to a clean file. An offline localhost regression checks that
counterfactual with the actual pip process.

The live verifier loads the installed Composer PHAR without executing project
plugins. It checks Composer's version, selected file and directory, configuration,
bundle hash, parsed certificates and enabled TLS before the next dependency
request. Use its `working-directory` input when the project is in a subdirectory.
It reports trust identities without dumping configuration or credentials.

Select only the clients a job uses. `npm` and `cargo` add their own package-client
overrides. The action does not make raw Node's compiled-in store safe, and it
does not use additive `NODE_EXTRA_CA_CERTS`. Node runtimes and native Windows
certificate backends need their own qualified release or trust configuration.
The pinned action download and hosted runner bootstrap remain a trust boundary.

For migrated targets, `composer_trust_required` makes the normal validator scan
every job in every workflow, including referenced repository shell helpers. A
Composer network command requires the reviewed bootstrap, fixed Composer setup
and unconditional live verifier in order. Unknown pins, omitted jobs, ignored
guards and later trust overrides fail. The check covers the repository's authored
request paths. It is not a shell sandbox or a claim about third-party actions'
internal requests. Enable the target setting after migrating all its request
paths so partial rollouts remain visible.
