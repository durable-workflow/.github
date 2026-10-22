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

## Isolated, hash-locked policy bootstrap

Server's policy preflight requires action revision
`fea245682582d0620054e8547a5f3c968f9ef0f0` and exactly:

```sh
python -I -m pip --isolated install --require-hashes --only-binary=:all: --no-deps -r .central-action-policy/qualification/requirements.lock
```

The reviewed central checkout supplies the lock. It permits only the reviewed
PyYAML 6.0.2 CPython 3.13 glibc Linux wheels for amd64 and arm64. Native CI checks
both wheel installations, a tampered hash, and working-directory `pip.py` and
`pip/` shadows. Missing isolation/integrity/binary/no-dependency flags, another
requirements path, extra options, a missing bootstrap or an older bootstrap
revision fail the Server contract. The same command is available for staged
adoption in other targets. Their legacy forms remain explicit migration work,
not evidence of the locked-policy contract. This source check does not establish
an independent protected execution boundary; that gate requires its own issuer
and repository-rule acceptance.

## Clean trust for dependency requests

Linux jobs that fetch Composer dependencies use this order after checkout:

```yaml
- uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6
  with:
    python-version: '3.13'
- uses: durable-workflow/.github/.github/actions/bootstrap-patched-pip@75587fc33ff40c34f32ef777293dad56bb6f48c7 # clean-trust
  with:
    clients: pip,python,composer,curl,git
- uses: shivammathur/setup-php@f3e473d116dcccaddc5834248c87452386958240 # v2
  with:
    php-version: '8.3'
    tools: composer:2.10.3
- uses: durable-workflow/.github/.github/actions/verify-composer-trust@75587fc33ff40c34f32ef777293dad56bb6f48c7 # clean-trust
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

The real npm and Cargo controls use a synthetic blocked root on localhost. They
check that the raw/additive configuration reaches the test registry and that
the exported trust refuses before an HTTP request. Cargo uses
`CARGO_HTTP_CAINFO` together with the common file and empty directory. The
bootstrap does not set `CARGO_HTTP_PROXY_CAINFO`: Cargo 1.86 refuses that setting
when its proxy is not configured. Unused Go overrides are not advertised.

For migrated targets, `composer_trust_required` makes the normal validator scan
every job in every workflow, including referenced repository shell helpers. A
Composer command requires the reviewed bootstrap and fixed Composer setup, with
an unconditional live verifier immediately before its request step. Only explicit
version/help/list/about operations are treated as local. New subcommands and
script aliases require verification by default. Literal shell helpers, including
extensionless and nested helpers, are inspected for requests and trust mutations.
Python/PHP test data is not interpreted as shell code.

Unknown pins, omitted jobs, ignored guards, intervening steps and trust overrides
fail. The check covers authored literal Composer calls and repository shell
helpers. It is not a shell sandbox, a multi-language program analyzer or a claim
about third-party actions' internal requests. Maintainers still review dynamic
request paths and their actual configuration. Enable the target setting after
migrating all its request paths so partial rollouts remain visible.
