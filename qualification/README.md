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
Cache restores in pull-request workflows must also exclude external forks at
the job or step condition. An earlier revision can populate the same PR cache,
so event-partitioned keys alone do not protect a later revision's build. An exact
shared key remains available for guarded restores and protected-main-only saves.
The scanner rejects `pull_request_target`, mutable container
images, unreviewed `workflow_run` consumers, and privileged artifact consumers
without exact producer and digest provenance.

A privileged `workflow_dispatch` job must be limited to the protected branch.
The only exceptions are listed in `privileged_tag_dispatch_workflows`: one named
workflow, its named jobs and one environment. Each listed job needs an
unconditional, unprivileged plan job and carries the exact
`github.ref == format('refs/tags/{0}', inputs.<tag>)` predicate as a top-level
condition, so a release runs from its own tag ref and a wrong ref fails in the
plan job. The workflow may have no other trigger.

Product repositories own their tests, documentation deployment, publication,
and deployment workflows. Editorial wording is outside this policy.

## Clean trust for dependency requests

### Composer inside a container

A host verifier cannot establish the trust used by Composer inside a build or
running container. The container must run `verify-composer-trust/verify.php`
against its own Composer binary and final project configuration, immediately
before each Composer command. Use the authenticated CA file and an empty
additional-root directory inside that same request boundary.

`verify-composer-container-trust` prepares inputs for registered container
requests. It checks the actual Git checkout and selected commit, compares the
Dockerfile and preparation files with an explicitly reviewed recipe, and checks
the bootstrap's CA digest against the actual file. It returns the verifier
context directory, CA file and digest, source commit, and Dockerfile digest. Its
provenance contains identities and hashes without environment or credentials.
The entire build context must match the selected Git tree, including raw file
bytes and executable modes. Tracked, staged, untracked and ignored changes
refuse. Docker exclusion files must be part of the reviewed recipe. New clean
product commits can use the same recipe while its build instructions remain
unchanged.

Give the action the actual `compose-directory`. It renders the registered local
Compose files with `--env-file /dev/null` and verifies every registered service's
build context, Dockerfile, stage, verifier context, source arguments and CA secret.
The immediately following build uses the same directory and the action's outputs
for all trust/source variables and `COMPOSE_FILE`. The central caller contract
requires that exact command and refuses an omitted, conditional, ignored or stale
guard. No rendered application configuration is printed or retained.
Its `ca-file` and `ca-sha256` inputs must reference outputs of the same earlier,
unconditional reviewed `bootstrap-patched-pip` step. Ambient or step-local CA
values cannot supply that identity. Additional Docker, Compose or Buildx build
commands in the registered job also refuse, including calls in shell helpers.

The initial `sdk-php-cooperative-server` entry in
`composer-container-trust.json` has no approved recipes. It therefore refuses
every build until the Server hook and caller pass combined container controls.
This preparation action does not make SDK-PHP's Composer migration mandatory or
authorize its new audit job. Those changes follow combined qualification.

The container control runs the actual digest-pinned Composer image against a
local synthetic TLS registry. The ambient store accepts its synthetic blocked
root. The verified clean store refuses before an HTTP request. Wrong bundle
digests, extra roots and a missing verifier also refuse. This exercises the
container client; BuildKit mount lifetime and final-image inspection remain
part of the Server hook's combined qualification.

### Composer on the runner

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


## Protected pilot source successor

The selective successor to [the reverted pilot](https://github.com/durable-workflow/.github/pull/240)
keeps ordinary consumer preflight and Composer helper interpretation at the
accepted rollback behavior. Its shared-policy changes allow only the pinned
App-token action and the byte-exact protected workflow. The stricter input
language lives in `scripts/protected_policy_context.py`, called only by the
protected reader before the shared validator. Candidate files remain bounded
nonexecutable data; the reader and issuer run from the protected base.

The pilot accepts new run text only as newline-separated literal commands with
fixed interpreter forms. Shell expansion, operators, escapes, inline environment
assignments, evaluator options and constructed command names refuse. Literal
data flags such as `--source` remain supported. Referenced shell helpers obey the
same language, including when `bash` reads a file with a misleading extension.
Python helper text remains data; this is not whole-program behavior analysis.

Five existing control workflows contain complex shell programs. Their complete
raw file SHA-256 identities are a finite compatibility catalog in the protected
checker source, not candidate-supplied assertions or a general Bash parser. A
changed file, changed execution context, relocated copy or new complex program
cannot inherit that exception; updating the catalog requires exact source
review. The catalog does not exempt referenced shell-helper bytes, root-directory
checks or interpreter/startup environment checks. The retained cancellation
workflow is a source compatibility identity, not admission to run its fixtures.

Relative helper references require the workspace root and a reviewed shell.
YAML traversal bounds depth and expanded alias work and refuses recursive
aliases, duplicate keys and merges. These conservative protected-pilot rules do
not change ordinary caller behavior. Run the dedicated controls with:

```sh
python -m unittest tests.test_protected_policy_context tests.test_protected_policy_check tests.test_protected_policy_inputs tests.test_protected_policy_issue
```

Integration also requires the Rust analytics checker's source-root correction
and actual old/new execution controls. The visual workflow keeps the candidate
build in its existing directory, then invokes that checker from the workspace
root with an explicit build directory. The SDK owner must prove that the checker
resolves its own source assets and preserves all content assertions. A passing
central context test does not substitute for that upstream compatibility proof.

The source remains inactive. No App/key, protected variable or secret,
environment, event-policy setting, required rule or live check is provisioned.
The existing [AI contribution issue](https://github.com/durable-workflow/ai/issues/27)
waits for accepted source and a separately qualified one-repository pilot. Human
account/key authorization and the live positive/negative, expected-issuer,
concurrency and rollback controls remain separate prerequisites.
