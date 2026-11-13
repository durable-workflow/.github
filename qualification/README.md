# GitHub Actions policy

## Initial PHP archive derivation

The initial Ubuntu 26.04/x64/PHP 8.3 source recipe uses the exact asset and
metadata recorded in `php-linux-initial-archive.json`, with the closed map in
`php-linux-initial-normalization.json`. `scripts/php_linux_normalize.py` copies
only contained regular targets, including their file metadata, into a sealed
regular-only archive. The strict root-input inspector continues to reject raw
links, sparse members, special files and path collisions. The producer writes
a complete archive-derived manifest before installation; receipt v3 binds its
object and bytes, original and derived archive identities, and alias target
provenance. Terminal qualification retains and checks that same manifest before
and after both PHAR probes, then removes exact owned state before publishing PASS.

The separate Ubuntu 24.04/x64/PHP 8.3 normalization source is recorded in
`php-linux-ubuntu24-archive.json` and `php-linux-ubuntu24-normalization.json`.
Selection requires the complete pinned asset identity, not a caller-supplied
map or path. Its 685 links have 637 contained regular targets and 48 explicit
directory or unresolved omissions; the derived inventory has 3,215 files and
373 directories. The source setup gate requires the exact Ubuntu 24.04 or
26.04 x64 host and matching complete archive identity, PHP 8.3, both literal
PHARs, coverage none and no extension override. Other catalog tuples refuse.
The accepted installed runs recorded in
[#297](https://github.com/durable-workflow/.github/issues/297) covered the
earlier Ubuntu 26.04 and Ubuntu 24.04 assets, which upstream has since replaced.
Each consumer still needs its own source binding and actual caller qualification.

### Upstream asset replacement

The scheduled *Check PHP setup pins upstream* workflow
(`php-linux-upstream-pins.yml`, daily and manual) fails when any pinned archive
ID is no longer published with the same name, size and digest, or when
`install.sh` bytes change. Its step summary lists each affected row, whether it
is a setup-profile row, and the current same-name candidate ID, size and digest.

`shivammathur/php-ubuntu` replaces its `builds` release assets in place, and a
replaced asset ID returns 404. Setup never falls back to a newer asset. To
re-pin, download the new asset by ID, check its size and SHA-256 against the
release API `digest`, and update `php-linux-bootstrap.json`. The catalog pins
only the archives setup uses (`HOST_ARCHIVES`), so every row needs re-pinning. Then rebuild each
setup profile's records in place from that exact local file:

```sh
python3 -I -S -B scripts/php_linux_profile_records.py 24.04 < ARCHIVE
```

The command refuses bytes that differ from the catalog. It prints the record
hashes and counts for `SOURCE_PROFILES`. Copy the new metadata hash into the
matching alternatives inventory, then update `INVENTORIES`, `PROFILES` and
`HOST_ARCHIVES` to the new asset ID. Before merging, review the member and
link differences against the previous records.

Receipt v4 additionally binds the initial CLI configuration. It derives the
production INI from the held archive's `php.ini-production.cli` and the exact
pinned PHP, xdebug and JIT configuration fragments. The bounded input document
is captured before configuration writes. Only CLI `php.ini`, CLI `99-pecl.ini`
and the explicit production marker are written; only inventory-bound CLI
xdebug/pcov startup entries are removed. The derived upstream helpers leave
other SAPIs unchanged and do not consult an ambient current-INI marker.

Terminal verification independently recomputes these outputs from the held
preimage and pinned source, checks the complete active CLI inventory, and holds
the configuration document through both PHAR probes and cleanup. Current live
qualification requires v4. Retained legacy readers and source controls do not
qualify a new installed original. A changed effect packet and distinct run
selection remain necessary before executing this source.

The fixed updater's writer inventories are in `php-linux-initial-alternatives.json`
and `php-linux-ubuntu24-alternatives.json`. They bind their respective metadata
hashes and the same exact stock writers. The generated installer bytes remain
unchanged. Setup and terminal verification pass the selected original asset
through the CLI configuration and alternatives checks; a document's profile
label cannot choose its own expected configuration. Post-probe alternatives
verification retains a copy of that same asset identity.
Nine archive-materialized alternatives paths are master links created by
`fix_alternatives`. Extraction excludes those exact paths, leaving their
creation to the existing updater after extraction. Both link hops and the
held versioned target bytes are verified before PHP and again before and after
the terminal probes. Registration alone retains higher-priority automatic or
preselected manual alternatives. After registration completes, the initial
recipe explicitly selects only those nine held versioned targets with the
stock updater and refuses any selection failure. Other registered options and
unrelated groups remain intact. The other eight alternatives aliases remain regular
copies: the library alias and seven plain manpage aliases have no writer in
that function. Its seven gzip-manpage slave operations use different names;
the socket operation has no contained regular target. Those existing operations
are retained without treating them as authority for another archive alias.

The focused source controls use inert archives, the stock alternatives updater
and temporary paths. They reproduce the regular-alternatives failure and check
the corrected extraction/updater/selection order, including higher-priority,
manual and already-selected choices, but do not establish installed PHP
configuration, module, loader or PHAR behavior. Historical installed originals
remain NONPASS. The live manual workflow keeps its immutable helpers; successor
adoption and a fresh installed qualification require their separate source and
effect decisions. Other host, PHP, tool and consumer tuples do not inherit this
initial profile.

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

An explicitly optional binding can be absent; every present job still satisfies
its full trust binding. `optional_jobs` allows only named, registered jobs to be
absent. These presence exceptions support the Server alias-promotion rollout:
accepted Server retains its legacy release alias job while the successor moves
that job into a separate protected workflow. Tighten the bindings after Server
accepts the successor. Neither option admits an unregistered privileged job or
relaxes ref, environment, plan verifier or failed-plan checks.

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

The guard stages only that authenticated public CA into a new owned mode-0700
directory inside the Compose tree. It verifies a single regular, non-symlink
source object and the original SHA-256, writes a mode-0400 copy, and binds the
rendered secret to that copy. Staging stays outside the Server and verifier
image contexts. This satisfies Bake's workspace filesystem boundary without
granting extra filesystem access or changing which store is trusted.
The authenticated original must remain under the owned `RUNNER_TEMP`; staging
and cleanup stay under the owned `GITHUB_WORKSPACE`. Both Python entry points
ignore workspace imports and site configuration. Directory descriptors hold
the selected parents while reading or removing the copy; aliases and changed
parent, state or file identities refuse before removal.

After the registered stack is stopped, an always-run caller cleanup step
uses the same guard's source and outputs, when present, to remove only the copy:

```sh
if [[ -n "$STAGED_CA" ]]; then
  python3 -I -S -B "$VERIFIER_CONTEXT/../../../scripts/composer_container_trust.py" cleanup-ca \
    --ca-file "$STAGED_CA" --ca-sha256 "$CA_SHA256" --compose-directory .
fi
```

Here `VERIFIER_CONTEXT`, `STAGED_CA` and `CA_SHA256` are the guard's
`context-directory`, `ca-file` and `ca-sha256` outputs. Cleanup refuses another
path, modified bytes, symlinks, hard links or unrelated directory contents.
The bootstrap's original selected bundle remains intact. A guard failure
cleans its staged copy before publishing any outputs.

The `sdk-php-cooperative-server` entry in `composer-container-trust.json`
applies only to its registered Compose request and reviewed Server recipes.
It supplies no trust for other build or runtime paths.

Its additional Server 3.8.0 recipe comes from published source
`28f084513235f6647e740c4b3d9e3aace7a323b7`. It binds the fixed APT parent
Dockerfile, lockfile, copied/executed `docker/apt/require-fixed-apt.sh` and
`docker/apt/parent.v1.json` proof alongside the existing preparation inputs.
The older recipe remains available. Source matching alone does not qualify
the caller: its clean predecessor, live in-container verifier and actual
registered Compose request remain required.

The `composer-container-trust` action-release role approves only the container
verifier path. It cannot supply the clean bootstrap or host Composer verifier.
The container request still binds its CA file and digest to an earlier,
independently approved clean bootstrap.

The container control runs the actual digest-pinned Composer image against a
local synthetic TLS registry. The ambient store accepts its synthetic blocked
root. The verified clean store refuses before an HTTP request. Wrong bundle
digests, extra roots and a missing verifier also refuse. This exercises the
container client; BuildKit mount lifetime and final-image inspection remain
part of the Server hook's combined qualification.

### Composer through a reviewed PHP launcher

The same catalog has a separate `runtime_setups` entry for Sample App's PHP CI
launcher. It binds the exact setup command, target, workflow/jobs, literal PHP
matrix, build inputs, launcher and TLS control by file hash and mode. An
unreviewed Dockerfile exclusion file refuses. The setup probes and exports an
immutable local image config ID; subsequent PHP and Composer invocations use
that ID. The actual Composer TLS control runs in both PHP profiles: ambient
trust reaches a synthetic HTTPS repository, while the selected clean bundle
refuses before an HTTP request.

This recognizes the PHP setup only. The reviewed clean bootstrap must still
precede it, and the reviewed live Composer verifier must run in the container
immediately before every dependency-request step. The launcher mounts the
selected CA file and empty additional-root directory read-only and inspects the
real Composer PHAR. Runtime selector overrides, changed source bytes or modes,
conditional/ignored setup, another target/job, and missing/intervening guards
refuse. This entry does not approve arbitrary Docker commands or another
repository's launcher.

### Composer on the runner

For the initial Ubuntu 24.04 or 26.04 x64 PHP 8.3 production profile, the policy
recognizes this dependency-request order after checkout. Use a literal supported
runner. The immutable setup entry approves only the `setup-php-linux` action path;
it does not approve other actions at that revision.

```yaml
- uses: durable-workflow/.github/.github/actions/bootstrap-patched-pip@242c2a7fb23459db2e1ada5f84dbee6d61d9b1e5 # clean-trust
  with:
    clients: python,composer,curl,git
- uses: durable-workflow/.github/.github/actions/setup-php-linux@411a14ac07d32073eed6ab4977f2825eba4739a7 # bound-linux-php
  with:
    php-version: '8.3'
    tools: composer:2.10.3,phpunit:11.5.57
    coverage: none
- uses: durable-workflow/.github/.github/actions/verify-composer-trust@242c2a7fb23459db2e1ada5f84dbee6d61d9b1e5 # clean-trust
- run: composer install --prefer-dist --no-interaction
```

The bound setup requires the Python trust client as well as Composer, curl and
Git. Its source contract requires those literal PHP/tool/coverage values,
production INI and no extension or INI-value override. The live verifier remains
required immediately before each dependency-request step. This policy entry is
source support for migration, not an installed caller result: retain independent
post-product setup revalidation and both setup/private-pip cleanup, and qualify
the actual consumer before release or publication.

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

Before that whole-target migration, `composer_trust_scopes` can name a workflow
and job for the bound initial PHP profile. The job is checked when it adopts
the reviewed setup action, including every enumerated dependency request and
its immediate live verifier. Other jobs retain their previous scope; a verifier
outside the named migration still enables the existing whole-repository checks.
Targets already requiring whole-target Composer trust cannot use scoped settings
to reduce that enforcement.

Workflow's `release-verification.yml` / `published-package` entry now uses
`required: true` after the reviewed caller wiring reached maintained Workflow
main at `2de438d4dcff8f213253603e608324272eeac8e5` (PR1055). This is source
presence/enumeration enforcement, not installed caller acceptance; selecting an
actual caller still requires its separate qualification and terminal cleanup.
A required entry refuses a missing workflow, missing job or missing reviewed
setup. Ambiguous
workflow identities, invalid scopes and a migrated job without an enumerated
dependency request also refuse. The remaining Laravel matrix stays separately
unqualified until its own applicable profiles and callers are delivered.


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
