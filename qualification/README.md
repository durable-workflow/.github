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

### Protected gate input layer

`scripts/protected_policy_inputs.py` captures an open public pull request against
the expected repository ID and exact `main` commit. It reads the candidate's
exact commit/tree identities and regular workflow blobs, plus literal referenced
helper blobs needed by the existing Composer inspection. Paths, file counts,
individual sizes, total bytes and encoding are bounded. Symlinks, submodules,
truncated trees and a changed PR identity refuse. Materialized files are data
with mode `0600`; candidate commands are never executed by this layer.

The caller must supply a bounded read-only GitHub API client from protected
source, keep candidate data outside the interpreter's import path, and call
`require_current` again immediately before issuing a result. This module does
not create a Check Run, grant merge authority, configure an Environment or prove
an issuer binding. Those live integration requirements remain open. Private
repositories are explicitly refused until their separate gate is qualified.

### Read-only protected-policy pilot client

`scripts/protected_policy_check.py` connects that input layer to the reviewed
validator for the public `.github` pilot. It binds the immutable repository ID,
requires the expected protected `main` SHA, and rechecks main and PR identity
after validation. Candidate workflow/helper files are temporary nonexecutable
data outside Python's import path. The policy always comes from the reviewed
central checkout; there is no candidate policy-path override.

After the authenticated bootstrap exports its CA file, empty additional-root
directory and digest, a read-only caller uses:

```sh
python -I scripts/protected_policy_check.py \
  --pull-request "$POLICY_PULL_REQUEST" --base-sha "$POLICY_BASE_SHA"
```

The client requires curl 8.4 or newer, an explicit matching CA bundle and no
additional roots. Transfers are HTTPS GETs to the fixed GitHub API host, with
no redirects or automatic content decoding. Each response is capped at 8 MiB;
there is a 15-second request budget and a shared 120-second API budget. JSON
depth/node counts, endpoint shapes and request counts are also bounded. A read
token, when supplied as `GITHUB_TOKEN`, travels on stdin rather than process
arguments. The caller grants only Contents read and Pull requests read. Never
give the reader the App signing key or its Checks-write token.

Success prints a bounded identity/digest report. Failure prints escaped JSON
and exits nonzero; candidate text cannot become a GitHub workflow command.
Ordinary PR CI exercises the real read client and validator. That candidate
controlled job remains a component test. Protected base execution, the App
issuer, immediate identity recheck, environment-denial tests and issuer-bound
repository rules still require separate live acceptance before enforcement.

### Prepared App issuer component

`scripts/protected_policy_issue.py` prepares the checks-only issuer for that
same public pilot. It runs the validator itself rather than accepting a
candidate-supplied report. The read-only `GITHUB_TOKEN` and separate
`POLICY_CHECKS_TOKEN` installation token have different roles; the issuer never
accepts or reads an App signing key. `POLICY_GATE_APP_ID` must name the reviewed
installation's App. The App must have Checks write and implicit Metadata read
only, installed solely on the pilot repository.

The intended protected caller uses:

```sh
python -I scripts/protected_policy_issue.py \
  --pull-request "$POLICY_PULL_REQUEST" --base-sha "$POLICY_BASE_SHA" \
  --expected-head "$POLICY_HEAD_SHA"
```

It checks the protected-main workflow context and exact event head, validates
bounded candidate data, creates one incomplete Check Run, and verifies the
returned check name, original head and App ID. Only then does it re-read the
protected main and complete PR identity immediately before completing that
same check successfully. Read and write credentials use stdin, with explicit
reviewed TLS roots and the existing transfer/time/JSON bounds. The App client
has no arbitrary endpoint or repository input. Refusal exits nonzero and never
reports success; a check already created may remain incomplete. A later head
cannot inherit an earlier head's successful check.

Caller environment markers are defense in depth, not proof of secret denial.
The workflow binding, immutable trusted-source selection, Environment branch
restriction, narrow policy exception, actual App installation and issuer-bound
branch rule still need separate review and live acceptance. The current policy
continues to forbid every `pull_request_target` workflow. No workflow is enabled
by this component. Its constructed-response tests prove the code paths only,
not GitHub's live Environment or merge enforcement.

The transport uses GitHub's [create and update Check Run API](https://docs.github.com/en/rest/checks/runs)
and checks the documented [workflow environment variables](https://docs.github.com/en/actions/reference/workflows-and-actions/variables).

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
