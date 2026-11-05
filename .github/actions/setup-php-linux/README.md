# Initial Linux setup source proposal

This action is not used by a workflow. Source and effect reviews remain on
[central issue 297](https://github.com/durable-workflow/.github/issues/297).
No setup, root extraction or hosted qualification has run for this proposal.

The first closed profile is Ubuntu 26.04, x86_64, PHP 8.3 NTS/release, production
INI, explicit `composer:2.10.3, phpunit:11.5.57`, coverage `none`, and no extension
override. The actual distribution/release/architecture are read from the host;
`ubuntu-latest` is never a distribution selector. Other profiles refuse before
acquisition. The larger archive catalog is source inventory for future review,
not acceptance of those profiles.

The candidate PHP archive is asset 672923785,
`php_8.3-nts+ubuntu26.04.tar.zst`, 41,840,918 bytes, SHA-256
`846f69bcf56fc25f672ab888415c12d40122b684c8fb9f1de87b7ddb64fa4272`.
The original installer is asset 713206915, 3,406 bytes, SHA-256
`7bc5bfea71696b0927367eb887e2710d44c6f17216fbd47add5a4cb181543e99`.
The two literal PHAR identities and publisher evidence are in
`qualification/php-linux-tools.json`. General selected PHPUnit's captured
publisher digest authority; its detached signature remains unverified.
Composer's signature verification is recorded separately. The original
stronger data controller's refusal remains its terminal result.

The trusted Node24 action replaces itself with trusted Python. Python captures
only known inputs, then replaces itself with a closed-environment process and
private HOME/TMP before reading those inputs or running upstream code. The
two absolute Python transitions both use `-I -S -B`, suppressing ambient Python
configuration, system/user site initialization and bytecode writes before the
source import boundary. The receipt distinguishes effective action inputs, environment inputs and omitted
values. Action metadata defaults cannot be distinguished from explicit caller
fields. Empty coverage/tools inputs keep their upstream meanings and refuse
this first profile. No GitHub-token input/default is exposed.

The recipe requires the existing authenticated shared CA output, exact digest
`50f79f98dac192b20dbf73f35c56f0b0c557ab267ff5199d1117cc1180b70785`,
and an empty additional-root directory. The existing `bootstrap-patched-pip`
action's `clients: python` export can supply that predecessor without an APT
route. Network reads use an exclusive Python TLS context and no proxy/auth.
GitHub asset reads use literal asset IDs and closed redirects; PHAR reads use
literal URLs with no redirects. No tag discovery, retry or fallback exists.

Every installer/archive/tool stream must match its independent size and digest
before it is sealed. All four streams are held before the first installation.
The same sealed archive descriptor feeds inspection and root extraction. The
inspector accepts only canonical directory/regular-file members; links,
sparse/special members, unknown PAX semantics and canonical/parent/type
collisions refuse. Directory and implicit-parent identities are tracked as
well as file identities. The derived installer excludes APT/dpkg input state and the package-state merge
helper; it never runs APT, that helper or a service start. It retains the
upstream archive's root file extraction, alternatives and Redis INI effects.
Host library/prerequisite failures refuse without package repair. This always
installs the bound archive, including when ambient PHP was already present.

Installed PHP/php-config paths, binary bytes, actual minor/NTS/release flags,
shared modules and active CLI startup configuration are bound before default
PHP startup. Unknown startup configuration/modules refuse. The full 88-file
pinned upstream runtime is verified against Git blob and SHA-256 identities,
then five shell files receive deterministic acquisition/repair guards. A
private refusal marker catches failures masked by upstream's fail-fast option.
Upstream tool dispatch receives internal `none`; the original PHAR request is
handled separately using held-FD installs and target byte/mode checks. Actual
configured extensions and coverage are checked before success.

The normal script owns private runtime cleanup and a stage-specific receipt.
Malformed archive/library failures are terminal refusals, with native HTTP/TLS
cause/status fields retained without recording signed URLs or credentials.
Existing host Node/Python/sudo/tar/zstd and native libraries remain host-tool
prerequisites, not software this action provisions. Source controls do not
qualify that host tuple, archive contents or any installed executable.

Run the inert controls from the repository root:

```sh
python3 -m unittest tests.test_php_linux_bootstrap tests.test_php_linux_tools tests.test_php_linux_recipe tests.test_php_linux_archive tests.test_setup_php_linux
```

The controls use inert transports, root/PHP executors and in-memory archives.
The credential boundary additionally uses real Python `execve` into an inert
probe; it keeps the PID and removes credential variables. The controls also
compare the exact predecessor's archive admissions and Python startup to
the corrected refusals/isolated startup without changing system site files.
They do not run the installer, PHP/PHAR, APT, root extraction or an actual setup.

Before any future effect, independently review the exact source/tree and this
candidate tuple. A proposed first qualification is one ephemeral native
Ubuntu26.04/x64 runner, with the actual image/tool identities read back first,
only this PHP/archive/two-PHAR tuple, one job, no credentials or persisted
checkout authentication, and no other package setup. A 15-minute job ceiling
bounds the original attempt; no retry, changed tuple, package repair or
fallback is included. The original receipt must show all four pinned inputs,
the transformed installer/source identities, zero APT/service/merge-helper
execution, installed-file and effective-PHP checks, and private cleanup.
No such effect is selected by committing this source.
