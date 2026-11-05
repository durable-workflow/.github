# Proposed bound PHAR inputs

The initial Linux setup companion accepts explicit `composer:2.10.3` and
`phpunit:11.5.57` selections, or explicit `none`. An omitted tools input retains
its upstream default meaning and is refused until that exact default is
selected and qualified. Other tools and mutable version selectors are refused.
PHPUnit 11 also refuses PHP 8.1.

`data-preparation.json` records the original bounded, credential-free data
preparation. Both actual PHARs match the literal catalog sizes and SHA-256
values. Composer's publisher Tags Public Key verifies its detached SHA-384
signature. PHPUnit's complete publisher-key authority remains missing: its
signature's full issuer fingerprint is not independently bound by the captured
publisher documentation. The tool selector refuses that tuple before fetching
or installing it. A signature issuer declaration is not a publisher identity.

The PHAR binaries remain private data, outside Git. Nothing here executes PHP,
a PHAR stub, package code, setup, APT or a root extraction. `php_linux_tools.py`
contains proposed effect primitives and has no command-line entrypoint. Its
source tests inject inert transports/installers and exercise real sealed input
descriptors. The surrounding setup adapter and any actual execution require
separate review and selection on central issue 297.

Run the inert controls from the repository root:

```sh
python3 -m unittest tests.test_php_linux_bootstrap tests.test_php_linux_tools
```
