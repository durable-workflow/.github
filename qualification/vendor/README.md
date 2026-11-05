These files are inert reference inputs for the PHP bootstrap source controls.
They are not actions and the shared workflows do not invoke them.

`setup-php-f3e473d/{unix.sh,linux.sh}` are the exact files at
[`shivammathur/setup-php` f3e473d116dcccaddc5834248c87452386958240](https://github.com/shivammathur/setup-php/tree/f3e473d116dcccaddc5834248c87452386958240/src/scripts).
The upstream MIT license is retained beside them.

`php-ubuntu-713206915/install.sh` is the 3,406-byte public release asset
713206915 from `shivammathur/php-ubuntu`, with SHA-256
`7bc5bfea71696b0927367eb887e2710d44c6f17216fbd47add5a4cb181543e99`.
Its bytes matched the separately read GitHub asset metadata on 2026-11-05.
The upstream MIT license is retained beside it.

The candidate installer and thirty NTS/release archive identities are in
`../php-linux-bootstrap.json`. They are proposed pins for independent review on
[central issue 297](https://github.com/durable-workflow/.github/issues/297),
not an execution or adoption decision. No archive was fetched for this source
checkpoint. The catalog never resolves a mutable tag/name at runtime.

Run the inert controls from the repository root:

```sh
python3 -m unittest tests.test_php_linux_bootstrap
```

The controls execute only extracted shell functions with command stubs and
inert sealed-memory data. They never execute an installer, PHP, APT, sudo or
archive extraction. Consumer wiring and the surrounding setup-php tool,
extension and preinstalled-runtime paths remain outside this source component.
