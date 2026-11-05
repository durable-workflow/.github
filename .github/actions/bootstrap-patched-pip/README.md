# Private pip and CI trust

This composite action preserves the caller's selected Python version and its
existing pip. It creates a mode0700 environment under `RUNNER_TEMP` with stock
`venv --without-pip`, then uses the existing pip's `--python` option to seed only
the hash-bound pip wheel into that empty environment. It never upgrades or
uninstalls system pip, uses `--ignore-installed`, or invokes ensurepip.

The source validates the wheel and its complete RECORD before installation,
then binds installed modules, distribution metadata, generated entrypoints,
the selected interpreter, and certifi to those bytes. A stdlib-only origin
probe runs with `-I -S -B` and explicitly adds only the validated private
site-packages root. The action exports the private `bin` directory through
`GITHUB_PATH`, disables user-site/home overrides and pip configuration/keyring
discovery, and retains the existing CA outputs and client selection.

Hosted setup-python callers retain their exact selected executable and version.
Only that toolcache runtime's validated library directory is used for its loader;
ambient loader paths, preload hooks and audit hooks do not enter the controller.
An unsafe owner, writable parent, foreign link, changed origin or unsupported
manager refuses without a system fallback. The manager must support pip's stock
`--python` primitive (22.3 or later).

The `pip-state` output identifies the exact private receipt. A later action call
with `operation: verify` requires that explicit receipt, rechecks private pip,
interpreter/manager origins and the exported trust clone, and performs no network
acquisition. Normal bootstrap also verifies an existing explicit receipt rather
than creating another environment. The action refuses startup hooks such as
`.pth`, `sitecustomize` and `usercustomize` in the private site-packages root.

The trust exporter reads the bound certifi file through a no-follow descriptor,
checks blocked subjects using the absolute validated OpenSSL executable under a
closed environment, and writes only held GitHub command files and private CA
outputs. `ca-file`, `ca-directory` and `ca-sha256` keep their existing meanings.

Failed seeding removes its newly allocated exact state. Successful state lives
for the job so later clients can use its trust bundle. A bounded qualification
must remove that exact state and verify absence before reporting terminal PASS;
ordinary disposable hosted jobs retain GitHub's job teardown lifecycle.

Source controls use stock pip with an inert local wheel to reproduce the Debian
no-RECORD refusal and prove that an empty private target succeeds while manager
pip remains unchanged. They perform no public package execution or system
installation. Run them with:

```sh
python -B -m unittest tests.test_private_pip_runtime tests.test_ci_trust
```

The prior initial PHP qualification failed before setup and consumed its original
attempt. This source correction does not rerun that attempt, qualify another
PHP/OS tuple, authorize consumer adoption, or publish an artifact.
