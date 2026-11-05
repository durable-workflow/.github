# Shared Bookworm parent and early APT preflight proposal

This source-only profile covers PHP **8.4.27 CLI / Debian 12 / amd64 and arm64**.
It does not qualify an installed image or select a build, pull, publisher, or
consumer adoption. The Ubuntu 26.04 / PHP 8.3 hosted setup profile is separate.

The official [Debian advisory](https://lists.debian.org/debian-lts-announce/2026/11/msg00004.html)
sets the Bookworm fixed floor to **2.6.2**. Both
[apt](https://packages.debian.org/bookworm/apt) and
[libapt-pkg6.0](https://packages.debian.org/bookworm/libapt-pkg6.0) must meet it.
`php-8.4.27-cli-bookworm.v1.json` records the exact official index, both native
child manifests, configs, attestation manifests and SPDX statements for the old
and proposed fixed parent. Descriptor bytes/sizes/SHA-256 and SPDX child subjects
were checked with bounded stock public Registry v2 metadata GETs. No rootfs layer
was fetched. The mutable tag was used only to discover the candidate; it is not
a permitted build selector.

| Parent | Index SHA-256 | Publisher APT/libapt records, both architectures |
| --- | --- | --- |
| Existing | `54b467ede1db96c66675e7b78457dd43729d0e7be31978d4a1e5c069ceabcf76` | 2.6.1 / 2.6.1 |
| Proposed | `b3e907a1108629c562c4bb313ce3449e34d49991f6bb2487913f6146f47200fe` | 2.6.2 / 2.6.2 |

The candidate config retains PHP_VERSION=8.4.27 on each native architecture.
These publisher records are source inventory. Actual fixed pair, architecture,
executable availability and affected consumer behavior still need a separately
selected original image qualification.

## Reuse before Python exists

`require-fixed-bookworm-apt.sh` is a single central read-only shell preflight.
It reads the effective Debian release as data, queries the installed native
APT/libapt pair and uses stock dpkg version comparison. It refuses other releases,
architectures, malformed/incomplete/duplicate rows, non-installed status and
either unfixed member. It accepts no overrides, acquires nothing and performs no
repair. It requires only `/bin/sh`, `/usr/bin/env`, `/usr/bin/dpkg-query` and
`/usr/bin/dpkg`; the package-query subprocesses receive an empty environment plus
fixed PATH/locale. It needs neither Python nor an APT operation to start.

The initial consumer source target is Sample App
`.devcontainer/docker/Dockerfile`, observed at commit
`42d9af5957832ed2b0413c7fea1853e4d47ed3f4`, blob
`11d349d36a7d26d6e8cd9abb99fd2a94c876aa73`. Its Brotli build and final stages both
use the old PHP index. Both run the APT-using Brotli helper before the later
obvious APT block; the final stage also runs Playwright with `--with-deps`.

The proposed narrow adoption, after central acceptance and owner selection, is:

1. Keep both existing PHP stage versions and both amd64/arm64 platforms; replace
   only their index with the exact proposed fixed index above.
2. Check out an accepted immutable central source commit without persisted
   credentials into `.central-apt-source` inside the disposable build context.
   Verify actual HEAD equals that literal before the build. Use the same central
   file directly; do not commit a repository-local guard implementation.
3. In each PHP stage, before its first RUN, copy the central file with ordinary
   Docker `COPY` from
   `.central-apt-source/docker/apt/require-fixed-bookworm-apt.sh` and run it with
   `/bin/sh` before the Brotli helper. A missing local context/file fails COPY;
   this route has no external-image/named-context fallback.
4. Invoke that same guard immediately before the later direct APT block and
   Playwright `--with-deps`, so earlier stage operations cannot silently replace
   the accepted effective pair. Preserve all current product/helper pins, source
   graphs, trust gates, test behavior and platform selection.

No action or caller currently invokes this profile. The exact accepted central
commit/file SHA and complete consumer diff are future immutable recipe inputs.
Docker context inclusion and both first-RUN orders must be checked on that
consumer diff before any selected build. Source tests use inert package/release
records and stock offline version comparison; they do not run a container or APT.
The existing Python host guard remains separate and unwired. No historical root
bootstrap or package-manager transaction is restored.
