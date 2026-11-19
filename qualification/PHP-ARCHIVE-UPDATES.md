# Updating the bound PHP archives

Routine PHP archive updates are data pull requests to `main`. They never change
the native policy runtime or organization ruleset 26628397.

## What is data and who reads it

| Data on `main` | Read by |
|---|---|
| `qualification/php-linux-bootstrap.json`: each setup archive's upstream identity (asset ID, name, size, SHA-256), normalization profile hashes and counts, and `mirror` record | `setup-php-linux` at the commit a workflow pins |
| `qualification/php-linux-<profile>-{archive,normalization,alternatives}.json` | `setup-php-linux`, via the catalog's profile hashes |
| `qualification/policy.json` `bound-linux-php` pins | consumer preflights (as before) and the native policy runtime |
| `qualification/protected-policy-data.json`: reviewed exact workflow bytes | the native policy runtime |

The native policy runtime is frozen at the commit the ruleset selects. It reads
this data from the protected `main` commit: for this repository that is the
PR or merge-group base, which must equal `main`. It never reads the data from
the candidate head, so a PR cannot approve its own pin or workflow bytes.

When a PR changes this data, the frozen runtime's data gate also requires:

1. A data-only PR: no file under `.github/` changes in the same PR.
2. Strict schemas for the data and catalog; existing reviewed-workflow
   approvals are immutable (they may only be removed).
3. A new upstream archive identity is live upstream with the same ID, name,
   size and `digest`. Every new or changed row has a `mirror` record whose
   live asset has the same bytes, and the mirror bytes are downloaded through
   setup's exact-ID sealed fetch. The strict inspector
   (`scripts/php_linux_profile_records.py`) re-derives the archive and
   normalization records from those bytes and they must equal the committed
   records byte for byte, with matching catalog hashes, counts and alternatives
   inventory.
4. A new `bound-linux-php` pin is a commit already on `main`, and every setup
   row in that commit's catalog is an approved, mirrored row.
5. A new reviewed workflow identity names the reviewed bytes it derives from
   (`derived_from` and both `fixture` files) and differs from them only by
   replacing approved `bound-linux-php` pins with one new approved pin.

Anything else (a new workflow shape, a third-party action for this
repository's own workflows, a new label) is not routine and still needs a
reviewed runtime change.

## Mirror storage

Each reviewed archive is mirrored byte for byte to its own release in
`durable-workflow/php-archives`, tagged `php-sha256-<first 16 hex of the
SHA-256>`, with GitHub immutable releases enabled. Setup fetches only the
mirror asset ID when a row has a `mirror` record, verifies the exact size and
SHA-256 before sealing the bytes, and never falls back to upstream: a deleted
or different mirror asset fails closed. Asset IDs are never reused, so even a
replaced asset cannot satisfy an existing pin.

## Routine update: a new PHP security release

Nothing below changes the ruleset, `native-policy.yml` or `scripts/`.

1. **Fetch.** In a new empty directory, download each new upstream archive by
   its exact asset ID (`Accept: application/octet-stream`). Compare its size
   and SHA-256 with the release API `digest`.
2. **Records.** Update the row's `asset` in `php-linux-bootstrap.json`, then
   rebuild the profile records from the exact local file:

   ```sh
   python3 -I -S -B scripts/php_linux_profile_records.py 26.04 < DIR/php_8.3-nts+ubuntu26.04.tar.zst
   ```

   Copy the printed metadata hash into the profile's alternatives inventory,
   and set the row's `profile` hashes (`metadata_sha256`, `plan_sha256`,
   `inventory_sha256`) and `counts`.
3. **Mirror (maintainer).** Plan, review, upload, then bind:

   ```sh
   python3 -I -S -B scripts/php_archive_mirror.py plan --archive-dir DIR --release 26.04
   gh api repos/durable-workflow/php-archives/releases/tags/TAG > RELEASE.json
   python3 -I -S -B scripts/php_archive_mirror.py adopt --release-json RELEASE.json
   ```

   `plan` uploads nothing. It re-runs the strict inspector over the local bytes
   against the committed records and prints one `gh release create` command
   per archive, which an authorized maintainer runs. Each release is published
   with its single asset and becomes immutable. `adopt` accepts only a
   published immutable release whose asset has the cataloged name, size and
   `digest`, and writes the row's `mirror` record.
4. **Data PR 1 (archives).** Open a PR with only those `qualification/`
   changes. Review the member and link differences. The required native
   policy gate checks provenance, the mirror and the strict inspector. Merge.
   Call the resulting `main` commit `P`: it is the new setup source.
5. **Data PR 2 (approval).** In `policy.json`, add `P` as `bound-linux-php`
   (retire the old pin when no caller uses it). In
   `protected-policy-data.json`, add one entry per bound workflow
   (`ci.yml`, `qualify-linux-php-initial.yml`, `qualify-linux-php-ubuntu24.yml`)
   whose `fixture` is the reviewed fixture with the old pin replaced by `P`,
   with `derived_from` set to the reviewed fixture's hash. The gate verifies
   that `P` is on `main` and binds only mirrored approved archives, and that
   each new identity is a pure pin substitution. Merge.
6. **Adoption PR.** Replace the old pin with `P` in those workflows (and
   update consumer repositories' `setup-php-linux@` pins). The runtime
   accepts them because `main` now approves `P` and the exact bytes.
7. Run the qualification workflows for the new archives as before.

If upstream replaces an archive that is already mirrored, nothing breaks: setup
keeps using the mirror. Update only when you choose to adopt the new release.

## Non-routine changes

Changes to the checking logic, the gate, or anything the gate refuses go
through a reviewed runtime change: a PR that changes `scripts/`, then a pin of
`native-policy.yml`'s runtime checkout, then an organization-admin ruleset
update selecting that commit on `refs/heads/main`. See `NATIVE-PILOT.md`.
