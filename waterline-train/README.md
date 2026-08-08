# Waterline release train

Waterline intentionally pins the PHP SDK exactly during the 2.0 prerelease.
That keeps each published Waterline package reproducible, but means a newer PHP
SDK cannot become part of the current install tuple until a sequential
Waterline prerelease exists with the new exact pin.

`contract.json` is the machine-owned coordination policy. A conflicting SDK
advance routes a Waterline successor; it never mutates an old package or adds a
compatibility shim. The completion workflow accepts only an immutable release
plan tag. It re-reads the tag, Git record, and release mirror; verifies the
source-bound GitHub releases, Packagist packages, and Waterline service image;
runs a fresh exact Composer solve; and binds the deployed docs revision to its
linked retained quickstart run. Caller-authored pass fields are not completion
evidence.

`completion-evidence-schema.json` defines the record generated from those
public checks. Completion remains unavailable while the current docs tuple or
five-scenario quickstart evidence is absent, stale, or bound to another tuple.
