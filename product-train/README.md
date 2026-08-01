# Durable Workflow product train

[`current.json`](current.json) is the machine-readable authority for the one
supported Durable Workflow 2.0 product train. Selecting its `current` record
selects exact server, CLI, Workflow, Waterline operator, PHP SDK, Python SDK,
and Rust SDK artifacts together. The record identifier names the aggregate
authority; each component keeps its own prerelease sequence. Python registry
versions use the PEP 440 spelling of the selected Python SDK version.
Waterline remains one component. Its `install.waterline` record publishes
separate `embedded` Composer and `service` OCI commands at that component's
single train version.

The supported train also binds its exact immutable `release-plan/*` tag and
canonical plan digest. A train is not complete authority until that plan and
its matching terminal completion record are public.

The same train binds
[`sdk-server-qualification.json`](sdk-server-qualification.json) by SHA-256.
That record carries the exact source identity, outcome, and published-artifact
conformance source for every PHP, Python, and Rust SDK binding to Server. A
missing, failed, stale, or tuple-mismatched qualification is not a supported
train and cannot become public compatibility guidance. Validation downloads the
pinned conformance suite, verifies its bytes, and requires passing heartbeat,
replay, and signal/query results that exercised all three SDK clients.

New aggregate prerelease plans must use every exact version in the current
train. Component prerelease sequences advance independently, while one
immutable candidate, release plan, and retained conformance suite bind the
installable tuple as a unit. After stable 2.0, compatible capabilities follow
ordinary semantic-version progression: fixes use patches, additive
capabilities use minors, and breaking changes use a new major.

Earlier 2.0 alphas, betas, release candidates, and mixed-version tuples remain
immutable historical artifacts, but they are unsupported and omitted from
install guidance. They may be yanked where a registry supports yanking without
deleting release history. No compatibility adapter between those prereleases
and the current train is part of the product contract.
