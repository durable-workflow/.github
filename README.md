# Durable Workflow

Welcome to the Durable Workflow project! This project is dedicated to creating tools and libraries for developers to build and manage durable, long-running, persistent, distributed workflows.

## Public release control plane

The machine-readable [product-train authority](product-train/README.md) maps
one Durable Workflow 2.0 choice to the exact seven-component tuple, every
required distribution, and their ecosystem install commands. It also defines
synchronized beta progression and the historical-prerelease policy.

This repository also owns the organization-level automation that records
verified, immutable beta candidate tuples on GitHub. See the
[candidate record contract](candidates/README.md) for the public artifact
surfaces, source-identity checks, durable query paths, and recovery behavior.

It also records and observes channel-aware, pre-publication
[release plans](release-plans/README.md). Publication remains repository-owned:
each component discovers plans and resumes with only its own GitHub token and
repository-local publication environment.

The protected [beta authorization authority](beta-authorization/README.md)
binds a product-owner decision to the exact proposed beta plan and its public
qualification, candidate, conformance, continuity, and backlog evidence. Its
append-only Git and GitHub Release record authorizes beta only; stable 2.0 has
a separate decision boundary.

The scheduled [workspace-unavailable continuity controller](beta-continuity/README.md)
assembles those public authorities into an interruption-and-resume drill. Its
append-only phase records bind GitHub issue intake, exact qualification,
release recovery, public verification, and clean-runner conformance without a
bootstrap workspace.

Published candidate tuples can be exercised by the independently runnable
[beta conformance workflow](beta-conformance/README.md). Its retained GitHub
Release evidence binds every experiment to the exact seven-component tuple,
all required distribution identities, their source identities, and the
conformance runner revision.

New public product work and the deliberately selected unresolved beta backlog
use [GitHub issue authority](issue-authority/README.md). Organization issue
forms capture durable intake context, while a one-way lifecycle audit prevents
an external mirror from reopening completed GitHub work.

The [public target qualification policy](qualification/README.md) also enforces
the organization-wide Actions trust boundary: immutable action and container
references, job-scoped credentials, isolated pull requests and caches, and
reviewed artifact consumers.

The machine-readable
[public repository hygiene inventory](repository-hygiene/inventory.json)
records the maintained protected branches, the synchronized release train, and
the cleanup completed for the 2.0 product surface.
