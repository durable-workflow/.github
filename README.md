# Durable Workflow

Welcome to the Durable Workflow project! This project is dedicated to creating tools and libraries for developers to build and manage durable, long-running, persistent, distributed workflows.

## Public release control plane

This repository also owns the organization-level automation that records
verified, immutable beta candidate tuples on GitHub. See the
[candidate record contract](candidates/README.md) for the public artifact
surfaces, source-identity checks, durable query paths, and recovery behavior.

It also records and observes channel-aware, pre-publication
[release plans](release-plans/README.md). Publication remains repository-owned:
each component discovers plans and resumes with only its own GitHub token and
repository-local publication environment.
