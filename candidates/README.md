# Beta candidate records

The `Beta candidate` GitHub workflow verifies and records a coherent public
release tuple. A dispatch supplies one JSON value conforming to
[`schema.json`](schema.json). The fixed [`main.json`](main.json) tuple exercises
the same path whenever this repository's main branch changes. It is the next
candidate to qualify, not the mutable supported-train pointer; current-train
verification derives its candidate input from the current release plan.

Every component version must be an exact release and every commit must be its
full 40-character source identity. Repository and registry locations are owned
by the verifier rather than supplied by the request:

| Component | Public artifact surface | Source identity check |
| --- | --- | --- |
| Workflow | Packagist `durable-workflow/workflow` | Packagist source/dist reference and GitHub release tag |
| Waterline | Packagist `durable-workflow/waterline` and Docker Hub `durableworkflow/waterline` | Packagist source/dist reference, OCI manifest/platform/config-label evidence, and one GitHub release tag |
| server | Docker Hub `durableworkflow/server` | OCI config labels and GitHub release tag |
| CLI | GitHub release assets | release checksums, build-attestation source commit/ref, and GitHub release tag |
| PHP SDK | Packagist `durable-workflow/sdk` | Packagist source/dist reference and GitHub release tag |
| Python SDK | PyPI `durable-workflow` | registry digests, repository metadata, and GitHub release tag |
| Rust SDK | crates.io `durable-workflow` | registry digest, packaged VCS identity, and GitHub release tag |

## Immutability and recovery

The authoritative record is the Git tag `beta-candidate/<candidate>`. Its
root commit contains only canonical `candidate.json` and `verification.json`.
The workflow never force-pushes that tag. A repeated request must have the same
canonical manifest; otherwise it fails before any record can change.

A GitHub Release with the same tag mirrors both files for convenient API and
browser queries. Reruns recreate a missing release or missing asset, but reject
an existing asset whose bytes differ from the tagged authority. Actions logs
and temporary workflow artifacts are not part of the record.

For example, after replacing the repository and candidate names as needed:

```text
GET /repos/durable-workflow/.github/releases/tags/beta-candidate%2F<CANDIDATE>
GET /repos/durable-workflow/.github/contents/candidate.json?ref=beta-candidate%2F<CANDIDATE>
GET /repos/durable-workflow/.github/contents/verification.json?ref=beta-candidate%2F<CANDIDATE>
```

The manifest contains public versions and source commits only. Registry
credentials, publishing environments, conformance results, and product secrets
are deliberately outside this format.

Waterline remains one manifest component. Its verification result has a
required `distributions` object with `embedded` Composer and `service` OCI
records. Both records are checked against the component's one version, source
tag, and full commit; either missing record makes the candidate unverifiable.

Candidate manifests using `durable-workflow.beta-candidate/v2` require that
dual-distribution verification contract. The verifier recognizes v1 evidence
only for the exact immutable candidate manifests recorded before the service
image became a required Waterline distribution.
