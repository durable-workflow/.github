# Beta conformance

The `Beta conformance` workflow runs the portable beta experiment set from a
clean GitHub-hosted runner. Its only product input is a canonical manifest that
already exists at the immutable Git tag `beta-candidate/<candidate>`.
`prepare` rejects a different tuple, invalid verification, an abbreviated
source identity, a distribution without recorded SHA-256 identities, or a
server image without the recorded OCI manifest digest. The plan binds the
digest of the complete candidate verification document as well as normalized
digests for every package, crate, image manifest, and CLI release asset.

The experiment contract is [`contract.json`](contract.json). It selects replay,
polyglot, worker-heartbeat, and signals/query runners shipped inside the exact
published server image. Those runners install the candidate's PHP SDK from
Packagist, Python SDK from PyPI, Rust SDK from crates.io, CLI release assets,
and Composer packages by exact version. Product checkouts and mutable package
selectors are not inputs to this workflow.

Runner entries declare the distributions they consume and any runtime they need
from the candidate. The union of the runner distribution sets must equal the
experiment's complete required set. The direct PHP SDK runner declares a
standalone server dependency, so the portable wrapper
bootstraps the digest-pinned candidate image and starts its HTTP, queue-worker,
and scheduler processes on isolated Docker state. The wrapper waits for the
published readiness endpoint before injecting the loopback URL, namespace, and
ephemeral token into that runner; it removes the containers and database volume
after every attempt.

## Independent execution

Dispatch `.github/workflows/beta-conformance.yml` with the complete canonical
candidate JSON. An optional `injected_failure_experiment` proves that a
same-version distribution digest mismatch is recorded, retained, and left red.
The injected mismatch is never passed through the infrastructure retry
classifier.

The same entry point can be exercised on any clean runner with Git, Python,
and Docker after checking out this repository at a full commit and fetching
the immutable candidate tags:

```text
python scripts/beta_conformance.py prepare candidate.json plan.json \
  --contract beta-conformance/contract.json \
  --runner-revision <FULL_CONTROL_PLANE_COMMIT>
python scripts/beta_conformance.py extract plan.json published-server extraction.json
python scripts/beta_conformance.py run plan.json replay published-server result \
  --contract beta-conformance/contract.json
```

`extract` pulls `docker.io/durableworkflow/server@sha256:<digest>` from the
candidate verification and copies the conformance orchestration and fixtures
from that container. It never falls back to a server checkout.

## Evidence and failure behavior

Every experiment result conforms to
[`result-schema.json`](result-schema.json) and repeats these bindings:

- the candidate name, manifest digest, immutable Git record, and exact
  seven-artifact version/commit tuple;
- the public source commit for every artifact;
- the candidate verification-document digest and expected distribution digests;
- bounded native evidence identifying the package, crate, image manifest, and
  release-asset bytes actually executed by the published runner;
- the control-plane runner revision and contract digest;
- the exact server OCI digest used to obtain the product-owned runner;
- the owning product contract, outcome, retry record, failure fingerprint,
  and bounded diagnostic tails and findings.

Native results at or below the 4 MiB portable evidence limit retain their exact
size and complete SHA-256 identity. An oversized result is never read or hashed
in full: the wrapper retains its observed size and the SHA-256 identity of at
most the first 64 KiB, with the hashed byte count recorded separately.

The wrapper recognizes only a small allowlist of registry and connection
transients. Those failures may run twice. A native non-passing result, timeout,
missing published runner, or injected distribution identity mismatch is never
retried.
Detached registry snapshots are not accepted as execution evidence. Each runner
must report identities derived from its own executed downloads for exactly the
distributions assigned to that runner. The experiment-wide check then requires
the complete distribution set declared by the experiment and matches every
reported identity to the immutable candidate record. Missing native evidence is
a non-retryable infrastructure failure; an exact-version or digest mismatch is
a non-retryable product failure under the experiment's owning contract.
Matching version strings cannot satisfy the identity check. A passing retained
suite covers all seven distributions.
Experiments run in separate GitHub matrix jobs, have explicit deadlines, use
unique scratch and Docker state, and prune Docker resources on every exit path.

The execution workflow keeps `contents: read` for every job. After its matrix
finishes, even when one cell is red, the separate `Beta conformance retention`
workflow runs from the trusted default branch with only `actions: read` and
`contents: write`. It validates that the source is a completed, same-repository
`Beta conformance` run on `main`, binds the execution plan to that run's exact
commit, and aggregates its retained JSON artifacts from the trusted default-
branch retention controller without executing artifact content.
The retention workflow can also be dispatched with an existing run ID and
attempt, allowing a completed matrix to be recovered without running it again.
Release creation tolerates a bounded transient API denial; a later recovery
attempt still consumes the same source run and attempt and produces the same
evidence tag.

Retention creates a GitHub Release tagged
`beta-conformance/<candidate>/<run-id>.<run-attempt>`. Its canonical suite and
experiment JSON assets are durable, immutable-by-comparison mirrors. They can
be queried later through the GitHub Releases API, independently of the Actions
job log or artifact-retention window.
