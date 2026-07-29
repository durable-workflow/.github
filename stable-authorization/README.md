# Protected stable 2.0 authorization

[`contract.json`](contract.json) is the public machine-readable release
authority for the stable 2.0 evidence gate. It fixes the release-critical
experiment set, the PHP, Python, and Rust polyglot cells, the seven artifact
components, and every fail-closed evidence rule. A historical aggregate pass
percentage is never part of the stable release claim.

An authorization request conforming to
[`request-schema.json`](request-schema.json) selects one immutable
`release-candidate/rc/*` tag and its exact Workflow, Waterline, server, CLI,
PHP SDK, Python SDK, and Rust SDK identities. Every supplied experiment record
also cites that tuple by tag, commit, and canonical SHA-256. Its public source
is digest-bound and must contain the same canonical evidence fields except for
the source locator itself.

The evaluator always creates a
[`readout-schema.json`](readout-schema.json) document. Missing tier records or
polyglot cells remain visible as missing; tuple mismatches are stale; execution
results are pass, fail, or runner-blocked. Incomplete evidence leaves stable
authorization blocked without preventing another prerelease or a later
readout.

The `Stable authorization` workflow verifies the candidate tag and every
public evidence source before enforcing readiness. Only a passing evidence job
can start the `stable-authorization` environment job. That environment must
allow only `main`, require the product owner, and prevent self-review, so the
approval is an explicit human release decision made after the evidence gate.

The resulting `stable-authorization/2.0.0/*` tag contains the exact contract,
request, readout, and authorization record. A GitHub Release with the same tag
mirrors all four files. Repeating the same request compares or repairs that
immutable authority; a changed tuple, evidence set, or readout fails closed.
The authorization record permits a later stable publication operation but
does not itself publish or retag any component.
