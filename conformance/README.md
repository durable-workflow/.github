# Conformance

`catalog.json` is the public source of truth for the fixed Durable Workflow 2.0
release-critical experiment tier. It names the experiment, owning repository,
runner command, execution location, timeout, result artifact, and acceptance
property.

GitHub Actions runs ordinary repeatable checks and any experiment that fits a
hosted runner. Experiments that need controlled Docker restarts, process loss,
private managed-runtime access, or other infrastructure behavior run from a
local isolated checkout using the catalog command. Local execution does not
create local authority: every run is reported as a
[`kind:conformance-run`](https://github.com/durable-workflow/.github/issues?q=is%3Aissue+label%3Akind%3Aconformance-run)
GitHub issue with its exact tuple and evidence.

## Run contract

1. Use only published packages and images from the exact proposed artifact
   tuple. Check out the runner repository at the source revision bound to that
   published artifact.
2. Create an isolated result directory and Docker project. Never reuse a
   customer namespace or another experiment's database, cache, network, or
   volume.
3. Run every runner listed for the experiment. A partial matrix is not a pass.
4. Preserve the structured result and a bounded sanitized log. Remove
   credentials, customer identifiers, and private infrastructure details.
5. Open a conformance-run issue containing the experiment ID, exact seven-part
   tuple, runner revision, timestamps, command, outcome, and evidence link.
6. A product failure opens or updates an issue in the owning product repository
   and links the fix PR, regression fixture, published replacement artifact,
   and confirming run.
7. Clean up local resources only after the evidence is available from GitHub.

## Outcomes

- `pass`: all catalog runners and acceptance properties passed on the exact
  tuple.
- `product-fail`: the experiment ran and exposed incorrect product behavior.
- `runner-blocked`: the product could not be evaluated because the runner or
  infrastructure failed. This is not a product failure and is not a pass.
- `out-of-scope`: the experiment was intentionally not attempted for this
  release. Release-critical experiments cannot use this outcome for stable
  authorization.

Missing, stale, partial, and runner-blocked evidence all deny a stable release.
Historical aggregate pass rate is never release authority.
