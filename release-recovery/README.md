# Component release recovery authority

[`authority.json`](authority.json) is the protected, machine-readable source
identity for every component's scheduled and manual release recovery workflow.
Each component first resolves protected `main` to an exact commit and requires
the `Beta candidate` push run for that same commit to have completed
successfully. Only then does it read this document from the resolved commit,
check the repository and protected target branch against the built-in product
topology, and require the exact normalized workflow SHA-256 before release
discovery can dispatch publication.

Workflow changes must land on their protected component branch before this
tuple is refreshed. A mismatched, missing, inactive, or differently located
workflow fails closed in every component. The source document intentionally
contains the full component tuple so a refresh is one reviewable change rather
than independent per-repository digest edits. Recovery evidence retains the
qualified authority commit, exact manifest SHA-256, and successful
qualification run identity.
