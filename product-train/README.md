# Durable Workflow product train

[`current.json`](current.json) is the machine-readable authority for the one
supported Durable Workflow 2.0 product train. Selecting its `current` value
selects exact server, CLI, Workflow, Waterline operator, PHP SDK, Python SDK,
and Rust SDK artifacts together. The Python registry normalizes the SemVer tag
`2.0.0-beta.10` to the PEP 440 spelling `2.0.0b10`; both identify the same train.

New beta release plans must use every version in the current train. A beta
increment advances all seven component identities together. After stable 2.0,
compatible capabilities follow ordinary semantic-version progression: fixes
use patches, additive capabilities use minors, and breaking changes use a new
major.

Earlier 2.0 alphas and mixed-version beta tuples remain immutable historical
artifacts, but they are unsupported and omitted from install guidance. They
may be yanked where a registry supports yanking without deleting release
history. No compatibility adapter between those prereleases and the current
train is part of the product contract.
