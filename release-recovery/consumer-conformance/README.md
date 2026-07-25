# Release-recovery consumer conformance

[`contract.json`](contract.json) is the public, versioned behavior contract for
the independently runnable recovery consumers in the seven component
repositories. Its suite digest binds the identical standard-library runner
copied into each repository. The contract lists the complete required case set
and exact protected target topology.

Each component owns a small adapter that pins the contract version, contract
digest, local runner digest, local consumer path, and its distribution-specific
verification command. The shared runner executes the authority cases first and
then delegates repository-specific verification through that adapter. Neither
recovery nor publication depends on this repository at runtime.

Component CI compares a changed contract with the previous target revision and
rejects changed contract content at the same version. Passing evidence records
the source commit, target branch, contract version and digests, every required
case, and the adapter-owned verification result. The control-plane target audit
also compares the contract, suite, and adapter pins on all seven public target
branches.

To validate this source copy without contacting another repository:

```console
python scripts/release_recovery_consumer_conformance.py \
  --contract release-recovery/consumer-conformance/contract.json
```
