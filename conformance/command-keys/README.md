# Committed command-response loss

This shared transport fixture supports [#216](https://github.com/durable-workflow/.github/issues/216).
It forwards one selected request to a loopback HTTP runtime, reads the complete
successful upstream response, then closes the client connection before sending
an HTTP status line. The next request forwards normally. The fixture does not
retry a request or decide whether command admission was idempotent.

`CommittedResponseLoss(upstream)` binds an ephemeral loopback port. Start its
`serve_forever` method in a thread and route the installed client through `url`.
Call `arm(method, path)` with the exact admission route before the selected
request. The caller owns shutdown, the runtime, synthetic data and cleanup.

`records` retains method/path, complete upstream status/body length/hash, parsed
synthetic JSON and the dropped flag. It records no headers. Use only synthetic
payloads and retain only the sanitized fields needed by the experiment.

Run the socket controls without dependencies or an external runtime:

```sh
python3 -I -S -B conformance/command-keys/test_committed_response_loss.py
```

The control proves upstream success was complete before the client received
`RemoteDisconnected`, and that one incoming request caused exactly one upstream
request. It also checks one-shot path selection, ordinary forwarding, errors
and loopback confinement. The proxy source is byte-identical to CLI's reviewed
fixture, SHA-256 `5418903ee570c7e205824adb3e8fcec6ab8a959daca6d52e13f59dddbde8834c`.

An SDK/CLI adapter still verifies the actual published tuple, original/generated
key, durable admission count, concurrent identical retries, changed-intent
conflicts, closure/continuation, namespace/run fences and retained identities.
Record those outcomes separately from this transport control. Producer-owned
legacy-shape and physical-upgrade seeds remain separate; the proxy creates
neither. The [original published reproduction](https://github.com/durable-workflow/.github/issues/216#issuecomment-6296529480)
describes the earlier loss scenarios and is not current installed acceptance.
