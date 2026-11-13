# Committed command-response loss

This shared transport fixture supports [#216](https://github.com/durable-workflow/.github/issues/216).
It forwards one selected request to a loopback HTTP runtime, reads the complete
successful upstream response, then closes the client connection before sending
an HTTP status line. The next request forwards normally. The fixture does not
retry a request or decide whether command admission was idempotent.

`CommittedResponseLoss(upstream)` accepts only `http://127.0.0.1:<port>` with a
canonical explicit port. Credentials, hostnames, paths, query and fragment
components refuse. It binds an ephemeral loopback port. Start its
`serve_forever` method in a thread and route the installed client through `url`.
Call `arm(method, path)` with the exact admission route before the selected
request. The caller owns shutdown, the runtime, synthetic data and cleanup.

Requests and responses each have a fixed 1 MiB wire-body cap and bounded socket
timeouts. POST requires one canonical Content-Length; request transfer encodings
refuse. GET is bodyless and may omit Content-Length. Complete bounded chunked
upstream responses are supported. Invalid, oversized or incomplete upstream
responses produce a generic 502 and no success record. A matching valid request
consumes the arm even if its upstream attempt fails; re-arming is explicit.

`records` contains method/path, request byte count/hash, complete upstream status,
response byte count/hash and the dropped flag. It retains no headers, parsed
JSON, caller keys, results or payloads. SDK adapters compare their own request
and retained-admission identities independently. Use synthetic inputs and
retain only the metadata needed by the experiment.

Run the socket controls without dependencies or an external runtime:

```sh
python3 -I -S -B conformance/command-keys/test_committed_response_loss.py
```

The controls prove upstream success was complete before the client received
`RemoteDisconnected`, and that one incoming request caused exactly one upstream
request. It also checks one-shot path selection, ordinary forwarding, errors
and numeric loopback confinement. Negative controls cover framing, byte caps,
incomplete upstream responses and body/header evidence minimization. The earlier
CLI fixture is preserved in Git history; this correction tightens its reusable
authority, resource and evidence boundaries.

An SDK/CLI adapter still verifies the actual published tuple, original/generated
key, durable admission count, concurrent identical retries, changed-intent
conflicts, closure/continuation, namespace/run fences and retained identities.
Record those outcomes separately from this transport control. Producer-owned
legacy-shape and physical-upgrade seeds remain separate; the proxy creates
neither. The [original published reproduction](https://github.com/durable-workflow/.github/issues/216#issuecomment-6296529480)
describes the earlier loss scenarios and is not current installed acceptance.
