# Payload protection v1 contract

This directory is the implementation contract for opt-in application-payload
protection across Durable Workflow SDKs, Workflow and Server. It fixes the
wire envelope, authenticated context, deterministic vector and initial call
site scope before any implementation is accepted.

The contract does not encrypt protocol metadata, grant a key-provider or
runtime effect, or make a partially protected deployment safe. Implementations
must use an established XChaCha20-Poly1305 library. Python implementations use
PyNaCl/libsodium; the 12-byte-nonce ChaCha20-Poly1305 construction is not a
substitute.

## Envelope recognition

Protected bytes are Avro single-object encoded with
[`ProtectedValue`](protected-value-v1.avsc), whose fingerprint is
`0ba70c3fd6c311ca`. The existing plain `Value` fingerprint remains
`e2a33dff55802237`. A decoder selects the schema from the single-object
fingerprint before decoding the record. A user map containing
`dw_protected`, `alg`, `key_id`, `nonce` or `ciphertext` is still an ordinary
plain value and is never reinterpreted as an envelope.

The protected record is valid only when:

- `dw_protected` is exactly `1`;
- `alg` is exactly `xchacha20poly1305-ietf`;
- `key_id` matches `[A-Za-z0-9._:-]{1,128}`;
- `nonce` is exactly 24 bytes; and
- `ciphertext` contains at least the 16-byte authentication tag.

These structural checks happen before key lookup. Writers use a fresh
cryptographically random nonce for every new protection operation; they do not
derive a nonce from payload or request identity and do not deliberately reuse a
key/nonce pair.

## Authenticated context

AAD is the exact byte concatenation:

```text
"durable-workflow.payload-protection\0"
|| u8(1)
|| lp("xchacha20poly1305-ietf")
|| lp(key_id)
|| lp(namespace)
|| lp(boundary_kind)
```

`lp(x)` is `u32be(len(UTF8(x))) || UTF8(x)`. There is no Unicode, case, path or
namespace normalization. The destination or owning namespace comes from the
authoritative protocol context, never an untrusted payload field. The allowed
boundary kinds are:

```text
workflow_input    workflow_result   activity_input
activity_result   signal_input      update_input
update_result     query_input       query_result
side_effect_result
```

Scheduled starts, child starts and continue-as-new use `workflow_input`.
External storage inherits the logical boundary kind; storage location is not a
new kind.

## Plaintext and errors

AEAD plaintext is the complete existing Avro `Value` single-object byte
sequence, including its fingerprint. A successful AEAD open is not enough: the
inner bytes must be exactly one valid plain `Value` with no trailing bytes.

Readers apply this stable refusal precedence:

1. malformed protected envelope, unsupported version or algorithm:
   `payload_envelope_unsupported`;
2. structurally valid envelope with unknown `key_id`:
   `payload_key_unavailable`;
3. authentication failure, including namespace or boundary substitution:
   `payload_authentication_failed`;
4. authenticated bytes that are not one complete plain `Value`:
   `payload_plaintext_invalid`.

An enabled boundary is strict by default: a plain `Value` is
`payload_protection_required`. An explicitly configured migration reader may
accept historical plain values. It must never treat a recognized protected
envelope as plain or fall back after any protected-envelope failure. A reader
that has no protection support refuses a recognized protected fingerprint as
`payload_envelope_unsupported`.

## Keys, retry and offload

Keys are exactly 32 bytes. A `key_id` is immutable: one active writer key may
be selected, old reader keys remain available for historical payloads, and an
ID cannot be reassigned or shadowed. Decryption selects the named key only; it
does not try every key.

New admission protects once. Automatic retries resend the exact protected
bytes, command/idempotency key and external-object reference. A retry that can
cross a process boundary therefore needs a persistable prepared request that
contains the operation, destination namespace, boundary kind, command key and
protected bytes or reference. It contains no credentials or key material.
Retry code must not regenerate a nonce or ciphertext.

Protection precedes the inline-size/offload decision. An external object is
the protected envelope bytes. A reader verifies the object's declared
size/hash before decrypting it.

## Initial call-site scope

[`call-sites-v1.json`](call-sites-v1.json) is the source-mapped inventory.
The supported rows are workflow input/result, ordinary durable activity
input/result, signal input, update input/result, query input/result and
side-effect results. Heartbeats, streams, Nexus, local/prepared activities,
unmapped external tasks, failure details and raw JSON/binary paths are
unsupported in v1. When protection is enabled, those paths refuse instead of
leaking plaintext.

| Call site | v1 disposition | AAD boundary | Required behavior |
| --- | --- | --- | --- |
| Workflow input, scheduled input, child input, continue-as-new | Protected | `workflow_input` | Protect at original admission; reuse exact bytes on retries/redrives. |
| Workflow result | Protected | `workflow_result` | Protect the completion value before persistence or offload. |
| Ordinary durable activity input | Protected | `activity_input` | Protect the scheduled arguments; local/prepared variants are not implied. |
| Ordinary durable activity result | Protected | `activity_result` | Protect the completion value before history persistence. |
| Signal input | Protected | `signal_input` | Bind to the target workflow namespace. |
| Update input | Protected | `update_input` | Protect once at update admission. |
| Update result | Protected | `update_result` | Preserve the same envelope for completion wait and later outcome reads. |
| Query input | Protected | `query_input` | Bind request and worker task to the target namespace. |
| Query result | Protected | `query_result` | Protect the worker result before returning or caching it. |
| Side-effect result | Protected | `side_effect_result` | Persist and replay the original envelope unchanged. |
| External object for a supported row | Protected | Inherited | Protect first; offload the complete envelope and verify size/hash before decrypt. |
| Activity heartbeat details | Refuse | — | Raw JSON has no v1 portable protected envelope. |
| Workflow message stream item | Refuse | — | Streaming framing and replay semantics are not specified. |
| Nexus request or result | Refuse | — | Caller/target namespace binding is not specified. |
| Local or prepared activity payload | Refuse | — | No protection until every persistence/retry path uses the portable envelope. |
| External task payload outside ordinary activity | Refuse | — | Do not infer the ordinary activity boundary without exact protocol proof. |
| Failure details | Refuse | — | Do not partially encrypt ad hoc detail fields; failure diagnostics remain metadata. |
| Raw JSON or generic binary payload | Refuse | — | Never wrap an untyped transport body as a protected `Value`. |

Identifiers, names, queues, namespaces, search/memo/visibility data, failure
messages/stacks/types, deadlines, policies and statuses remain plaintext
protocol metadata. This is intentional and must not be described as full
record encryption.

## Vector

[`vectors-v1.json`](vectors-v1.json) contains the canonical Unicode and integer
boundary vector, exact AAD and inner bytes, deterministic ciphertext, complete
outer Avro object, external-object hash and required negative cases. The fixed
key and nonce are test data only and must never be used outside conformance
tests.

The contract originates from the accepted decisions in
[durable-workflow/.github#217](https://github.com/durable-workflow/.github/issues/217).
