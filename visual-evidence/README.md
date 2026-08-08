# Rendered visual evidence policy

The organization policy classifies customer-facing stylesheet and template
changes that touch search or navigation selectors. Those changes require
desktop, intermediate, and mobile captures of the corresponding open
interaction state. A default-page capture does not satisfy an interaction
requirement.

Classify a checkout relative to a base revision:

```console
python scripts/visual_evidence.py classify --root ../sdk-python --base-ref main
```

Validate the resulting requirements against a visual capture manifest:

```console
python scripts/visual_evidence.py validate \
  --root ../sdk-python \
  --base-ref main \
  --manifest visual-review/manifest.json
```

Validation also requires a meaningful click selector, an HTTP 200 capture,
the referenced screenshot and report, and a healthy capture report. The
machine-owned report requirements in `policy.json` reject horizontal overflow,
clipped text, clipped control text, oversized native choice controls, browser
request, HTTP, console, or page errors, and non-empty
`geometry.unreachable_controls` findings.

The `rust-sdk-reference` profile treats the Rust reference's HTML templates
and browser runtime as visual inputs while leaving Rust source, API prose, and
Markdown on the lightweight documentation path. Visual changes require exact
1440x900, 800x900, 390x844, and compact-height 640x360 captures proving the
analytics interface is absent and page controls remain reachable. The
manifest, every capture entry, and every report must bind to the same expected
`durable-workflow/sdk-rust` commit.

## Shared capture runtime

`scripts/pipeline_visual_capture.mjs` is the canonical source for the shared
`pipeline-visual-capture` command. `npm ci` installs an integrity-locked browser
driver and Linux Chromium payload with exact package identities. CI extracts
that payload under a run-specific job temporary directory; pull-request code
does not receive a writable shared browser or package cache, and browser setup
does not require privileged OS-package installation. A configured system
browser remains available for the installed worker command, but a missing
configured browser fails with a sanitized error before capture.

The capture scans every visible, enabled input, select, textarea, button, link,
summary, and explicit interactive ARIA role. It samples the control's visible
line fragments, clipped to the viewport and clipping ancestors, with both
`elementFromPoint` and `elementsFromPoint`. A control is reported when less
than half its sampled fragment area is reachable or a fragment center is
blocked. Associated labels and descendants count as legitimate hit targets,
which covers native choices, nested icon/text content, and intentional child
overlays. Sampling only rendered fragments keeps wrapped inline controls and
partially visible controls valid when their usable area is reachable.

Click-driven captures wait for resulting document navigation, network idle,
font readiness, and a bounded one-second stable layout window before collecting
geometry or taking the screenshot. This prevents a reloading or transitioning
page from being recorded as its final interaction state.

Every Chromium request is intercepted before it leaves the browser. Chromium
disables non-proxied WebRTC UDP and is forced through a loopback policy proxy
so transports outside the HTTP and WebSocket routing hooks cannot connect
directly. Page and worker WebTransport constructors are guarded before native
connection setup. WebRTC peer connections are rejected before ICE gathering
because ICE, STUN, and TURN direct transports cannot satisfy the HTTP(S)
capture-origin and scoped public-dependency allowlist. The worker guard applies
to dedicated workers, shared workers, and recursively nested worker realms.
Loopback previews may use only the exact origin passed to `--url`, including
its scheme and port. Public
captures follow the same exact-origin rule. The only cross-origin rendering
dependencies are a `GET` fetch for repository facts from the exact repository
path associated with the main site or the PHP, Python, and Rust SDK hostname,
the status page's exact Google Font stylesheet query and font files, and the
Python reference's exact default Material font stylesheet query and font files.
Those exceptions are limited by capture host, HTTPS origin, request type,
method, and path. Other redirects, navigations,
frames, resources, browser API requests, and persistent connections fail the
capture before a screenshot, report, or manifest is written. URL credentials,
authorization headers, non-HTTP(S) protocols, and unapproved loopback, private,
link-local, or external destinations are rejected with a bounded diagnostic
that does not include the destination URL. The sole protocol exception is an
exact-origin `ws:` or `wss:` connection corresponding to an HTTP or HTTPS
capture origin, which keeps loopback preview live-reload connections usable
while blocking cross-origin handshakes.

The merge-gate and audit prompt contracts are recorded in the policy's
`review_contract`. Both must name and inspect
`geometry.unreachable_controls`, and both must correlate report geometry with
the screenshot instead of treating either artifact as sufficient by itself.
