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
the referenced screenshot and report, and a report with no horizontal
overflow.
