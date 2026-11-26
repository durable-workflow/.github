"""Replay the shared replay-clock vectors through the installed Python SDK.

Reads vectors-v1.json from the path in argv[1] and prints one JSON object
mapping each case id to its observations. Times are UTC RFC 3339 with six
fractional digits and Z; an unavailable read is null.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any

from durable_workflow import ReplayClockUnavailable, workflow
from durable_workflow.testing import replay_history

VECTORS = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
SPEC = VECTORS["workflow"]


def _read(ctx: Any) -> str | None:
    try:
        value: datetime = ctx.replay_now()
    except ReplayClockUnavailable:
        return None
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@workflow.defn(name=SPEC["type"])
class ReplayClockConformance:
    def run(self, ctx: Any):  # type: ignore[no-untyped-def]
        entry = _read(ctx)
        repeated = _read(ctx) == entry
        yield ctx.schedule_activity(SPEC["activity_type"], [])
        after_activity = _read(ctx)
        yield ctx.start_timer(SPEC["timer_seconds"])
        after_timer = _read(ctx)
        return {"entry": entry, "repeated_reads_equal": repeated,
                "after_activity": after_activity, "after_timer": after_timer}


def _elapsed(start: str | None, end: str | None) -> int | None:
    if start is None or end is None:
        return None
    parse = lambda text: datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ")  # noqa: E731
    delta = parse(end) - parse(start)
    return delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds


observations: dict[str, Any] = {}
for case in VECTORS["cases"]:
    outcome = replay_history(
        ReplayClockConformance, VECTORS["history"], SPEC["input"], run_id=SPEC["run_id"],
        payload_codec=SPEC["payload_codec"], replay_clock_entry=case.get("replay_clock"),
    )
    try:
        commands = outcome.commands
        if len(commands) != 1 or type(commands[0]).__name__ != "CompleteWorkflow":
            raise SystemExit(f"{case['id']}: expected one CompleteWorkflow, got {commands!r}")
        result = dict(commands[0].result)
    finally:
        outcome.close()
    result["elapsed_microseconds"] = _elapsed(result["after_activity"], result["after_timer"])
    observations[case["id"]] = result

print(json.dumps({"binding": "python", "sdk_version": metadata.version("durable-workflow"),
                  "observations": observations}, sort_keys=True))
