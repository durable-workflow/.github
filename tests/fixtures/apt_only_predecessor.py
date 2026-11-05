"""Refuse networked package setup unless the installed APT has the CVE fix."""

import json
import os
import platform
import re
import subprocess
import sys

FIXED = {
    ("ubuntu", "22.04"): "2.4.15ubuntu0.1",
    ("ubuntu", "24.04"): "2.8.4ubuntu0.1",
    ("ubuntu", "26.04"): "3.2.1ubuntu0.1",
    ("ubuntu", "26.10"): "3.3.3ubuntu0.1",
    ("debian", "13"): "3.0.4",
}
CLEAN_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


def require_fixed_apt(release, run=subprocess.run):
    subject = (release.get("ID"), release.get("VERSION_ID"))
    minimum = FIXED.get(subject)
    if minimum is None:
        raise ValueError("APT release has no reviewed fixed-version floor")
    query = run(["/usr/bin/dpkg-query", "--show", "--showformat=${db:Status-Status}\\t${Version}\\n", "apt"],
                env=CLEAN_ENV, capture_output=True, text=True, timeout=10, check=False)
    if query.returncode != 0:
        raise ValueError("Installed APT version query failed")
    fields = query.stdout.strip().split("\t")
    if len(fields) != 2 or fields[0] != "installed" or re.fullmatch(r"[0-9][0-9A-Za-z.+:~\-]{0,99}", fields[1]) is None:
        raise ValueError("Installed APT package/version is missing or ambiguous")
    version = fields[1]
    comparison = run(["/usr/bin/dpkg", "--compare-versions", version, "ge", minimum],
                     env=CLEAN_ENV, capture_output=True, text=True, timeout=10, check=False)
    if comparison.returncode != 0:
        raise ValueError(f"APT {version} does not prove the fixed {minimum} floor")
    return {"os": subject[0], "release": subject[1], "apt": version, "minimum": minimum,
            "fixed_apt": True}


def main():
    try:
        if sys.argv[1:]:
            raise ValueError("APT preflight accepts no version or release overrides")
        report = require_fixed_apt(platform.freedesktop_os_release())
        report.update(runner_image=os.environ.get("ImageOS", "unknown")[:200],
                      runner_version=os.environ.get("ImageVersion", "unknown")[:200])
        print(json.dumps(report, sort_keys=True))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({"fixed_apt": False, "refusal": str(error)[:500]}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
