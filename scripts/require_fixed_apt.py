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
LIBRARIES = {
    ("ubuntu", "22.04"): "libapt-pkg6.0",
    ("ubuntu", "24.04"): "libapt-pkg6.0t64",
    ("ubuntu", "26.04"): "libapt-pkg7.0",
    ("ubuntu", "26.10"): "libapt-pkg7.0",
    ("debian", "13"): "libapt-pkg7.0",
}
CLEAN_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


def require_fixed_apt(release, run=subprocess.run):
    subject = (release.get("ID"), release.get("VERSION_ID"))
    minimum = FIXED.get(subject)
    if minimum is None:
        raise ValueError("APT release has no reviewed fixed-version floor")
    library = LIBRARIES[subject]
    query = run(["/usr/bin/dpkg-query", "--show", "--showformat=${Package}\\t${Status}\\t${Version}\\n", "apt", library],
                env=CLEAN_ENV, capture_output=True, text=True, timeout=10, check=False)
    if query.returncode != 0:
        raise ValueError("Installed APT version query failed")
    versions = {}
    for line in query.stdout.splitlines():
        fields = line.split("\t")
        if (len(fields) != 3 or fields[0] not in {"apt", library} or fields[0] in versions
                or fields[1] != "install ok installed"
                or re.fullmatch(r"[0-9][0-9A-Za-z.+:~\-]{0,99}", fields[2]) is None):
            raise ValueError("Installed APT pair status/version is missing or ambiguous")
        versions[fields[0]] = fields[2]
    if set(versions) != {"apt", library}:
        raise ValueError("Installed APT pair is incomplete")
    for package, version in versions.items():
        comparison = run(["/usr/bin/dpkg", "--compare-versions", version, "ge", minimum],
                         env=CLEAN_ENV, capture_output=True, text=True, timeout=10, check=False)
        if comparison.returncode != 0:
            raise ValueError(f"{package} {version} does not prove the fixed {minimum} floor")
    return {"os": subject[0], "release": subject[1], "apt": versions["apt"],
            "libapt_package": library, "libapt": versions[library], "minimum": minimum,
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
