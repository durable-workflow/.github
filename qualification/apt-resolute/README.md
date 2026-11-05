# Fixed Resolute APT package proposal

These are public Ubuntu packages retained as source inputs for review. No CI job
installs them and no installation was performed during preparation. They do not
make the current red hosted contexts pass.

The existing official Ubuntu archive keyring independently verified the retained
InRelease signature with primary fingerprint
F6ECB3762474EDA9D21B7022871920D1991BC93C. Its SHA256 table binds the retained
Packages.xz by size and SHA256. Those exact package paragraphs bind both DEBs by
package, version, architecture, size and SHA256. Provenance records the original
URLs and all identities. Stock dpkg-deb readback independently reports apt and
libapt-pkg7.0 version3.2.1ubuntu0.1, amd64. No package was unpacked or executed.

The intended narrow future effect is an offline installation of exactly these
two packages on a disposable Ubuntu26.04/amd64 GitHub runner whose installed
apt/libapt pair is the observed3.2.0. It must capture and hash the reviewed bytes,
transfer only those bytes into a fresh root-owned private directory, recheck them
there, and invoke stock dpkg with network disabled. No APT download, repair,
fallback, repository/key installation or shared-host update is proposed. Missing
dependencies or partial installation must fail the job and retain its outcome;
the dedicated VM lifetime remains the partial-state cleanup boundary. Re-run
the read-only fixed-version check before any subsequent networked APT operation.

`scripts/bootstrap_fixed_apt.py` supplies the unexecuted bootstrap proposal.
Its default/`--plan` mode only captures and verifies these inputs. No workflow
calls `--install`. The proposed install mode accepts only the reviewed hosted
Ubuntu26.04/amd64 subject and observed apt/libapt3.2.0 pair. It sends captured
bytes over stdin to stock root commands and rehashes root-owned copies. It
captures the exact hash-bound `fixed_apt_transaction.py` bytes and sends them to
absolute isolated root Python, without reopening checkout source as root.

The unwired transaction takes the stock POSIX frontend lock for its full
lifetime. It refuses an active package manager or contended direct-dpkg lock.
It creates no-replace runtime masks for both APT services before masking and
stopping their timers, then verifies the exact mask identities and effective
inactive states. It does not stop or kill a running package service. It checks
the clean database and exact affected pair before stock dpkg's dependency dry
run and two-package install, each in a network namespace. Stock dpkg retains
its own database locking; the documented `DPKG_FRONTEND_LOCKED=1` tells it that
the parent already holds the frontend lock.

Success requires both packages in the exact clean installed state, package-file
verification, the absolute client version, and intact effective masks. The
runtime masks remain until the disposable VM ends, including on failure. There
is no unmask, restore, retry or shared-host mode. Only the staged two files and
private directory are removed. Partial package state remains a failed disposable
VM. Inert tests exercise actual kernel lock contention and fixture mask creation;
every systemd, root, package and install command is mocked.

The transaction correction needs fresh source review. The separate installation
effect decision remains pending. The setup-php transitive installer/archive finding #297 also remains
open; these packages cannot qualify that unrelated executable supply chain.

Public source advisories:

- https://ubuntu.com/security/CVE-2026-109518
- https://ubuntu.com/security/notices/USN-8996-1
- https://manpages.debian.org/testing/dpkg/dpkg.1.en.html
