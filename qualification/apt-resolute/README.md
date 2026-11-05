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
bytes over stdin to stock root commands, rehashes root-owned copies, performs
stock dpkg's dependency dry run and actual install in a network namespace, then
rechecks fixed APT. It removes only its two files and private directory; failed
partial installation remains a failed disposable VM, with no shared-host or
restoration claim. Inert tests mock every root/install command.

Executable-source review and the separate installation effect decision remain
pending. The setup-php transitive installer/archive finding #297 also remains
open; these packages cannot qualify that unrelated executable supply chain.

Public source advisories:

- https://ubuntu.com/security/CVE-2026-109518
- https://ubuntu.com/security/notices/USN-8996-1
