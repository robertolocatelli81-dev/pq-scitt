# Security policy

Please report vulnerabilities **privately**, not in a public issue or pull request:
use GitHub's "Report a vulnerability" button on the Security tab of this repository (private vulnerability reporting).

Useful in a report: the file and function, an input that shows the problem, what you expected and what happened,
and the commit you tested.

In scope: any input that a verifier in this repository accepts when it should refuse it (or the reverse), a crash or
hang on untrusted input, a key or signature check that can be bypassed, a secret written where it should not be.

There is no bug bounty.

Supported versions: the latest release (see `CHANGELOG.md`) and the latest commit of the default branch.

Platforms the CI tests (run 45352560170, 24 November 2026, all green): Linux (`ubuntu-24.04`) with Python 3.10 to
3.14, macOS (`macos-15`, arm64) and Windows (`windows-2025`) with Python 3.13, each with and without `slh-dsa`, with
real SoftHSM2 and OpenBao backends. Other systems are not tested.
