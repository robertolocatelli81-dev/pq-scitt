# Changelog

## 0.1.1 (2026-11-24)

Defects of 0.1.0, all present since the initial import (4bf24e9). Each fix has a test that fails on 0.1.0 on the
system where the defect shows (the Windows and macOS ones were seen in the CI of the `ci-prova-0.1.1` branch):

- A FIFO given as input blocked forever, `/dev/zero` was read whole (MemoryError traceback) and a directory was a
  traceback, in `pq-scitt verify-ledger` (ledger and `--checkpoint`), `verify-ledger-standalone`, `export`,
  `verify --registro` and `kms … --backend file:`. Inputs are now regular files only, opened without blocking, at most
  256 MiB (key files 64 KiB). The salts file (`verify --sali`, `export --sali-precedenti`) was already refused when
  not a regular file, but was read whole (a 5 GiB file was a MemoryError traceback): same bound now.
- `pq_scitt.strict_json`: the depth pre-scan was quadratic on an unterminated string (80 KB took 48 s on Python 3.12)
  and named the wrong reason (`troppo_profondo` instead of `non_json`).
- `pq-scitt verify-ledger`, generic mode (ledgers without `idx`): cutting the head of a ledger, with no hash recomputed,
  was PASS. Entry 0 must now start from the genesis (64 zeros) or have no `prev` key; a ledger without `idx` whose
  first entry names another genesis value is FAIL in this mode (it was PASS).
- `pq-scitt verify-ledger`: `idx` true or 1.0 was accepted as 1.
- `pq-scitt verify` and `export`: a refusal naming a non-UTF-8 path or argument raised UnicodeEncodeError in a UTF-8
  locale.
- `pq-scitt verify-ledger`: `--expect-hmac` with a non-ASCII character, `--hmac-key` given as non-UTF-8 bytes and an
  unwritable `--out` were tracebacks.
- `pq_scitt.kms`: a malformed NetHSM answer was a KeyError traceback.
- `pq-scitt export` on Windows (no `O_NOFOLLOW`, no `geteuid`): `file:` keys and the salts file were an AttributeError
  traceback. New `pq_scitt.filepriv`: the same rule with the Windows means (owner SID and DACL; no reparse point;
  the salts file is created with CreateFileW, CREATE_NEW and FILE_FLAG_OPEN_REPARSE_POINT, born with a protected
  DACL for the user only). Another system refuses with the reason. Found by the CI run 45341103851 before release:
  creating it with os.open(O_CREAT|O_EXCL) on Windows followed a dangling link at the salts path and created the
  link's target.
- Windows: a directory given as input was a PermissionError; now "not a regular file", as on POSIX. A device path
  (`\\.\pipe\…`) is refused by its name, never opened (opening would connect to a named pipe).
- `verify-ledger --out` writes the receipt as UTF-8 with LF on every system (Windows wrote CRLF).
- `.gitattributes`: no CRLF conversion on Windows checkouts (the tests pin the sha256 of `tests/data`; the CI run of the
  `ci-prova-0.1.1` branch showed a different hash of the Wycheproof file on Windows).
- `pq_scitt.kms`, PKCS#11: on Windows the ctypes structures had the default layout, while pkcs11.h packs them to 1
  byte there; now packed (the attribute checks start from refusing values, so a template read wrongly ended in a
  refusal, not in an accepted key). The public key was read with `pkcs11-tool --read-object --output-file`, which
  failed on Windows (a temporary file held open) and on macOS (Homebrew's OpenSC 0.27.1 refused the point stored by
  Homebrew's SoftHSM2 2.7.0); now it is read through the module (CKA_EC_POINT, closed: Ed25519 parameters, DER OCTET
  STRING or the 32 raw bytes of PKCS#11 3.1). The signature ran in a thread: at the time limit the caller stopped
  waiting, but a call hung in the module could not be stopped; now the public-key read and the signature run in a
  child process that is killed at the limit, on every system. The child does not import from the current directory
  (`python -c` would: a `json.py` there ran in the process that holds the PIN), answers on a private copy of standard
  output (a module that prints on standard output cannot enter the protocol), and an answer out of form stops it; a
  child that does not read its input is stopped at the limit too. On Windows, `PQ_PKCS11_DLL_DIRS` lists extra
  folders for the DLLs a module depends on.

Other changes:

- The `verifier` field of the `verify-ledger` and `verify-ledger-standalone` receipts names the installed version
  (0.1.1).

Texts corrected:

- The docstring of `anchors.slh_dsa.verify_anchor` said that a swapped backend fails: false for v2 anchors (`backend`
  is not signed), true for v1.
- README: EdDSA (-8) is Deprecated in the IANA COSE Algorithms registry (RFC 9864); the schema of `verify-ledger` is
  open; the CI result of 0.1.0 comes from the two CI runs on `main` of 8 November 2026.
- A commit message of 0.1.0 cannot be changed; corrected here. 9692a74, «README: CI result measured on the first run
  (243 run, 0 failed, 22 skipped on 3.10-3.14)»: the same result came from the two CI runs on `main`, on 4bf24e9 and on
  9692a74; the run of 9692a74 was the second, not the first. The two commits of 0.1.0 are not signed
  (`git log --format=%G?` = N); the commits of 0.1.1 are.
- NOTICE keeps the NIST notice of usnistgov/ACVP-Server intact, as it requires; SECURITY.md supported versions;
  CONTRIBUTING; `--help` of the two ledger verifiers.

Build and CI:

- `requirements/ci.txt`: cryptography 50.0.2 (regenerated from the PyPI JSON API on 2026-11-24, every published file);
  supersedes the Dependabot pull request #1, which could not pass `check_tree.py`.
- CI on every branch: Linux with Python 3.10 to 3.14, macOS and Windows with 3.13, each with and without `slh-dsa`; the
  log lists every skip with its reason, and a skip for a missing POSIX `sh` fails the job.
- `tests/test_kms_reali.py` runs in the CI on Linux, macOS and Windows: SoftHSM2 + OpenSC (Ubuntu packages pinned;
  Homebrew; on Windows SoftHSM2 built from the 2.7.0 commit with vcpkg OpenSSL and cached, and the OpenSC 0.27.1 MSI)
  and the official OpenBao 2.7.3 binary run natively (sha256 from its checksums.txt, whose GPG signature was checked on
  2026-11-24). HashiCorp Vault is BUSL-1.1 since 1.15 (its LICENSE, read on 2026-11-24): the tests use OpenBao, whose
  Transit API is the same. `PQ_REQUIRE_KMS` turns a missing required service into a failure, with a positive control
  in the CI and in `TestRequisitoKms`.

Measured: CI run 45369158453 (GitHub Actions, 24 November 2026, commit 61ab771, all 14 jobs green; numbers read from
each job's log with `gh run view --job <id> --log`), the suite of `tests/` against the installed package with
`PQ_REQUIRE_KMS=1` (SoftHSM2 + OpenSC and OpenBao 2.7.3 required, so their 21 tests in `tests/test_kms_reali.py` ran), plus
`test_verify_ledger.py` 3/3 in every job:

| Runner | Python | with `slh-dsa` | without `slh-dsa` |
|---|---|---|---|
| ubuntu-24.04 | 3.10.22, 3.11.18, 3.12.16, 3.13.18, 3.14.10 | 266 run, 0 failed, 1 skipped | 266 run, 0 failed, 12 skipped |
| macos-15 (arm64) | 3.13.17 | 266 run, 0 failed, 1 skipped | 266 run, 0 failed, 12 skipped |
| windows-2025 | 3.13.17 | 266 run, 0 failed, 2 skipped | 266 run, 0 failed, 13 skipped |

Skips, from the same logs: 1 everywhere, the interoperability test that needs `liboqs-python` (not installed);
11 more without `slh-dsa`, the tests that need it; 1 more on Windows, `test_descrittore_zero_chiuso_dopo_rifiuto`
(no equivalent: Windows has no FIFO inside a folder and does not open a directory as a file). Backends installed:
SoftHSM2 2.6.1-2.2ubuntu3 and OpenSC 0.25.0~rc1-1ubuntu0.2 (Ubuntu), SoftHSM2 2.7.0 and OpenSC 0.27.1 (Homebrew),
SoftHSM2 2.7.0 built from commit 13e6e86b and OpenSC 0.27.1 (Windows); OpenBao 2.7.3 on all three.

## 0.1.0 (initial import 2026-11-08, GitHub release 2026-11-12)

First version: SCITT export and closed verifier (Ed25519, EdDSA, ML-DSA-65), strict JSON reader, Ed25519 key checks,
hash-chained ledger verifiers, SLH-DSA anchors, KMS/HSM signing backends. Commits 4bf24e9 and 9692a74.
