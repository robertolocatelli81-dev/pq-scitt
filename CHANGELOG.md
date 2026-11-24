# Changelog

## 0.1.1 (prepared on 2026-11-24, not yet tagged)

Defects of 0.1.0, all present since the initial import (4bf24e9), each with a test that fails on 0.1.0:

- A FIFO given as input blocked forever, `/dev/zero` was read whole (MemoryError traceback) and a directory was a
  traceback, in `pq-scitt verify-ledger` (ledger and `--checkpoint`), `verify-ledger-standalone`, `export`,
  `verify --registro` and `kms … --backend file:`. Inputs are now regular files only, opened without blocking, at most
  256 MiB (key files 64 KiB).
- `pq_scitt.strict_json`: the depth pre-scan was quadratic on an unterminated string (80 KB took 48 s on Python 3.12)
  and named the wrong reason (`troppo_profondo` instead of `non_json`).
- `pq-scitt verify-ledger`, generic mode (ledgers without `idx`): cutting the head of a ledger, with no hash recomputed,
  was PASS. Entry 0 must now start from the genesis.
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
- The `verifier` field of the `verify-ledger` and `verify-ledger-standalone` receipts names the installed version.

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
- `tests/test_kms_reali.py` runs in the CI: SoftHSM2 and OpenSC on Linux and macOS, OpenBao 2.7.3 (MPL-2.0, pinned by
  digest) in docker on Linux. HashiCorp Vault is BUSL-1.1 since 1.15 (its LICENSE, read on 2026-11-24): the tests use
  OpenBao, whose Transit API is the same (`PQ_VAULT_IMAGE` can still name a Vault image). `PQ_REQUIRE_KMS` turns a
  missing required service into a failure, with a positive control in the CI and in `TestRequisitoKms`.

## 0.1.0 (initial import 2026-11-08, GitHub release 2026-11-12)

First version: SCITT export and closed verifier (Ed25519, EdDSA, ML-DSA-65), strict JSON reader, Ed25519 key checks,
hash-chained ledger verifiers, SLH-DSA anchors, KMS/HSM signing backends. Commits 4bf24e9 and 9692a74.
