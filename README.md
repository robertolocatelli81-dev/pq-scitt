# pq-scitt

A small Python library and command line for **checking evidence logs offline** and exporting them as IETF SCITT
Transparent Statements, with post-quantum options (ML-DSA-65 signatures, SLH-DSA anchors):

- `pq_scitt.strict_json`: a strict JSON reader. Duplicate member names, NaN/Infinity, numbers that overflow to
  infinity, a BOM, lone surrogates, invalid UTF-8 and nesting deeper than 128 are refused with a named reason.
- `pq_scitt.ledger.verify` (`pq-scitt verify-ledger`): verifies a hash-chained JSONL ledger (`self_hash` = SHA-256 or
  SHA3-256 of the canonical JSON of the entry, `prev_hash` = the previous `self_hash`) and prints a JSON receipt.
  Optional out-of-band anchors: expected entry count, expected tip, HMAC of the tip, signed checkpoint.
- `pq_scitt.ledger.standalone` (`pq-scitt verify-ledger-standalone`): a ledger verifier that needs only the Python
  standard library (from cryptovalid-opencore, same author).
- `pq_scitt.scitt.export`, `pq_scitt.scitt.verify`, `pq_scitt.scitt.cbor` (`pq-scitt export`, `pq-scitt verify`):
  export such a ledger as IETF SCITT Transparent Statements (COSE_Sign1, RFC 9943) with RFC 9162 Merkle inclusion
  proofs in the receipts (RFC 9942), and verify an export with a closed verifier. Algorithms: Ed25519 (-19, RFC 9864),
  EdDSA (-8, interop mode), ML-DSA-65 (-49, RFC 9964). Profile 2 adds a signed issue time, key validity windows,
  revoked key ids, per-entry salted commitments and RFC 9162 consistency proofs between two exports.
- `pq_scitt.ed25519_keys`, `pq_scitt.ed25519_order`: refuse Ed25519 public keys and signature R values of small
  order, keys outside the prime-order subgroup and non-canonical encodings (RFC 8032 §5.1.3), before the signature
  equation is checked.
- `pq_scitt.anchors.slh_dsa` (`pq-scitt anchor-selftest`): long-term anchors of a hash with SLH-DSA (FIPS 205, pure
  mode, empty context).
- `pq_scitt.kms` (`pq-scitt kms`): signing backends where the private key stays in a PKCS#11 HSM, AWS KMS, HashiCorp
  Vault Transit or a NetHSM; backend URIs have a closed form (an unknown or repeated key is an error).

Comments, docstrings and messages are in English. Some **stable identifiers are Italian words** and stay as they are,
because they are part of the API or of the formats: reason codes (for example `kid_ignoto` = unknown kid,
`firma_receipt_non_valida` = invalid receipt signature, `catena_riga_non_valida` = invalid chain row), command-line
options and values (`--nome` name, `--effimere` ephemeral keys, `--revocata` revoked kid, `--payload chiaro|riservato`
clear|reserved), JSON keys of the manifest and of the policy (`chiavi_pubbliche_da_confrontare_fuori_banda` = public
keys to compare out of band, `valida_dal`/`valida_fino` = valid from/until), the policy rule text signed into leaf 0,
the `non verificato:` (not verified) marker in `sig_verified` and the `key_source` values of `pq-scitt verify-ledger`.
Format identifiers keep their names (`omega-scitt/1`, `omega-scitt/2`, `application/vnd.omega.*`,
`omega-slhdsa-anchor-v2`): changing any of these would change the format or break callers.

## Status

- **First release**: version 0.1.0, not yet published on PyPI. Extracted on 2026-11-08 from a larger private code base
  by the same author.
- **One maintainer** (Roberto Locatelli). No independent review outside the author's own process yet.
- **Tests**, measured on 2026-11-08 on Linux x86-64 in clean virtual environments, against the **installed wheel**
  (dependencies from `requirements/ci.txt`): Python 3.10.22, 3.11.2, 3.12.15, 3.13.15 and 3.14.8, each 243 unittest
  tests run, 0 failed, 1 skipped, plus `test_verify_ledger.py` 3/3. Same result on 3.12 from the unpacked sdist.
  The skip: one SLH-DSA test needs `liboqs-python`. SoftHSM2, `pkcs11-tool` and podman with the Vault image were
  installed, so the 21 real-backend tests in `tests/test_kms_reali.py` ran; without them those 21 skip (measured on
  3.12: 243 run, 0 failed, 22 skipped). On the public CI (GitHub Actions `ubuntu-24.04`, no SoftHSM2 or podman) the
  result is 243 run, 0 failed, 22 skipped on Python 3.10 to 3.14 (first CI run, 8 November 2026). The tests of the `chain` event format use
  events produced by the original implementation of that format, frozen in `tests/data/chain_events.json`.
- **Conformance measurements** that can be repeated from this repository (run from `tests/`, package installed):

| What | Measured on 2026-11-08 | Command |
|---|---|---|
| SLH-DSA (FIPS 205) against NIST ACVP: 2 SLH-DSA-SHA2-128f sigGen vectors from usnistgov/ACVP-Server (1 external/pure, 1 internal), see `NOTICE` | pure: the anchor signature is byte-identical to the vector and verifies, the Bare interface refuses it; internal: verifies only as a legacy v1 anchor | `python -m unittest test_anchor_slhdsa_fips205` (needs `slh-dsa`) |
| Ed25519 against Wycheproof `ed25519_test.json` (210 cases) | 117/117 valid accepted, 64/64 invalid refused, 29/29 «acceptable» (small- or mixed-order keys) refused by the key check; the `cryptography` library alone accepts those 29 | `python -m unittest test_wycheproof_ed25519` |
| RFC 9162 Merkle tree roots for 1 to 8 leaves, transparency-dev/merkle vectors | equal | `python -m unittest test_scitt.TestRoundTrip.test_vettori_rfc6962` |
| AWS SigV4 signing key, AWS's published test vector | equal | `python -m unittest test_kms_http` |

  Only two ACVP vectors and one parameter set are in the repository: this is a check of the signing interface, not
  a validation of the SLH-DSA implementation (that comes from the `slh-dsa` or `liboqs` package). ML-DSA-65 signing and
  verification come from `cryptography`; this repository does not test them against ACVP vectors.

## Install

Python 3.10 or newer. From a clone:

```sh
python -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r requirements/ci.txt   # pinned, hash-checked dependencies
pip install --no-deps .
```

`pip install .` alone also works and resolves `cryptography>=50.0.1` (the only required dependency).
SLH-DSA anchors need the optional `slh-dsa` package (`pip install '.[slh]'`, LGPL-3.0-or-later) or `liboqs-python`.

## Example (5 commands)

`examples/ledger.jsonl` is a 3-entry ledger (`self_hash` = SHA-256 of the canonical JSON of the entry without
`self_hash`, `prev_hash` = the previous `self_hash`). From the root of a clone, with the package installed, this block
verifies the ledger, exports it as SCITT Transparent Statements with throw-away keys and verifies the export. It is
POSIX `sh` (no bash needed). `tests/test_readme_example.py` runs exactly this block with `sh`, and checks that
`examples/ledger.jsonl` is the ledger its own generator produces.

<!-- esempio:inizio -->
```sh
pq-scitt verify-ledger examples/ledger.jsonl
pq-scitt export examples/ledger.jsonl export --nome demo --payload chiaro --effimere
TS=$(sed 's/.*"ts":\[-19,"\([0-9a-f]*\)".*/\1/' export/manifest.json)
POL=$(sed 's/.*"politica":\[-19,"\([0-9a-f]*\)".*/\1/' export/manifest.json)
pq-scitt verify export --alg -19 --ts-pub "$TS" --politica-pub "$POL"
```
<!-- esempio:fine -->

Expected: a JSON receipt with `"verdict": "PASS"`, then `exported 4 Transparent Statements, root …` (3 entries plus
the registration policy as leaf 0) and `OK 4 leaves, root …`. The two `sed` lines read the transparency-service and
policy public keys from `export/manifest.json` (field `chiavi_pubbliche_da_confrontare_fuori_banda`).

In this example the public keys are read from the export itself, which proves nothing about who signed it. In real use
the verifier must get the transparency-service and policy keys **out of band** (the manifest field name says so).

## What it does not do

- It is not a transparency log service: no server, no API for third-party submissions, no witnesses, no gossip. The
  export is a folder of files produced by whoever holds the ledger.
- A bare hash chain is tamper-evident only against partial edits. Whoever holds the file can rewrite an entry and
  re-chain everything after it, or cut the tail; only out-of-band anchors (expected count, tip, HMAC, signed
  checkpoints, an independent log) detect that.
- Consistency between two exports is checked only if you keep the older export and run the consistency check. Two
  different extensions of the same export both pass that check against it (measured: 5 rows extended to 8 and to 9
  with different new rows, two different roots, both OK); only comparing the two extensions with each other shows the
  fork.
- The issue time `iat` of profile 2 is stated by the signer: whoever holds a key can date a signature anywhere inside
  that key's validity window (measured: an export dated 200 days back inside a 360-day window verifies).
- Revoked key ids written in a policy cover only the export that carries that policy, and the exporter refuses to sign
  with a key its own policy revokes. For exports already handed out, a revocation works only when the verifier is given
  the key id: `pq-scitt verify … --revocata KID` (then `chiave_revocata`).
- Payload `riservato`: in profile 2 each row becomes a commitment SHA-256(domain ‖ 32-byte salt ‖ row) and the salts
  stay with the exporter, outside the export. The confidentiality rests entirely on the salts staying secret: with the
  salt, a guessed row is confirmed. The number of rows and the `iat` values stay visible. In profile 1, `riservato`
  publishes `idx`, `prev_hash` and `self_hash`, so a guessed row of a predictable ledger is confirmed by its hash.
- It does not certify anything about the content of the entries, only their integrity and who signed the export.
- `pq_scitt/ed25519_order.py` is not constant time. That is not needed: its only inputs are public keys and signatures
  being verified (it is called by `pq_scitt.ed25519_keys`, used only to verify: by `pq-scitt verify`, and by
  `pq-scitt export --estendi`, which first verifies the previous export); signing goes through `cryptography` or a
  KMS/HSM backend and never passes a private key or another secret to it.
- Not tested in this repository: AWS KMS and NetHSM against real services (the AWS SigV4 signing key is checked against
  AWS's published test vector); YubiHSM hardware. `tests/test_kms_reali.py` runs SoftHSM2 and a Vault dev server only
  when `softhsm2`/`pkcs11-tool` and `podman` with the Vault image are installed, otherwise it skips.
- Interoperability, measured on 2026-11-08 outside this repository: an export of `examples/ledger.jsonl` with
  `--alg -8 --effimere` was verified with the independent Python library `scitt-cose` 0.5.0 (action-state-group):
  4/4 receipts (`verify_receipt`, same root as `manifest.json`) and 4/4 statement signatures
  (`parse_signed_statement`); a wrong log key, a leaf with one byte appended and a receipt signature with one bit
  flipped were refused (3/3). With `-19` (RFC 9864) that library reports `unsupported alg code point -19`, and its
  verifier has no ML-DSA (`-49`, RFC 9964). No interoperability test is in this repository yet.
- Signed chain tips in `verify-ledger-standalone` need `cryptovalid_tip` from cryptovalid-opencore, which is not
  included: with `--tip` and `--trusted-pubkey` the verdict is FAIL (`tip_unreadable`); with `--tip` alone the tip is
  not checked (`tip_untrusted`) and the verdict is the bare chain's, as in the original verifier.

## Tests

The tests import the **installed** package (the code is under `src/`, so the repository root does not shadow it):

```sh
pip install --require-hashes -r requirements/ci.txt && pip install --no-deps .
cd tests
python -m unittest test_verify_ledger_full test_scitt test_anchor_slhdsa_fips205 test_kms_reali test_kms_http \
    test_wycheproof_ed25519 test_cli test_readme_example test_strict_json
python test_verify_ledger.py
cd .. && python check_tree.py   # the repository holds only the files listed in FILE_LIST.tsv
python check_tree.py --update    # after changing or adding files: rewrites FILE_LIST.tsv, then runs the checks
```

## How it relates to other projects

These projects run transparency logs or ledgers as services. This library does not; it can sit next to them.

| Project | What it is (from its own repository) | Relation |
|---|---|---|
| [Sigstore Rekor v2 (rekor-tiles)](https://github.com/sigstore/rekor-tiles) | "Sigstore's signature transparency log", redesigned on a tile-backed transparency log | Rekor is a public log you submit signatures to. This library checks your own ledger and exports it; it does not submit to Rekor. |
| [Tessera](https://github.com/transparency-dev/tessera) | "Go library for building tile-based transparency logs" ([C2SP tlog-tiles](https://c2sp.org/tlog-tiles)) | Tessera builds and serves logs. The Merkle tree hash here is the RFC 9162 one, which tlog-tiles takes from RFC 6962 (the tests check the roots for 1 to 8 leaves against transparency-dev/merkle vectors); this library does not read or write the tlog-tiles format. |
| [CCF](https://github.com/microsoft/CCF) and [scitt-ccf-ledger](https://github.com/microsoft/scitt-ccf-ledger) | "framework for building … secure, highly available … applications"; a SCITT ledger application on CCF that "targets AMD SEV-SNP" | scitt-ccf-ledger is a service that accepts signed claims submitted by others and returns receipts, on a CCF network (Confidential Consortium Framework). Here one party exports its own ledger; there is no service, consortium, replication or TEE. |

Sources read on 2026-11-08: the README of each repository linked above.

## Contributing and security

See `CONTRIBUTING.md` and `SECURITY.md` (vulnerabilities: private report, not a public issue).

## License

Apache License 2.0, see `LICENSE` and `NOTICE`.
