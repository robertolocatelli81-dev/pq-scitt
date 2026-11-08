# Contributing

Issues and pull requests are welcome. Security problems: see `SECURITY.md` (private report).

## Rules of this repository

1. **Unknown input is refused with a named reason, and a test shows it.** What is refused today, and where:
   - `pq_scitt.strict_json`: repeated member names, NaN/Infinity, numbers that overflow to infinity, a BOM, lone
     surrogates, invalid UTF-8, nesting deeper than 128 (`test_strict_json`, including 4000 random byte mutations
     that may end only in a named refusal);
   - `pq-scitt verify`: unknown labels in the protected and unprotected COSE headers of statements and receipts, extra
     receipts, unknown or missing fields in the registration policy, a `sub` outside the profile
     (`test_scitt.TestControlloPositivo.test_etichette_ignote`, `…test_header_protetto_ignoto_firmato_davvero`,
     `test_scitt.TestPrivacyRiservato.test_politica_forma_chiusa`, `…test_sub_chiuso_nel_verificatore`,
     `test_scitt.TestRotazioneChiavi.test_politica_v2_forma_chiusa`); more than 20 000 structural and byte mutations
     of valid Transparent Statements, none accepted (`test_scitt.TestGenerativi.test_mutanti_rifiutati`, with a
     positive control that a verifier skipping the inclusion proof is caught);
   - `pq_scitt.kms` backend URIs: an unknown or repeated key, an empty value, an empty segment or a segment without
     `=` (400 random URIs, `test_kms_reali.TestUriChiuso.test_generativo`).
   These tests cover the cases listed; they are not a proof about every possible input. A new format or check comes
   with the same kind of test. Where a standard says what to do with unknown input (for example RFC 7519 §4 for
   unknown JWT claims), the standard is followed and the behaviour is documented.
2. **Tests first fail, then pass.** A fix comes with a test that fails on the old code. A new check comes with a
   positive control: an input it must refuse.
3. **Only measured sentences** in README, docstrings and commit messages. If a number is quoted, say how it was
   measured and on what date.
4. **The file list is closed.** `FILE_LIST.tsv` lists every file with its sha256; `python check_tree.py`
   fails on any file not listed, any import outside the standard library, the listed modules and a closed set of
   third-party packages (`cryptography`, `slh-dsa`, `liboqs-python`, `boto3`), and any secret found by gitleaks. A pull
   request that changes or adds a file updates the list with `python check_tree.py --update` (see below) and commits
   the new `FILE_LIST.tsv`; the diff of that file shows every change for review.

## Running the checks

```sh
python -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r requirements/ci.txt && pip install --no-deps .
cd tests
python -m unittest test_verify_ledger_full test_scitt test_anchor_slhdsa_fips205 test_kms_reali test_kms_http \
    test_wycheproof_ed25519 test_cli test_readme_example test_strict_json
python test_verify_ledger.py && cd ..
git add -A                      # check_tree.py lists files with git (tracked + untracked, .gitignore respected)
python check_tree.py --update   # rewrites FILE_LIST.tsv (new sha256, new files as "new", removed files dropped),
                                # prints each change, then runs all checks; needs gitleaks on PATH
python check_tree.py --positive-control
```

Install with `pip install .` (not `-e`) before running the tests, so they exercise the installed package.

## Measured

See the «Status» section of `README.md`.

## License of contributions

By contributing you agree that your contribution is licensed under the Apache License 2.0 (see `LICENSE`).
