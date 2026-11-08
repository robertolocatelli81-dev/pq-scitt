#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pq-scitt · tests/test_verify_ledger_full.py
===========================================
COMPLETE unittest suite for pq_scitt/ledger/verify.py (auditor-grade ledger verifier).

Covers all branches: algorithm auto-detect, full generic recompute, linkage
verification for module-specific schemes, standard path with `idx`, missing file,
malformed JSON, idx monotonicity, and the main() entrypoint (--quiet / --out / exit code).

REAL checks: hash chain rebuilt by hand with hashlib.sha256/sha3_256, so the
asserts compare against real invariants (no mock of the hash computation).

Official run: python3 -m unittest tests.test_verify_ledger_full
"""

import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest

# sys.path: original lines; the module comes from the installed pq_scitt package
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (_ROOT, os.path.join(_ROOT, "core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from pq_scitt.ledger.verify import (  # noqa: E402
    GENESIS_PREV,
    SUPPORTED_ALGOS,
    canonical_payload,
    detect_algo,
    hash_with,
    _generic_recompute_verify,
    _linkage_verify,
    verify_ledger,
    main,
)


# ─────────────────────────── construction helpers ───────────────────────────

def _sealed_idx_entry(idx, data, prev_hash, algo="sha256"):
    """PersistentLedger schema entry: {idx, ts, data, prev_hash, self_hash}."""
    entry = {"idx": idx, "ts": f"2026-06-18T00:00:0{idx}Z", "data": data, "prev_hash": prev_hash}
    entry["self_hash"] = hash_with(algo, canonical_payload(entry))
    return entry


def _native_entry(data, prev_hash, algo="sha256", sign=False):
    """NATIVE schema entry (no idx): {data, prev_hash, [signature], hash}.
    hash = ALGO(canonical(entry without 'hash')) — recomputable by the generic rule."""
    entry = {"data": data, "prev_hash": prev_hash}
    if sign:
        entry["signature"] = "ZmFrZS1zaWc="  # fake signature (in the hashed body)
    payload = json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str).encode()
    entry["hash"] = hash_with(algo, payload)
    return entry


def _write_ledger(entries):
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    with os.fdopen(fd, "w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")
    return path


def _write_raw(lines):
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    with os.fdopen(fd, "w") as f:
        for ln in lines:
            f.write(ln + "\n")
    return path


class _TmpMixin(unittest.TestCase):
    def setUp(self):
        self._paths = []

    def tearDown(self):
        for p in self._paths:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(p)

    def ledger(self, entries):
        p = _write_ledger(entries)
        self._paths.append(p)
        return p

    def raw(self, lines):
        p = _write_raw(lines)
        self._paths.append(p)
        return p


# ─────────────────────────── hashing primitives ───────────────────────────

class TestHashPrimitives(unittest.TestCase):
    def test_hash_with_sha256_matches_hashlib(self):
        payload = b"omega"
        self.assertEqual(hash_with("sha256", payload), hashlib.sha256(payload).hexdigest())

    def test_hash_with_sha3_256_matches_hashlib(self):
        payload = b"omega"
        self.assertEqual(hash_with("sha3_256", payload), hashlib.sha3_256(payload).hexdigest())

    def test_hash_with_unsupported_raises(self):
        with self.assertRaises(ValueError):
            hash_with("md5", b"x")

    def test_canonical_payload_excludes_self_hash(self):
        e = {"idx": 0, "self_hash": "deadbeef", "data": {"a": 1}}
        payload = canonical_payload(e)
        self.assertNotIn(b"self_hash", payload)
        self.assertIn(b"data", payload)


# ─────────────────────────── detect_algo ───────────────────────────

class TestDetectAlgo(unittest.TestCase):
    def test_detect_empty_returns_none(self):
        self.assertIsNone(detect_algo([]))

    def test_detect_missing_self_hash_returns_none(self):
        self.assertIsNone(detect_algo([{"idx": 0, "data": {}}]))

    def test_detect_sha256(self):
        e0 = _sealed_idx_entry(0, {"v": "g"}, GENESIS_PREV, algo="sha256")
        self.assertEqual(detect_algo([e0]), "sha256")

    def test_detect_sha3_256(self):
        e0 = _sealed_idx_entry(0, {"v": "g"}, GENESIS_PREV, algo="sha3_256")
        self.assertEqual(detect_algo([e0]), "sha3_256")

    def test_detect_no_match_returns_none(self):
        e0 = _sealed_idx_entry(0, {"v": "g"}, GENESIS_PREV, algo="sha256")
        e0["self_hash"] = "0" * 64  # hash not recomputable with any supported algo
        self.assertIsNone(detect_algo([e0]))


# ─────────────────────────── verify_ledger: path standard (idx) ───────────────────────────

class TestVerifyStandardIdx(_TmpMixin):
    def test_valid_chain_passes(self):
        e0 = _sealed_idx_entry(0, {"v": "genesis"}, GENESIS_PREV)
        e1 = _sealed_idx_entry(1, {"v": "second"}, e0["self_hash"])
        r = verify_ledger(self.ledger([e0, e1]))
        self.assertEqual(r["verdict"], "PASS")
        self.assertTrue(r["chain_integrity"])
        self.assertEqual(r["entries_count"], 2)
        self.assertIn("receipt_sha256", r)
        self.assertIn("receipt_sha3_256", r)

    def test_forced_algo_sha3_bypasses_native(self):
        e0 = _sealed_idx_entry(0, {"v": "g"}, GENESIS_PREV, algo="sha3_256")
        e1 = _sealed_idx_entry(1, {"v": "s"}, e0["self_hash"], algo="sha3_256")
        r = verify_ledger(self.ledger([e0, e1]), algo="sha3_256")
        self.assertEqual(r["verdict"], "PASS")
        self.assertEqual(r["algorithm_used"], "sha3_256")

    def test_missing_self_hash_fails_gracefully(self):
        e0 = _sealed_idx_entry(0, {"v": "genesis"}, GENESIS_PREV)
        e1 = _sealed_idx_entry(1, {"v": "second"}, e0["self_hash"])
        del e0["self_hash"]
        r = verify_ledger(self.ledger([e0, e1]))
        self.assertEqual(r["verdict"], "FAIL")
        self.assertTrue(any(f.get("reason") == "missing_self_hash" for f in r["hash_failures"]))
        self.assertFalse(r["link_passed"])

    def test_broken_linkage_detected(self):
        e0 = _sealed_idx_entry(0, {"v": "genesis"}, GENESIS_PREV)
        e1 = _sealed_idx_entry(1, {"v": "second"}, e0["self_hash"])
        e1["prev_hash"] = "f" * 64
        r = verify_ledger(self.ledger([e0, e1]))
        self.assertEqual(r["verdict"], "FAIL")
        self.assertFalse(r["link_passed"])

    def test_hash_mismatch_detected(self):
        e0 = _sealed_idx_entry(0, {"v": "genesis"}, GENESIS_PREV)
        e0["data"] = {"v": "tampered"}  # change the data WITHOUT updating self_hash
        r = verify_ledger(self.ledger([e0]))
        self.assertEqual(r["verdict"], "FAIL")
        self.assertFalse(r["hash_recompute_passed"])
        self.assertTrue(any(f.get("reason") == "hash_mismatch" for f in r["hash_failures"]))

    def test_idx_non_monotonic_detected(self):
        e0 = _sealed_idx_entry(0, {"v": "g"}, GENESIS_PREV)
        e1 = _sealed_idx_entry(1, {"v": "s"}, e0["self_hash"])
        e1["idx"] = 5  # breaks monotonicity (and the self_hash → hash_mismatch)
        e1["self_hash"] = hash_with("sha256", canonical_payload(e1))
        r = verify_ledger(self.ledger([e0, e1]))
        self.assertFalse(r["idx_monotonic"])
        self.assertEqual(r["verdict"], "FAIL")

    def test_json_decode_error_recorded(self):
        e0 = _sealed_idx_entry(0, {"v": "g"}, GENESIS_PREV)
        # malformed line + a valid one with idx (to stay on the standard path)
        path = self.raw(["{ this is not json ]", json.dumps(e0)])
        r = verify_ledger(path)
        self.assertTrue(r["parse_errors"])
        self.assertTrue(any("json_decode" in pe.get("error", "") for pe in r["parse_errors"]))

    def test_file_not_found(self):
        r = verify_ledger("/nonexistent/omega/ledger_xyz.jsonl")
        self.assertEqual(r["verdict"], "FILE_NOT_FOUND")

    def test_empty_file_is_not_pass(self):
        # file with only empty lines: like a missing one, EMPTY and no longer "vacuous PASS" (review 08/11)
        path = self.raw(["", "   "])
        r = verify_ledger(path)
        self.assertEqual(r["entries_count"], 0)
        self.assertEqual(r["verdict"], "EMPTY")


# ─────────────────────────── verify_ledger: NATIVE schema (no idx) ───────────────────────────

class TestVerifyNativeGeneric(_TmpMixin):
    def _native_chain(self, n, algo="sha256", sign=False):
        entries = []
        prev = GENESIS_PREV
        for i in range(n):
            e = _native_entry({"v": i}, prev, algo=algo, sign=sign)
            entries.append(e)
            prev = e["hash"]
        return entries

    def test_generic_full_recompute_pass(self):
        r = verify_ledger(self.ledger(self._native_chain(3)))
        self.assertEqual(r["mode"], "full_recompute_generic")
        self.assertEqual(r["verdict"], "PASS")
        self.assertTrue(r["hash_recompute_passed"])
        self.assertEqual(r["hash_key"], "hash")
        self.assertEqual(r["prev_key"], "prev_hash")
        self.assertIn("receipt_sha256", r)

    def test_generic_with_signature_field(self):
        # with signature in the hashed body: the drop={hash} rule still recomposes
        r = verify_ledger(self.ledger(self._native_chain(3, sign=True)))
        self.assertEqual(r["mode"], "full_recompute_generic")
        self.assertEqual(r["verdict"], "PASS")

    def test_generic_sha3_algo(self):
        r = verify_ledger(self.ledger(self._native_chain(3, algo="sha3_256")))
        self.assertEqual(r["mode"], "full_recompute_generic")
        self.assertEqual(r["algorithm_used"], "sha3_256")
        self.assertEqual(r["verdict"], "PASS")

    def test_generic_hash_ok_but_linkage_broken(self):
        # rule detected and recompute OK on ALL entries, but the prev_hash of one entry
        # points to a wrong value (internally consistent with its own hash) →
        # covers the link_failures branch inside _generic_recompute_verify.
        chain = self._native_chain(3)
        chain[1]["prev_hash"] = "b" * 64  # broken link
        # recompute its hash so the entry stays hash-valid
        body = {k: v for k, v in chain[1].items() if k != "hash"}
        chain[1]["hash"] = hash_with("sha256", json.dumps(
            body, sort_keys=True, separators=(",", ":"), default=str).encode())
        chain[2]["prev_hash"] = chain[1]["hash"]
        body2 = {k: v for k, v in chain[2].items() if k != "hash"}
        chain[2]["hash"] = hash_with("sha256", json.dumps(
            body2, sort_keys=True, separators=(",", ":"), default=str).encode())
        r = verify_ledger(self.ledger(chain))
        self.assertEqual(r["mode"], "full_recompute_generic")
        self.assertTrue(r["hash_recompute_passed"])  # all hashes match
        self.assertFalse(r["chain_integrity"])        # but the chain is broken
        self.assertEqual(r["verdict"], "FAIL")
        self.assertIn(1, r["link_failures_idx"])

    def test_generic_tampered_hash_fails(self):
        # tampering of ONE entry under a detected rule → verdict FAIL (no false PASS)
        chain = self._native_chain(4)
        chain[2]["data"] = {"v": "TAMPERED"}  # hash no longer recomputes
        r = verify_ledger(self.ledger(chain))
        # the rule stays detectable by majority (3/4) → mode generic, but FAIL
        self.assertEqual(r["mode"], "full_recompute_generic")
        self.assertEqual(r["verdict"], "FAIL")
        self.assertFalse(r["hash_recompute_passed"])
        self.assertIn(2, r["hash_failures_idx"])


class TestVerifyNativeLinkage(_TmpMixin):
    def _opaque_linked_chain(self, n, break_link=False):
        """Chain with an OPAQUE hash (not recomputable by the generic rule) but consistent
        linkage: prev_hash == previous hash. → falls back to LINKAGE mode."""
        entries = []
        prev = GENESIS_PREV
        for i in range(n):
            # arbitrary hash, NOT a function of the content → generic does not recompose
            h = hashlib.sha256(f"opaque-secret-{i}".encode()).hexdigest()
            entries.append({"module_data": {"v": i}, "prev_hash": prev, "hash": h})
            prev = h
        if break_link and n >= 2:
            entries[1]["prev_hash"] = "e" * 64
        return entries

    def test_linkage_mode_linked(self):
        r = verify_ledger(self.ledger(self._opaque_linked_chain(3)))
        self.assertEqual(r["mode"], "linkage")
        self.assertEqual(r["verdict"], "LINKED")
        self.assertTrue(r["chain_linkage_integrity"])

    def test_linkage_mode_broken(self):
        r = verify_ledger(self.ledger(self._opaque_linked_chain(3, break_link=True)))
        self.assertEqual(r["mode"], "linkage")
        self.assertEqual(r["verdict"], "FAIL")
        self.assertFalse(r["chain_linkage_integrity"])
        self.assertTrue(r["link_failures"])

    def test_native_no_hash_keys_is_not_a_ledger(self):
        # entries without idx AND without ANY hash key → it is a DATASET, not a hash-chained ledger.
        # Fix 2026-08-18 (d065174): dedicated verdict NOT_A_LEDGER, NOT FAIL — a dataset is not a
        # tampered ledger, and must not be confused with a real broken ledger (that would dilute the real FAILs).
        # The test was aligned with this intended behaviour (before, it expected FAIL on the standard path).
        path = self.ledger([{"foo": 1}, {"bar": 2}])
        r = verify_ledger(path)
        self.assertEqual(r["verdict"], "NOT_A_LEDGER")
        self.assertEqual(r["mode"], "none")


# ─────────────────────────── direct internal functions (remaining branches) ───────────────────────────

class TestInternalBranches(unittest.TestCase):
    def test_generic_empty_returns_none(self):
        self.assertIsNone(_generic_recompute_verify([], "t", "p"))

    def test_generic_no_prev_or_hash_keys_returns_none(self):
        self.assertIsNone(_generic_recompute_verify([{"a": 1}], "t", "p"))

    def test_linkage_empty_returns_none(self):
        self.assertIsNone(_linkage_verify([], "t", "p"))

    def test_linkage_no_keys_returns_none(self):
        self.assertIsNone(_linkage_verify([{"a": 1}], "t", "p"))


# ─────────────────────────── main() / entrypoint ───────────────────────────

class TestMain(_TmpMixin):
    def _capture_main(self, argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(argv)
        return rc, buf.getvalue()

    def test_main_pass_returns_0(self):
        e0 = _sealed_idx_entry(0, {"v": "g"}, GENESIS_PREV)
        e1 = _sealed_idx_entry(1, {"v": "s"}, e0["self_hash"])
        rc, out = self._capture_main([self.ledger([e0, e1])])
        self.assertEqual(rc, 0)
        self.assertIn('"verdict"', out)

    def test_main_fail_returns_1(self):
        # linkage mode → verdict LINKED (not PASS) → main returns 1 (only PASS==0)
        chain = [{"d": {"v": i}, "prev_hash": GENESIS_PREV if i == 0 else "x", "hash": f"h{i}"}
                 for i in range(2)]
        rc, _ = self._capture_main([self.ledger(chain)])
        self.assertEqual(rc, 1)

    def test_main_quiet(self):
        e0 = _sealed_idx_entry(0, {"v": "g"}, GENESIS_PREV)
        rc, out = self._capture_main(["--quiet", self.ledger([e0])])
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "PASS")

    def test_main_out_writes_receipt(self):
        e0 = _sealed_idx_entry(0, {"v": "g"}, GENESIS_PREV)
        outfd, outpath = tempfile.mkstemp(suffix=".json")
        os.close(outfd)
        self._paths.append(outpath)
        rc, _ = self._capture_main(["--out", outpath, self.ledger([e0])])
        self.assertEqual(rc, 0)
        with open(outpath) as f:
            receipt = json.load(f)
        self.assertEqual(receipt["verdict"], "PASS")

    def test_main_file_not_found_returns_1(self):
        rc, out = self._capture_main(["/no/such/omega_ledger.jsonl"])
        self.assertEqual(rc, 1)
        self.assertIn("FILE_NOT_FOUND", out)


# ─────────────────────────── existing script-style run ───────────────────────────

class TestExistingScriptRuns(unittest.TestCase):
    """Runs tests/test_verify_ledger.py (script-style with sys.exit) in isolation and
    checks that its internal self-check passes (exit 0)."""

    def test_legacy_script_exits_zero(self):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_verify_ledger.py")
        g = {"__name__": "__main__", "__file__": path}
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            try:
                exec(compile(open(path).read(), path, "exec"), g)
                rc = 0
            except SystemExit as se:
                rc = se.code if se.code is not None else 0
        # check by IDENTITY: 0 == success (True==0 is False in Python, ok)
        self.assertEqual(rc, 0, "the self-check of the legacy script must pass")


if __name__ == "__main__":
    unittest.main(verbosity=2)
