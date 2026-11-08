#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pq-scitt · tests/test_verify_ledger.py
======================================
Targeted tests for pq_scitt/ledger/verify.py (the auditor-grade ledger verifier).

Covers in particular robustness on MALFORMED ledgers: the verifier must
return a structured FAIL receipt, never raise an unhandled exception.

Exit 0 = everything passes. Exit 1 = failures.
"""

import hashlib
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "core"))

from pq_scitt.ledger.verify import verify_ledger, canonical_payload, GENESIS_PREV

PASS = FAIL = 0


def ok(msg):
    global PASS
    PASS += 1
    print(f"  \033[32m✓\033[0m {msg}")


def fail(msg):
    global FAIL
    FAIL += 1
    print(f"  \033[31m✗\033[0m {msg}", file=sys.stderr)


def _sealed_entry(idx, data, prev_hash):
    """Builds a valid entry with a consistent SHA-256 self_hash (like the real ledger)."""
    entry = {"idx": idx, "ts": f"2026-06-18T00:00:0{idx}Z", "data": data, "prev_hash": prev_hash}
    entry["self_hash"] = hashlib.sha256(canonical_payload(entry)).hexdigest()
    return entry


def _write_ledger(entries):
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    with os.fdopen(fd, "w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")
    return path


def test_valid_chain_passes():
    e0 = _sealed_entry(0, {"v": "genesis"}, GENESIS_PREV)
    e1 = _sealed_entry(1, {"v": "second"}, e0["self_hash"])
    path = _write_ledger([e0, e1])
    try:
        receipt = verify_ledger(path)
    finally:
        os.unlink(path)
    assert receipt["verdict"] == "PASS", receipt
    assert receipt["chain_integrity"] is True
    assert receipt["entries_count"] == 2
    ok("Valid 2-entry chain → PASS, integrity confirmed")


def test_missing_self_hash_does_not_crash():
    """Regression: an entry without self_hash must give FAIL, not KeyError."""
    e0 = _sealed_entry(0, {"v": "genesis"}, GENESIS_PREV)
    e1 = _sealed_entry(1, {"v": "second"}, e0["self_hash"])
    # Tampering: remove self_hash from entry 0 (the previous one in the linkage check).
    del e0["self_hash"]
    path = _write_ledger([e0, e1])
    try:
        receipt = verify_ledger(path)  # must not raise exceptions
    finally:
        os.unlink(path)
    assert receipt["verdict"] == "FAIL", receipt
    # The hash check reports the missing self_hash...
    assert any(f.get("reason") == "missing_self_hash" for f in receipt["hash_failures"]), receipt
    # ...and the link check of e1 fails (expected prev = None instead of a real hash).
    assert receipt["link_passed"] is False, receipt
    ok("Entry without self_hash → graceful FAIL (no KeyError), failures recorded")


def test_broken_linkage_detected():
    e0 = _sealed_entry(0, {"v": "genesis"}, GENESIS_PREV)
    e1 = _sealed_entry(1, {"v": "second"}, e0["self_hash"])
    e1["prev_hash"] = "f" * 64  # broken link (and self_hash now inconsistent)
    path = _write_ledger([e0, e1])
    try:
        receipt = verify_ledger(path)
    finally:
        os.unlink(path)
    assert receipt["verdict"] == "FAIL", receipt
    assert receipt["link_passed"] is False, receipt
    ok("Broken linkage → FAIL detected")


print("\n\033[36m── verify_ledger: robustness and regression ──\033[0m")
test_valid_chain_passes()
test_missing_self_hash_does_not_crash()
test_broken_linkage_detected()

total = PASS + FAIL
print(f"\n{'═' * 60}")
print(f"  verify_ledger: {PASS}/{total} passed", end="")
if FAIL:
    print(f"  \033[31m({FAIL} FAILED)\033[0m")
    sys.exit(1)
else:
    print(f"  \033[32m✓ ALL OK\033[0m")
    sys.exit(0)
