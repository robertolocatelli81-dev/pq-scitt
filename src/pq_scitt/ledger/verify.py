#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pq-scitt · pq_scitt/ledger/verify.py — Standalone ledger verifier (auditor-grade)
=============================================================================

Independently verifies a hash-chained ledger (`*.jsonl`) using only stdlib (hashlib, json,
sys, argparse) and a single companion file, also stdlib-only: `pq_scitt/strict_json.py`, the
strict reader. A line with repeated members, NaN, Infinity, BOM, excessive depth, non-UTF-8
bytes, or that is not an object is an error with a reason: FAIL, never a crash and never a skipped line.

Verified schema:
  - Each line is a JSON object with at least: {idx, ts, data, prev_hash, self_hash}
  - `self_hash` = SHA-256( JSON(entry without self_hash, sort_keys, separators (',',':')) )
  - `prev_hash` of entry i = `self_hash` of entry i-1 (the first one has 64 zeros)

Output: structured JSON receipt. Exit code 0 = chain intact, 1 = error.

Example:
    pq-scitt verify-ledger ledger.jsonl
    pq-scitt verify-ledger ledger.jsonl --algo sha256
    pq-scitt verify-ledger ledger.jsonl --algo sha3_256

Reproducible by a third-party auditor: same file, same schema → same receipt.

╔══════════════════════════════════════════════════════════════════════════════╗
║  THREAT MODEL — the BARE chain is only tamper-EVIDENT (PARTIAL edits)         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  The self-contained chain (prev_hash/self_hash) is NOT tamper-PROOF: whoever  ║
║  holds the file can alter an entry and RE-WIRE all downstream hashes (FORGE + ║
║  RE-CHAIN), or TRUNCATE the tail; the result stays internally consistent and  ║
║  would pass the chain check alone. The bare chain detects ONLY PARTIAL edits  ║
║  (by someone who does not recompute the hashes).                              ║
║                                                                                ║
║  DEFENSE (OUT-OF-BAND anchors, this verifier enforces them on request):       ║
║   • --expect-count N   → FAILS if there are < N entries (tail truncation).    ║
║   • --expect-tip HASH  → FAILS if the last self_hash != HASH (rechain/        ║
║                          truncation change the tip → they are caught).        ║
║   • --hmac-key K + --expect-hmac T → HMAC-SHA256(K, "count:tip"): without the ║
║                          key an attacker cannot sign a forged tip.            ║
║   • --checkpoint FILE --checkpoint-pubkey HEX → reads the SIGNED (Ed25519)    ║
║                          .checkpoint sidecar and uses its (count,last_hash)   ║
║                          as anchor; the signature is verified with the        ║
║                          caller's TRUSTED key, never with the one written in  ║
║                          the sidecar. Without --checkpoint-pubkey the anchor  ║
║                          FAILS; the old TOFU only with --checkpoint-tofu      ║
║                          ("non verificato" = not verified).                   ║
║  A REAL but old checkpoint proves only the state at that time: whoever        ║
║  truncates to that point and presents that checkpoint again passes. The       ║
║  up-to-date expected count (--expect-count) lives outside the file.           ║
║  The expected tip/HMAC/checkpoint must be kept ON A TRUSTED CHANNEL, not next ║
║  to the file (an attacker who rewrites the file would also rewrite an         ║
║  unsigned co-located anchor).                                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional

try:
    from pq_scitt.strict_json import loads_object as _strict_object
except ImportError:   # origin branch: here it is the same import
    from pq_scitt.strict_json import loads_object as _strict_object

GENESIS_PREV = "0" * 64
SUPPORTED_ALGOS = ("sha256", "sha3_256")


def canonical_payload(entry: Dict) -> bytes:
    """Canonical string of the entry without self_hash: used to recompute self_hash."""
    d = {k: v for k, v in entry.items() if k != "self_hash"}
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def hash_with(algo: str, payload: bytes) -> str:
    if algo == "sha256":
        return hashlib.sha256(payload).hexdigest()
    if algo == "sha3_256":
        return hashlib.sha3_256(payload).hexdigest()
    raise ValueError(f"unsupported_algo:{algo}")


def detect_algo(entries: List[Dict]) -> Optional[str]:
    """Auto-detect: tries both algorithms on the first entry."""
    if not entries:
        return None
    e0 = entries[0]
    if "self_hash" not in e0:
        return None
    payload = canonical_payload(e0)
    for algo in SUPPORTED_ALGOS:
        if hash_with(algo, payload) == e0["self_hash"]:
            return algo
    return None


def _generic_recompute_verify(entries: List[Dict], started: str, path: str) -> Optional[Dict]:
    """Attempt at FULL verification (hash recompute) for ledgers without `idx` but with a
    detectable GENERIC hashing rule: hash_key = ALGO( canonical(entry without hash_key
    [and without signature]) ). Returns a PASS receipt only if the recompute matches on ALL
    entries AND the chain is intact (no risk of a false PASS: PASS only if every hash matches).
    If the rule does not match everywhere → None (fall back to linkage)."""
    if not entries:
        return None
    keys = list(entries[-1].keys())
    prev_keys = [k for k in keys if "prev" in k.lower() and "hash" in k.lower()]
    hash_cands = [k for k in keys if "hash" in k.lower() and "prev" not in k.lower()]
    if not prev_keys or not hash_cands:
        return None
    pk = prev_keys[0]
    sig_keys = [k for k in keys if k in ("signature", "sig")]
    total = len(entries)

    def _matches(hk, algo, drop):
        idxs = []
        for i, e in enumerate(entries):
            body = {k: v for k, v in e.items() if k not in drop}
            payload = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()
            if hash_with(algo, payload) == e.get(hk):
                idxs.append(i)
        return idxs

    # find the rule (hk, algo, drop) that reproduces AS MANY entries AS POSSIBLE
    best = None  # (n_ok, hk, algo, drop, ok_idxs)
    for hk in hash_cands:
        for algo in SUPPORTED_ALGOS:
            for drop in ({hk}, {hk, *sig_keys}):
                ok_idxs = _matches(hk, algo, drop)
                if best is None or len(ok_idxs) > best[0]:
                    best = (len(ok_idxs), hk, algo, drop, ok_idxs)

    if best is None:  # pragma: no cover - defensive: hash_cands is already guaranteed non-empty above
        return None
    n_ok, hk, algo, drop, ok_idxs = best
    # rule NOT detected (no majority) → module-specific scheme → fall back to linkage
    if n_ok < max(1, (total + 1) // 2):
        return None

    # rule DETECTED: from here the full verification is MANDATORY (no fallback that could hide tampering)
    hash_failures = [i for i in range(total) if i not in set(ok_idxs)]
    # linkage under the same rule
    link_failures = []
    prev = GENESIS_PREV
    for i, e in enumerate(entries):
        if i > 0 and e.get(pk) not in (prev, None):
            link_failures.append(i)
        prev = e.get(hk)
    passed = (not hash_failures) and (not link_failures)
    receipt = {
        "verified_utc": started,
        "verifier": "pq-scitt ledger.verify 0.1.0 (stdlib-only, generic full-recompute)",
        "path": path,
        "mode": "full_recompute_generic",
        "algorithm_used": algo,
        "hash_key": hk,
        "prev_key": pk,
        "drop_fields": sorted(drop),
        "entries_count": total,
        "hash_recomputed_ok": n_ok,
        "hash_failures_idx": hash_failures[:10],
        "link_failures_idx": link_failures[:10],
        "hash_recompute_passed": not hash_failures,
        "chain_integrity": passed,
        "verdict": "PASS" if passed else "FAIL",
    }
    rc = {k: v for k, v in receipt.items() if k != "verified_utc"}
    payload = json.dumps(rc, sort_keys=True, separators=(",", ":"), default=str).encode()
    receipt["receipt_sha256"] = hashlib.sha256(payload).hexdigest()
    return receipt


def _linkage_verify(entries: List[Dict], started: str, path: str) -> Optional[Dict]:
    """LINKAGE verification for ledgers with a module-specific hash scheme
    (modules with their own scheme): these have no `idx` and use their own hashing rule
    that verify_ledger does not recompute independently. Here we verify that the
    CHAIN is intact — each `prev_hash` == hash of the previous entry — which detects
    reordering / deletion / insertion. Honest verdict: LINKED (not PASS: the full
    hash recompute requires the module's native verifier)."""
    if not entries:
        return None
    keys = list(entries[-1].keys())
    prev_keys = [k for k in keys if "prev" in k.lower() and "hash" in k.lower()]
    hash_cands = [k for k in keys if "hash" in k.lower() and "prev" not in k.lower()]
    if not prev_keys or not hash_cands:
        return None
    pk = prev_keys[0]
    # pick the hash key that makes the chain most consistent
    best = None
    for hk in hash_cands:
        prev = None
        fails: List[Dict] = []
        for i, e in enumerate(entries):
            if i > 0 and e.get(pk) != prev:
                fails.append({"index": i, "expected_prev": prev, "actual_prev": e.get(pk)})
            prev = e.get(hk)
        if best is None or len(fails) < len(best[1]):
            best = (hk, fails)
    hk, link_failures = best
    linked = len(link_failures) == 0
    receipt = {
        "verified_utc": started,
        "verifier": "pq-scitt ledger.verify 0.1.0 (stdlib-only, linkage mode)",
        "path": path,
        "mode": "linkage",
        "scheme_note": (
            "module-specific hash scheme: the CHAIN was verified "
            "(prev==previous hash), NOT the full hash recompute "
            "(use the module's native verifier for that)."
        ),
        "hash_key": hk,
        "prev_key": pk,
        "entries_count": len(entries),
        "link_ok": len(entries) - len(link_failures),
        "link_total": len(entries),
        "link_failures": link_failures[:10],
        "chain_linkage_integrity": linked,
        "verdict": "LINKED" if linked else "FAIL",
    }
    rc = {k: v for k, v in receipt.items() if k != "verified_utc"}
    payload = json.dumps(rc, sort_keys=True, separators=(",", ":"), default=str).encode()
    receipt["receipt_sha256"] = hashlib.sha256(payload).hexdigest()
    return receipt


def _with_parse_errors(receipt: Dict, errors: List[Dict]) -> Dict:
    """A rejected line is not a line that does not exist. Before this function the generic and linkage branches got
    only the good lines: a broken line at the tail gave PASS (audit 07/11). With errors the verdict is FAIL."""
    if not errors:
        return receipt
    out = dict(receipt, parse_errors=errors[:10], verdict="FAIL")
    for k in ("chain_integrity", "chain_linkage_integrity"):
        if k in out:
            out[k] = False
    rc = {k: v for k, v in out.items() if k not in ("verified_utc", "receipt_sha256")}
    out["receipt_sha256"] = hashlib.sha256(
        json.dumps(rc, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
    return out


def _tip_hmac(key, count: int, tip: str) -> str:
    """HMAC-SHA256(key, "count:tip") — keyed anchor against forge+rechain. `key` str or bytes."""
    kb = key.encode() if isinstance(key, str) else bytes(key)
    return hmac.new(kb, f"{count}:{tip}".encode(), hashlib.sha256).hexdigest()


def _load_checkpoint_anchor(cp_path: str, trusted_pub_hex: Optional[str] = None,
                            allow_untrusted: bool = False) -> Dict:
    """Reads a SIGNED (Ed25519) .checkpoint sidecar and extracts (count, last_hash) from it as an ANCHOR.

    The signature is verified with the TRUSTED public key given by the caller (`trusted_pub_hex`, 32 bytes
    hex), NEVER with the key written in the sidecar: whoever truncates the tail can also rewrite the checkpoint
    with their own key (fleet audit 04/11/2026, C1-M1). Outcomes of `sig_verified`:
      True     signature valid with the caller's key;
      False    invalid signature, missing/malformed key, sidecar key different from the expected
               one, signature not verifiable → the anchor FAILS (reason in `reason`);
      <string> only with allow_untrusted=True (historical behaviour, explicitly requested):
               signature verified with the sidecar key, identity NOT verified (not a PASS
               of the identity)."""
    meta: Dict = {"checkpoint_path": cp_path, "count": None, "last_hash": None, "sig_verified": None}
    try:
        with open(cp_path, "rb") as f:
            cp = _strict_object(f.read())
    except (OSError, ValueError) as e:   # ValueError: also the strict reader's rejection, with a reason
        meta["sig_verified"] = False
        meta["error"] = f"checkpoint unreadable: {str(e)[:80]}"
        return meta
    if "count" in cp and (type(cp["count"]) is not int):   # the comparison with count is outside this function
        meta["sig_verified"] = False
        meta["reason"] = "checkpoint_count_non_intero"
        return meta
    meta["count"] = cp.get("count")
    meta["last_hash"] = cp.get("last_hash")
    body = {k: cp[k] for k in ("count", "last_hash", "ts", "byte_offset") if k in cp}
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

    trusted_raw = None
    if trusted_pub_hex is not None:
        try:
            trusted_raw = bytes.fromhex(trusted_pub_hex.strip())
        except (ValueError, AttributeError):
            trusted_raw = None
        if trusted_raw is None or len(trusted_raw) != 32:
            meta["sig_verified"] = False
            meta["reason"] = "checkpoint_pubkey_malformata (expected 32 bytes hex)"
            return meta
        meta["key_source"] = "chiamante"
    elif not allow_untrusted:
        meta["sig_verified"] = False
        meta["reason"] = ("checkpoint_pubkey_assente: the signer's trusted key is required "
                          "(--checkpoint-pubkey HEX); the key written in the checkpoint does not bind the identity")
        return meta
    else:
        meta["key_source"] = "checkpoint (non fidata)"

    if "sig_hybrid" in cp and "sig" not in cp:
        note = "firma-ibrida-non-verificabile-stdlib (use the native pqc_hybrid verifier)"
        if trusted_raw is not None:
            meta["sig_verified"] = False
            meta["reason"] = note
        else:
            meta["sig_verified"] = "non verificato: " + note
        return meta
    if trusted_raw is not None:
        cp_pub = cp.get("pub")
        if "pub" in cp and (not isinstance(cp_pub, str) or cp_pub.strip().lower() != trusted_raw.hex()):
            meta["sig_verified"] = False
            meta["reason"] = "checkpoint_pub_diversa_dalla_chiave_attesa"
            return meta
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        raw = trusted_raw if trusted_raw is not None else bytes.fromhex(cp["pub"])
        pub = Ed25519PublicKey.from_public_bytes(raw)
        pub.verify(bytes.fromhex(cp["sig"]), payload)
        if trusted_raw is not None:
            meta["sig_verified"] = True
        else:
            meta["sig_verified"] = ("non verificato: signature valid with the key written in the checkpoint "
                                    "(TOFU requested with --checkpoint-tofu); signer identity NOT bound")
    except ImportError:
        if trusted_raw is not None:
            meta["sig_verified"] = False
            meta["reason"] = "cryptography-assente: signature not verifiable"
        else:
            meta["sig_verified"] = "non verificato: cryptography-assente (advisory anchor)"
    except Exception:
        meta["sig_verified"] = False
        meta["reason"] = "firma_non_valida"
    return meta


def _eval_anchor(entries: List[Dict], expect_count, expect_tip, hmac_key, expect_hmac,
                 checkpoint_meta: Optional[Dict]) -> Optional[Dict]:
    """Evaluates the out-of-band ANCHORS against the observed entries. Returns None if no anchor is
    requested (legacy behaviour unchanged), otherwise {checks, failed, anchor_ok}."""
    # the signed checkpoint provides (count, last_hash) as expected values, if not already passed explicitly
    if checkpoint_meta is not None:
        if expect_count is None and checkpoint_meta.get("count") is not None:
            expect_count = checkpoint_meta["count"]
        if expect_tip is None and checkpoint_meta.get("last_hash") is not None:
            expect_tip = checkpoint_meta["last_hash"]
    if expect_count is None and expect_tip is None and hmac_key is None and expect_hmac is None \
            and checkpoint_meta is None:
        return None

    observed_count = len(entries)
    observed_tip = entries[-1].get("self_hash") if entries else GENESIS_PREV
    checks: Dict = {"observed_count": observed_count, "observed_tip": observed_tip}
    failed: List[str] = []

    if checkpoint_meta is not None:
        checks["checkpoint"] = checkpoint_meta
        if checkpoint_meta.get("sig_verified") is False:
            failed.append("checkpoint: Ed25519 signature NOT verified with the expected key ("
                          + str(checkpoint_meta.get("reason") or checkpoint_meta.get("error")
                                or "forged sidecar") + ")")

    if expect_count is not None:
        checks["expect_count"] = expect_count
        if observed_count < expect_count:
            failed.append(f"count {observed_count} < expected {expect_count} (tail truncation)")

    if expect_tip is not None:
        checks["expect_tip"] = expect_tip
        if observed_tip != expect_tip:
            failed.append("observed tip != expected tip (chain re-wired or truncated)")

    if hmac_key is not None or expect_hmac is not None:
        if hmac_key is None or expect_hmac is None:
            failed.append("hmac: BOTH --hmac-key AND --expect-hmac are required")
        else:
            computed = _tip_hmac(hmac_key, observed_count, observed_tip)
            checks["hmac_computed"] = computed
            checks["hmac_expected"] = expect_hmac
            if not hmac.compare_digest(computed, expect_hmac):
                failed.append("tip HMAC does not match (forge+rechain or truncation without the key)")

    return {"checks": checks, "failed": failed, "anchor_ok": len(failed) == 0}


def _finalize(receipt: Dict, anchor: Optional[Dict]) -> Dict:
    """Merges the anchor outcome into the receipt and re-seals the receipt hash. If no anchor is
    requested (anchor=None) it returns the receipt IDENTICAL to the legacy behaviour (no reseal)."""
    if anchor is None:
        return receipt
    receipt["anchor"] = anchor
    if not anchor["anchor_ok"]:
        receipt["verdict"] = "FAIL"
        for k in ("chain_integrity", "chain_linkage_integrity"):
            if k in receipt:
                receipt[k] = False
    # re-seal: same canonicalization as the other paths (excl. verified_utc + the receipt hashes)
    rc = {k: v for k, v in receipt.items()
          if k not in ("verified_utc", "receipt_sha256", "receipt_sha3_256")}
    payload = json.dumps(rc, sort_keys=True, separators=(",", ":"), default=str).encode()
    if "receipt_sha256" in receipt:
        receipt["receipt_sha256"] = hashlib.sha256(payload).hexdigest()
    if "receipt_sha3_256" in receipt:
        receipt["receipt_sha3_256"] = hashlib.sha3_256(payload).hexdigest()
    return receipt


def verify_ledger(path: str, algo: Optional[str] = None, *,
                  expect_count: Optional[int] = None, expect_tip: Optional[str] = None,
                  hmac_key=None, expect_hmac: Optional[str] = None,
                  checkpoint_path: Optional[str] = None,
                  checkpoint_pubkey: Optional[str] = None,
                  checkpoint_allow_untrusted: bool = False) -> Dict:
    """Verifies ledger integrity. Returns a JSON-serializable receipt.

    Optional OUT-OF-BAND anchors (default: none → legacy behaviour):
      expect_count   fails if there are < expect_count entries (tail truncation).
      expect_tip     fails if the last self_hash != expect_tip (forge+rechain / truncation).
      hmac_key + expect_hmac  HMAC-SHA256(key,"count:tip") expected, from a trusted channel.
      checkpoint_path  SIGNED Ed25519 .checkpoint sidecar → (count,last_hash) as anchor.
      checkpoint_pubkey  TRUSTED Ed25519 public key (hex) of the signer: MANDATORY with
                     checkpoint_path, otherwise the anchor FAILS (checkpoint_pubkey_assente).
      checkpoint_allow_untrusted  only on explicit request: historical behaviour (signature
                     verified with the sidecar key), marked "non verificato" (not verified).
    The BARE chain (without anchors) is only tamper-EVIDENT: it detects PARTIAL edits, NOT forge+rechain
    nor tail truncation (see the threat model in the module docstring)."""
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    errors: List[Dict] = []

    # `is not None`: `--checkpoint ""` (empty variable) is an unreadable file, not "no anchor"; a key or
    # --checkpoint-tofu without a checkpoint ask for an anchor that is not there: FAIL, never PASS without anchor
    checkpoint_meta = None
    if checkpoint_path is not None:
        checkpoint_meta = _load_checkpoint_anchor(checkpoint_path, checkpoint_pubkey, checkpoint_allow_untrusted)
    elif checkpoint_pubkey is not None or checkpoint_allow_untrusted:
        checkpoint_meta = {"checkpoint_path": None, "count": None, "last_hash": None, "sig_verified": False,
                           "reason": "checkpoint_assente: key or --checkpoint-tofu without --checkpoint"}

    try:
        with open(path, "rb") as f:   # bytes: a non-UTF-8 byte is a rejected line, not a verifier crash
            raw_lines = [ln for ln in f.read().splitlines() if ln.strip()]
    except FileNotFoundError:
        anchor = _eval_anchor([], expect_count, expect_tip, hmac_key, expect_hmac, checkpoint_meta)
        r = {"verdict": "FILE_NOT_FOUND", "path": path, "verified_utc": started}
        if anchor is not None:
            r["anchor"] = anchor
        return r

    if not raw_lines:   # empty (also truncated to zero bytes) like absent: nothing to verify is not a PASS (review 08/11)
        anchor = _eval_anchor([], expect_count, expect_tip, hmac_key, expect_hmac, checkpoint_meta)
        r = {"verdict": "EMPTY", "path": path, "verified_utc": started, "entries_count": 0}
        if anchor is not None:
            r["anchor"] = anchor
        return r

    entries: List[Dict] = []
    for i, line in enumerate(raw_lines):
        try:
            entries.append(_strict_object(line))
        except ValueError as e:
            errors.append({"line": i, "error": f"json_decode:{e}"})

    anchor = _eval_anchor(entries, expect_count, expect_tip, hmac_key, expect_hmac, checkpoint_meta)

    # NON-LEDGER (fix 2026-08-18): a .jsonl without ANY hash key (e.g. a dataset
    # of measurements) ended up in the PersistentLedger branch and came out FAIL "full"
    # (every entry missing_self_hash) — the same verdict as a tampered ledger. Honest frame:
    # the ledger yardstick does NOT apply → dedicated verdict, which is NOT a PASS (it clears
    # nothing) and does not dilute real FAILs (a real ledger has hash keys and stays under the yardstick).
    if algo is None and entries and not any(
        "hash" in k.lower() for e in entries[:3] for k in e.keys()
    ):
        return {
            "verdict": "NOT_A_LEDGER", "path": path, "verified_utc": started,
            "entries_count": len(entries), "mode": "none", "parse_errors": errors[:10],
            "scheme_note": "no hash key in any entry: data file, not a hash-chained "
                           "ledger — the chain integrity yardstick does not apply",
        }

    # NATIVE scheme (non-PersistentLedger): no `idx` → honest linkage verification,
    # without pretending a full hash recompute we do not know.
    if algo is None and entries and not any("idx" in e for e in entries[:3]):
        # 1) try the generic FULL verification (hash recompute on all entries)
        full = _generic_recompute_verify(entries, started, path)
        if full is not None:
            return _finalize(_with_parse_errors(full, errors), anchor)
        # 2) otherwise honest LINKAGE verification (module-specific scheme)
        linkage = _linkage_verify(entries, started, path)
        if linkage is not None:
            return _finalize(_with_parse_errors(linkage, errors), anchor)

    if algo is None:
        algo = detect_algo(entries) or "sha256"

    # Re-hash check
    hash_recomputed = 0
    hash_failures: List[Dict] = []
    for i, e in enumerate(entries):
        expected = e.get("self_hash")
        if expected is None:
            hash_failures.append({"idx": e.get("idx", i), "reason": "missing_self_hash"})
            continue
        computed = hash_with(algo, canonical_payload(e))
        if computed == expected:
            hash_recomputed += 1
        else:
            hash_failures.append(
                {
                    "idx": e.get("idx", i),
                    "reason": "hash_mismatch",
                    "expected": expected,
                    "computed": computed,
                }
            )

    # Chain linkage check
    link_ok = 0
    link_failures: List[Dict] = []
    for i, e in enumerate(entries):
        expected_prev = entries[i - 1].get("self_hash") if i > 0 else GENESIS_PREV
        actual_prev = e.get("prev_hash")
        if actual_prev == expected_prev:
            link_ok += 1
        else:
            link_failures.append(
                {
                    "idx": e.get("idx", i),
                    "expected_prev": expected_prev,
                    "actual_prev": actual_prev,
                }
            )

    # Idx monotonicity
    idx_ok = True
    for i, e in enumerate(entries):
        if e.get("idx") != i:
            idx_ok = False
            errors.append({"line": i, "error": f"idx_mismatch: expected {i}, got {e.get('idx')}"})

    chain_integrity = len(hash_failures) == 0 and len(link_failures) == 0 and idx_ok and len(errors) == 0

    receipt: Dict = {
        "verified_utc": started,
        "verifier": "pq-scitt ledger.verify 0.1.0 (stdlib-only)",
        "path": path,
        "algorithm_used": algo,
        "algorithm_supported": list(SUPPORTED_ALGOS),
        "entries_count": len(entries),
        "hash_recomputed_ok": hash_recomputed,
        "hash_recomputed_total": len(entries),
        "hash_recompute_passed": len(hash_failures) == 0,
        "hash_failures": hash_failures[:10],  # cap
        "link_ok": link_ok,
        "link_total": len(entries),
        "link_passed": len(link_failures) == 0,
        "link_failures": link_failures[:10],
        "idx_monotonic": idx_ok,
        "parse_errors": errors[:10],
        "chain_integrity": chain_integrity,
        "verdict": "PASS" if chain_integrity else "FAIL",
    }

    # Receipt-of-receipt: hash of the receipt itself (deterministic, verified_utc excluded)
    receipt_canonical = {k: v for k, v in receipt.items() if k != "verified_utc"}
    receipt_payload = json.dumps(
        receipt_canonical, sort_keys=True, separators=(",", ":"), default=str
    ).encode()
    receipt["receipt_sha256"] = hashlib.sha256(receipt_payload).hexdigest()
    receipt["receipt_sha3_256"] = hashlib.sha3_256(receipt_payload).hexdigest()
    return _finalize(receipt, anchor)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pq-scitt verify-ledger",
        description="Independent verification of a hash-chained .jsonl ledger (auditor-grade, stdlib-only).",
    )
    parser.add_argument("ledger_path", help="Path of the .jsonl file to verify")
    parser.add_argument(
        "--algo", choices=SUPPORTED_ALGOS, default=None, help="Force the algorithm (default: auto-detect)"
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Print only the short verdict (PASS/FAIL + exit code)"
    )
    parser.add_argument("--out", default=None, help="Also write the JSON receipt to a file")
    # ── OUT-OF-BAND anchors (against forge+rechain and tail truncation) ──
    parser.add_argument("--expect-count", type=int, default=None,
                        help="FAILS if there are fewer than N entries (tail truncation)")
    parser.add_argument("--expect-tip", default=None,
                        help="FAILS if the last self_hash != HASH (forge+rechain / truncation)")
    parser.add_argument("--hmac-key", default=None,
                        help="Key (str) for the HMAC-SHA256 of the tip; requires --expect-hmac")
    parser.add_argument("--expect-hmac", default=None,
                        help="HMAC-SHA256(key,\"count:tip\") expected, from a trusted channel")
    parser.add_argument("--checkpoint", default=None,
                        help="SIGNED Ed25519 .checkpoint sidecar → uses (count,last_hash) as anchor; "
                             "requires --checkpoint-pubkey")
    parser.add_argument("--checkpoint-pubkey", default=None,
                        help="TRUSTED Ed25519 public key of the checkpoint signer (64 hex), "
                             "from a trusted channel; without it, --checkpoint FAILS")
    parser.add_argument("--checkpoint-tofu", action="store_true",
                        help="Historical behaviour: signature verified with the key written in the "
                             "checkpoint; outcome marked 'non verificato' (not verified; identity not bound)")
    args = parser.parse_args(argv)

    receipt = verify_ledger(args.ledger_path, algo=args.algo,
                            expect_count=args.expect_count, expect_tip=args.expect_tip,
                            hmac_key=args.hmac_key, expect_hmac=args.expect_hmac,
                            checkpoint_path=args.checkpoint,
                            checkpoint_pubkey=args.checkpoint_pubkey,
                            checkpoint_allow_untrusted=args.checkpoint_tofu)

    if args.out:
        with open(args.out, "w") as f:
            json.dump(receipt, f, indent=2, default=str)

    if args.quiet:
        print(receipt["verdict"])
    else:
        print(json.dumps(receipt, indent=2, default=str))

    return 0 if receipt.get("verdict") == "PASS" else 1


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint (main() is covered directly)
    sys.exit(main())
