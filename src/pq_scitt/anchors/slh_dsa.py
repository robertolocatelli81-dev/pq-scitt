#!/usr/bin/env python3
"""
pq_scitt/anchors/slh_dsa.py — LONG-TERM ANCHORS of a hash, signed with SLH-DSA (SPHINCS+, FIPS 205).

Why SLH-DSA and not (only) the hybrid Ed25519+ML-DSA-65 already present:
the security of SLH-DSA rests ONLY on hash functions (no assumption on lattices/algebra).
It is the most CONSERVATIVE leg of an archival anchor (10-30 years): it holds even in the scenario
— hypothetical today — in which lattices (ML-DSA) fall. Complementary, not a replacement.

TWO BACKENDS (optional, auto-selected at keygen time):
  - 'oqs'    : liboqs C (open-quantum-safe) via liboqs-python — FAST. Measured: 256f sign ~96ms, verify ~2.7ms.
               Chosen by 'auto' only if the `oqs` module is REALLY liboqs-python (it has `Signature` and
               `get_enabled_sig_mechanisms`) and the mechanism for the parameter is enabled in the build.
               (08/11/2026: PyPI has a homonymous `oqs` package, an expression interpreter: it used to be chosen.)
  - 'slhdsa' : PyPI `slh-dsa` (0.2.5: wheel compiled with mypyc) — portable, slower. Fallback.
Hand-rolling SPHINCS+ = snake oil: we use only vetted libraries.

FORMAT SPECIFICATION (versioned, 08/11/2026):
  - omega-slhdsa-anchor-v2 (new anchors): FIPS 205 "pure" signature (Alg. 22/24, slh_sign/slh_verify) with
    EMPTY context over the canonical body {schema,param,root,ts}, for BOTH backends. Keys and signatures are the
    same for both backends (pk = PK.seed‖PK.root): a v2 anchor is a FIPS 205 pure signature with empty
    ctx: liboqs (SLH_DSA_PURE_*) verifies it, measured on 3 parameters; if the recorded backend is missing, the other is used. Fields: exactly
    {schema, backend, param, root, ts, sig, pub}; any other field = anchor rejected.
  - omega-slhdsa-anchor-v1 (VERIFY only, for anchors already signed): backend 'slhdsa' = the library's "Bare"
    interface (initial draft = slh_verify_internal over the body, without the FIPS 205 prefix 0x00‖|ctx|‖ctx);
    backend 'oqs' = already pure. Fields: {schema, param, root, ts, sig, pub} plus optional 'backend' (absent ⇒
    'slhdsa'). Measured on the NIST ACVP vectors (tests/data/acvp_slhdsa_sha2_128f.json, tests/test_anchor_slhdsa_fips205.py): v1 'slhdsa' passes the
    "internal" group and NOT the "external/pure" group; this is why new anchors are v2.

Honest cost: large signature (~50KB with sha2_256f) and sign ~100ms (C) / ~600ms (Python). RARE anchors
(one per rotation/segment) → amortized cost. Default sha2_256f: 256-bit + fast sign.

Honest-scope: an absolute "unbreakable" does NOT exist. It defends against the harvest-now-forge-later threat on
long-retention archives; NOT against TODAY's theft of the key; it does not replace a periodic full verify.
"""
from __future__ import annotations

import json
import time
from typing import Any, Optional

SCHEMA = "omega-slhdsa-anchor-v2"      # FIPS 205 pure, empty ctx (new anchors)
SCHEMA_V1 = "omega-slhdsa-anchor-v1"   # verify only: slhdsa = Bare (internal), oqs = pure
DEFAULT_PARAM = "sha2_256f"        # 256-bit, FAST sign (was sha2_256s: smaller signature but slow sign)
DEFAULT_BACKEND = "auto"           # auto → oqs if it is liboqs-python with the mechanism enabled, otherwise slhdsa
PARAMS = frozenset(f"{h}_{n}{v}" for h in ("sha2", "shake") for n in (128, 192, 256) for v in "sf")
_BACKENDS = ("oqs", "slhdsa")
_KEYS_V2 = frozenset({"schema", "backend", "param", "root", "ts", "sig", "pub"})
_KEYS_V1 = frozenset({"schema", "param", "root", "ts", "sig", "pub"})      # + optional 'backend'

# CANONICAL (short) parameter names: sha2_128s/f, sha2_192s/f, sha2_256s/f, shake_*  (s=small-sig/slow, f=fast/big)


# ---------------------------------------------------------------------------
# backend helpers (LAZY import, honest degradation)
# ---------------------------------------------------------------------------

def _oqs_mech(param_name: str) -> str:
    """Canonical name ('sha2_256f') → liboqs 0.16 mechanism ('SLH_DSA_PURE_SHA2_256F')."""
    return "SLH_DSA_PURE_" + param_name.upper()


def _oqs_available(param_name: Optional[str] = None) -> bool:
    """True only if `oqs` is liboqs-python (not a homonymous package) and, if given, the mechanism is enabled."""
    try:
        import oqs
    except (Exception, SystemExit):     # liboqs-python without liboqs: tries to download it, then SystemExit
        return False
    if not (callable(getattr(oqs, "Signature", None)) and callable(getattr(oqs, "get_enabled_sig_mechanisms", None))):
        return False
    if param_name is None:
        return True
    try:
        return _oqs_mech(param_name) in set(oqs.get_enabled_sig_mechanisms())
    except Exception:
        return False


def _slhdsa_available() -> bool:
    try:
        import slhdsa  # noqa: F401
        import slhdsa.parameters  # noqa: F401
        return True
    except Exception:
        return False


def _require_slhdsa():
    try:
        import slhdsa
        import slhdsa.parameters as P
        return slhdsa, P
    except ImportError as e:
        raise RuntimeError("SLH-DSA (pure Python) not available: pip install slh-dsa") from e


def _slhdsa_param(param_name: str):
    _slhdsa, P = _require_slhdsa()
    p = getattr(P, param_name, None)
    if p is None:
        raise ValueError(f"Unknown SLH-DSA parameter: {param_name!r} "
                         "(expected sha2_128s/f, sha2_192s/f, sha2_256s/f, shake_*).")
    return p


def _resolve_backend(backend: str, param_name: Optional[str] = None) -> str:
    if backend == "auto":
        return "oqs" if _oqs_available(param_name) else "slhdsa"
    if backend not in _BACKENDS:
        raise ValueError(f"unknown backend: {backend!r} (expected 'oqs', 'slhdsa', 'auto').")
    if backend == "oqs" and not _oqs_available(param_name):
        raise RuntimeError("backend 'oqs' requested but liboqs-python is not available or the mechanism is not enabled "
                           f"({_oqs_mech(param_name) if param_name else 'SLH_DSA_PURE_*'}). Use 'slhdsa' or 'auto'.")
    return backend


# ---------------------------------------------------------------------------
# AnchorKey — anchor key abstracted over the two backends
# ---------------------------------------------------------------------------

class AnchorKey:
    """SLH-DSA anchor key on backend 'oqs' (fast) or 'slhdsa' (portable).
    Generate with AnchorKey.generate(); persist with export_secret()/from_secret()."""

    def __init__(self, backend: str, param_name: str, impl: Any, pub: bytes):
        self.backend = backend
        self.param_name = param_name
        self._impl = impl            # oqs.Signature (with secret) | slhdsa.KeyPair
        self._pub = pub              # bytes: pub raw (oqs) | pub.digest() 32B (slhdsa)

    @classmethod
    def generate(cls, param_name: str = DEFAULT_PARAM, backend: str = DEFAULT_BACKEND) -> "AnchorKey":
        if param_name not in PARAMS:
            raise ValueError(f"Unknown SLH-DSA parameter: {param_name!r} (expected {sorted(PARAMS)}).")
        be = _resolve_backend(backend, param_name)
        if be == "oqs":
            import oqs
            sig = oqs.Signature(_oqs_mech(param_name))
            pub = sig.generate_keypair()          # returns the pub ONCE; we capture it here
            return cls("oqs", param_name, sig, pub)
        _slhdsa, _P = _require_slhdsa()
        from slhdsa import KeyPair
        kp = KeyPair.gen(_slhdsa_param(param_name))
        return cls("slhdsa", param_name, kp, kp.pub.digest())

    def sign(self, message: bytes) -> bytes:
        """FIPS 205 "pure" signature with empty context (slh_sign, Alg. 22) on both backends.
        slhdsa: deterministic (opt_rand = PK.seed, variant allowed by FIPS 205 §9.2); oqs: randomized."""
        if self.backend == "oqs":
            return self._impl.sign(message)                 # liboqs SLH_DSA_PURE_*: pure, empty ctx
        return self._impl.sign_pure(message, False, b"")    # NOT .sign(): that is the Bare (internal) interface

    def pub_bytes(self) -> bytes:
        return self._pub

    def export_secret(self) -> dict:
        """SECRET material to persist the key (keep it as a private key)."""
        if self.backend == "oqs":
            return {"backend": "oqs", "param": self.param_name,
                    "secret_hex": self._impl.export_secret_key().hex(), "pub_hex": self._pub.hex()}
        return {"backend": "slhdsa", "param": self.param_name,
                "keypair_digest_hex": self._impl.digest().hex(), "pub_hex": self._pub.hex()}

    @classmethod
    def from_secret(cls, meta: dict) -> "AnchorKey":
        be = meta["backend"]; param = meta["param"]
        if be == "oqs":
            _resolve_backend("oqs", param)
            import oqs
            sig = oqs.Signature(_oqs_mech(param), secret_key=bytes.fromhex(meta["secret_hex"]))
            return cls("oqs", param, sig, bytes.fromhex(meta["pub_hex"]))
        _slhdsa, _P = _require_slhdsa()
        from slhdsa import KeyPair
        kp = KeyPair.from_digest(bytes.fromhex(meta["keypair_digest_hex"]), _slhdsa_param(param))
        return cls("slhdsa", param, kp, bytes.fromhex(meta["pub_hex"]))


# ---------------------------------------------------------------------------
# canonical body + raw verify per backend
# ---------------------------------------------------------------------------

def _is_hex(s) -> bool:
    return isinstance(s, str) and len(s) > 0 and len(s) % 2 == 0 and all(c in "0123456789abcdef" for c in s)


def _canonical_body(schema: str, param: str, root: str, ts: float) -> bytes:
    return json.dumps({"schema": schema, "param": param, "root": root, "ts": ts},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _verify_raw(backend: str, param: str, pub_hex: str, message: bytes, sig: bytes,
                legacy_bare: bool = False) -> bool:
    """FAIL-CLOSED verify. Default: FIPS 205 pure, empty ctx (slh_verify, Alg. 24) — with the given backend if
    available, otherwise with the other one (same scheme, same keys). legacy_bare=True: ONLY for v1 anchors
    of the 'slhdsa' backend = the library's Bare interface (slh_verify_internal); never with 'oqs'."""
    try:
        if backend not in _BACKENDS or param not in PARAMS:
            return False
        if legacy_bare:
            if backend != "slhdsa":
                return False
            from slhdsa import PublicKey
            pub = PublicKey.from_digest(bytes.fromhex(pub_hex), _slhdsa_param(param))
            return pub.verify(message, sig) is True
        # lazy order: the recorded backend first, the other only if it is missing (importing `oqs` can have side
        # effects: liboqs-python without liboqs attempts git clone + build, then SystemExit)
        avail = {"oqs": lambda: _oqs_available(param), "slhdsa": _slhdsa_available}
        other = "slhdsa" if backend == "oqs" else "oqs"
        if avail[backend]():
            be = backend
        elif avail[other]():
            be = other
        else:
            return False
        if be == "oqs":
            import oqs
            return oqs.Signature(_oqs_mech(param)).verify(message, sig, bytes.fromhex(pub_hex)) is True
        from slhdsa import PublicKey
        pub = PublicKey.from_digest(bytes.fromhex(pub_hex), _slhdsa_param(param))
        return pub.verify_pure(message, sig, b"") is True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def create_anchor(root_hex: str, key, param_name: Optional[str] = None) -> dict:
    """Create an SLH-DSA anchor for `root_hex` (e.g. chain_sha3 of a Checkpoint or a segment MMR root).
    `key`: AnchorKey (recommended) OR a pure-Python slhdsa.KeyPair (legacy → backend 'slhdsa').
    Signs the canonical body {schema,param,root,ts}. Returns a dict with backend + embedded pub (TOFU)."""
    if not isinstance(root_hex, str) or not root_hex:
        raise ValueError("root_hex must be a non-empty string (hash/root to anchor).")
    if isinstance(key, AnchorKey):
        ak = key
        if param_name is not None and param_name != ak.param_name:
            raise ValueError(f"param_name {param_name!r} differs from the key parameter {ak.param_name!r}.")
        param = ak.param_name
    else:
        # backward compat: pure-Python slhdsa.KeyPair passed directly
        param = param_name or DEFAULT_PARAM
        ak = AnchorKey("slhdsa", param, key, key.pub.digest())
    if param not in PARAMS:
        raise ValueError(f"Unknown SLH-DSA parameter: {param!r}.")
    ts = time.time()
    body = _canonical_body(SCHEMA, param, root_hex, ts)
    sig = ak.sign(body)
    return {"schema": SCHEMA, "backend": ak.backend, "param": param, "root": root_hex, "ts": ts,
            "sig": sig.hex(), "pub": ak.pub_bytes().hex()}


def verify_anchor(anchor: dict, pub: Optional[Any] = None) -> bool:
    """Verify an anchor. FAIL-CLOSED on every error. Dispatch on the recorded backend ('backend',
    default 'slhdsa' for v1 anchors without the field). `pub`: hex/bytes of the expected pub (pinning); if None
    the embedded one is used. A swapped backend or a wrong pub fail (the signature is not valid on that backend/key)."""
    try:
        if not isinstance(anchor, dict):
            return False
        schema = anchor.get("schema")
        keys = frozenset(anchor)
        if schema == SCHEMA:
            if keys != _KEYS_V2:                       # closed format: no unknown or missing fields
                return False
            backend = anchor["backend"]; legacy = False
        elif schema == SCHEMA_V1:
            if not (_KEYS_V1 <= keys <= _KEYS_V2):
                return False
            backend = anchor.get("backend", "slhdsa")
            legacy = backend == "slhdsa"               # v1 slhdsa = Bare; v1 oqs = already pure
        else:
            return False
        param = anchor["param"]; root = anchor["root"]; ts = anchor["ts"]
        if backend not in _BACKENDS or param not in PARAMS or not isinstance(root, str) or not root \
                or isinstance(ts, bool) or not isinstance(ts, (int, float)) or ts != ts or ts in (float("inf"), float("-inf")) \
                or not isinstance(anchor["sig"], str) or not isinstance(anchor["pub"], str):
            return False
        if not (_is_hex(anchor["sig"]) and _is_hex(anchor["pub"])):
            return False                               # a single encoding: lowercase hex, no spaces
        sig = bytes.fromhex(anchor["sig"])
        if pub is None:
            pub_hex = anchor["pub"]
        elif isinstance(pub, str):
            pub_hex = bytes.fromhex(pub).hex()
        elif isinstance(pub, (bytes, bytearray)):
            pub_hex = bytes(pub).hex()
        elif isinstance(pub, AnchorKey):
            pub_hex = pub.pub_bytes().hex()
        else:
            return False                               # pin of unknown type: never fall back to the embedded pub
        if pub_hex != anchor["pub"]:
            return False                               # with a pin, the embedded pub must be the same
        body = _canonical_body(schema, param, root, ts)
        return _verify_raw(backend, param, pub_hex, body, sig, legacy_bare=legacy)
    except Exception:
        return False


def anchor_checkpoint(checkpoint_obj, key, param_name: Optional[str] = None) -> dict:
    """Convenience: anchors the `.chain_sha3` field of a checkpoint (object or dict)."""
    root = getattr(checkpoint_obj, "chain_sha3", None)
    if root is None and isinstance(checkpoint_obj, dict):
        root = checkpoint_obj.get("chain_sha3")
    if not root:
        raise ValueError("checkpoint_obj has no 'chain_sha3': no root to anchor.")
    return create_anchor(root, key, param_name=param_name)


# ---------------------------------------------------------------------------
# self-test
# ---------------------------------------------------------------------------

def self_test(param_name: str = DEFAULT_PARAM, backend: str = DEFAULT_BACKEND) -> bool:
    ak = AnchorKey.generate(param_name, backend)
    print(f"selected backend: {ak.backend}  param: {ak.param_name}")
    anchor = create_anchor("a" * 64, ak)
    checks = [
        ("positive (valid→True)", verify_anchor(anchor) is True),
        ("tampered root→False", verify_anchor({**anchor, "root": "b" * 64}) is False),
        ("tampered param→False", verify_anchor({**anchor, "param": "sha2_256s"}) is False),
        ("tampered ts→False", verify_anchor({**anchor, "ts": anchor["ts"] + 1}) is False),
        ("truncated signature→False", verify_anchor({**anchor, "sig": anchor["sig"][:-8]}) is False),
        ("wrong pub→False", verify_anchor(anchor, pub=AnchorKey.generate(param_name, backend).pub_bytes()) is False),
        ("unknown field→False", verify_anchor({**anchor, "x": 1}) is False),
        ("v1 schema declared on v2 signature→False", verify_anchor({**anchor, "schema": SCHEMA_V1}) is False),
        ("unknown backend→False", verify_anchor({**anchor, "backend": "altro"}) is False),
    ]
    all_ok = True
    for name, ok in checks:
        print(f"[{'OK ' if ok else 'FAIL'}] {name}"); all_ok = all_ok and ok
    print(f"\nself_test SLH-DSA (backend={ak.backend}, {param_name}): {'PASS' if all_ok else 'FAIL'}")
    return all_ok


if __name__ == "__main__":
    import sys
    sys.exit(0 if self_test() else 1)
