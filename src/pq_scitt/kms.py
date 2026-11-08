#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pq-scitt — KMS/HSM signing backends (the private key leaves the process).

SPDX-License-Identifier: Apache-2.0
Copyright (C) 2026 Roberto Locatelli

Closes the gap "Ed25519 seed read from a local file into process memory": the signature
operation is delegated to a backend where the private key is NON-EXPORTABLE — a PKCS#11
HSM (YubiHSM 2, SoftHSM2, smartcard), AWS KMS (key spec ECC_NIST_EDWARDS25519, available
since 2025-11), or HashiCorp Vault Transit (key type ed25519). The evidence format does
NOT change: signatures stay 64-byte Ed25519 over `self_hash`, so `pq_scitt/ledger/standalone.py` and
cryptovalid-opencore's `signer.py verify` keep working unchanged, offline, stdlib-only.

Backends (URI-style selector, `backend_from_uri`):
  file:signer.key
      Legacy: hex seed on disk (0600). Key IS in process memory — kept for
      compatibility and tests; use an HSM/KMS backend in production.
  pkcs11:module=/usr/lib/softhsm/libsofthsm2.so;token=cryptovalid;key=evidence;pin=env:CRYPTOVALID_PIN
      Any PKCS#11 token via OpenSC `pkcs11-tool` (subprocess; no extra Python deps).
      The PIN is passed as `env:VAR` (never on argv → not visible in `ps`).
      Keygen/public key via pkcs11-tool; signing with a single-part C_Sign on the module (ctypes): pkcs11-tool 0.23
      streams inputs over 1024 bytes and EdDSA is single-part only (SoftHSM2: CKR_OPERATION_NOT_INITIALIZED).
      Measured 08/11/2026 against SoftHSM2 2.6.1 with SCITT exports (log not in this repository); YubiHSM 2 exposes the
      same mechanism via its PKCS#11 module (not tested on real hardware here — honest).
  awskms:key_id=<arn-or-id>;region=eu-south-1;profile=<optional>
      AWS KMS asymmetric key, KeySpec ECC_NIST_EDWARDS25519, SigningAlgorithm
      ED25519_SHA_512, MessageType RAW. Needs `boto3` (optional dep) + credentials.
      Provenance of the spec (verified 2026-08-16 against the official docs, not from
      memory): EdDSA support announced 2025-11-07
      (https://aws.amazon.com/about-aws/whats-new/2025/11/aws-kms-edwards-curve-digital-signature-algorithm/);
      per the key-spec reference, ED25519_SHA_512 is "NIST FIPS 186-5, Section 7.6"
      EdDSA — i.e. PureEdDSA/RFC 8032, same as every other backend here — and
      REQUIRES MessageType RAW (ED25519_PH_SHA_512/DIGEST is prehashed and NOT
      interchangeable; this module deliberately never uses it)
      (https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html).
      The unit tests use an injected client; live signatures were measured on 08/11/2026 against real AWS KMS
      (eu-central-1, boto3 and the stdlib client below; log not in this repository).
  vault:url=https://vault:8200;key=cryptovalid;mount=transit
      HashiCorp Vault Transit engine, key type ed25519. stdlib-only client
      (urllib); token from $VAULT_TOKEN. Measured 08/11/2026 against a real Vault 1.20 (dev server in a throwaway
      container, loopback): export, rotation, errors (log not in this repository).
  nethsm:url=https://nethsm.example.com;key=cryptovalid;user=operator;pass_env=NETHSM_PASS
      Nitrokey NetHSM (REST, basic-auth). Public demo nethsmdemo.nitrokey.com =
      integration bench ONLY (known credentials, reset every 8h), never custody.

Threat model (honest): these backends remove the *private key* from this process.
They do NOT protect against a compromised host that asks the HSM/KMS to sign
attacker-chosen data (use KMS policies/audit + HSM touch-policy for that), and the
file: backend keeps the old caveat entirely.
"""
from __future__ import annotations

import sys as _sys_0203
if __name__ == "__main__":   # 0.20.3: run as a command, never write the bytecode cache: CPython 3.9 and 3.11 write
    _sys_0203.dont_write_bytecode = True   # a .pyc with one raw write; cut by a file size limit, every later run died (13/10/2026)
    _L0210 = type(__loader__)   # 0.21.0: a .pyc already cut (CPython 3.9/3.11 installed one) is compiled from the source
    if _L0210.__name__ == "SourceFileLoader":   # instead of failing every later run (EOFError: marshal data too short)
        def _get_code_0210(self, fullname, _get_code=_L0210.get_code):
            try:
                return _get_code(self, fullname)
            except (EOFError, ValueError):
                path = self.get_filename(fullname)
                return self.source_to_code(self.get_data(path), path)
        _L0210.get_code = _get_code_0210
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, Optional

ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")  # RFC 8410 SPKI header


def _raw_from_spki(der_or_pem: bytes) -> bytes:
    """Extract the raw 32-byte Ed25519 public key from DER or PEM SPKI (RFC 8410)."""
    data = der_or_pem
    if b"-----BEGIN" in data:
        b64 = b"".join(l for l in data.splitlines() if b"-----" not in l)
        data = base64.b64decode(b64)
    if data.startswith(ED25519_SPKI_PREFIX) and len(data) == 44:
        return data[-32:]
    if len(data) == 32:               # already raw
        return data
    raise ValueError("not an Ed25519 SubjectPublicKeyInfo (RFC 8410)")


class FileKeyBackend:
    """Legacy backend: hex seed file. Private key IS loaded in memory (documented caveat)."""

    name = "file"

    def __init__(self, path: str):
        self._path = path
        self._cached = None

    def _sk(self):
        # cache: a single read (avoids N reads + TOCTOU halfway through a ledger)
        if self._cached is None:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            with open(self._path, encoding="utf-8") as f:
                self._cached = Ed25519PrivateKey.from_private_bytes(
                    bytes.fromhex(f.read().strip()))
        return self._cached

    def public_key_hex(self) -> str:
        from cryptography.hazmat.primitives import serialization as ser
        return self._sk().public_key().public_bytes(
            ser.Encoding.Raw, ser.PublicFormat.Raw).hex()

    def sign(self, message: bytes) -> bytes:
        return self._sk().sign(message)

    def describe(self) -> Dict:
        return {"backend": "file", "keyfile": self._path,
                "key_in_process_memory": True}


_CKR_NAMES = {0x0: "CKR_OK", 0x5: "CKR_GENERAL_ERROR", 0x6: "CKR_FUNCTION_FAILED", 0x7: "CKR_ARGUMENTS_BAD",
              0x30: "CKR_DEVICE_ERROR", 0x32: "CKR_DEVICE_REMOVED", 0x60: "CKR_KEY_HANDLE_INVALID",
              0x63: "CKR_KEY_TYPE_INCONSISTENT", 0x68: "CKR_KEY_FUNCTION_NOT_PERMITTED", 0x70: "CKR_MECHANISM_INVALID",
              0x82: "CKR_OBJECT_HANDLE_INVALID", 0x91: "CKR_OPERATION_NOT_INITIALIZED", 0xA0: "CKR_PIN_INCORRECT",
              0xA4: "CKR_PIN_LOCKED", 0xB3: "CKR_SESSION_HANDLE_INVALID", 0xE0: "CKR_TOKEN_NOT_PRESENT",
              0x100: "CKR_USER_ALREADY_LOGGED_IN", 0x101: "CKR_USER_NOT_LOGGED_IN", 0x150: "CKR_BUFFER_TOO_SMALL",
              0x190: "CKR_CRYPTOKI_NOT_INITIALIZED", 0x191: "CKR_CRYPTOKI_ALREADY_INITIALIZED"}
_CKA_CLASS, _CKA_KEY_TYPE, _CKA_LABEL = 0x0, 0x100, 0x3
_CKA_SENSITIVE, _CKA_SIGN, _CKA_EXTRACTABLE = 0x103, 0x108, 0x162
_CKO_PRIVATE_KEY, _CKK_EC_EDWARDS, _CKM_EDDSA = 3, 0x40, 0x1057
# One PKCS#11 call sequence at a time in this process: each signature runs C_Initialize ... C_Finalize with NULL init
# args, i.e. without telling the module that several threads may call it at once. Without this lock two concurrent
# sign() calls, or a sign() after a timed-out one whose thread is still inside the module, crashed the whole process
# with SIGSEGV on SoftHSM2 2.6.1 (measured 08/11/2026: 5/5 runs with 8 threads, 9/12 runs with short timeouts).
# Not covered: other code in the same process calling the same module directly.
_P11_LOCK = threading.Lock()


def _p11_sign_direct(module: str, token: str, label: str, pin: bytes, message: bytes) -> bytes:
    """Single-part C_Sign with CKM_EDDSA through the PKCS#11 module itself (ctypes, stdlib; Linux/Unix LP64 ABI).
    Why not pkcs11-tool: OpenSC 0.23 signs inputs over 1024 bytes with C_SignUpdate, and EdDSA is single-part only:
    SoftHSM2 2.6.1 answers CKR_OPERATION_NOT_INITIALIZED (measured 08/11/2026: 1024 bytes ok, 1025 refused; a SCITT
    Sig_structure is ~1 KB or more). Closed: exactly one token with the label, exactly one private key with the label,
    key type EC_EDWARDS, CKA_SIGN true, CKA_SENSITIVE true and CKA_EXTRACTABLE false — anything else is refused."""
    import ctypes
    ul = ctypes.c_ulong

    class _Attr(ctypes.Structure):
        _fields_ = [("type", ul), ("pValue", ctypes.c_void_p), ("ulValueLen", ul)]

    class _Mech(ctypes.Structure):
        _fields_ = [("mechanism", ul), ("pParameter", ctypes.c_void_p), ("ulParameterLen", ul)]

    try:
        lib = ctypes.CDLL(module)
    except OSError as e:
        raise RuntimeError(f"PKCS#11 module {module!r} cannot be loaded: {str(e)[:120]}") from None

    def ck(rv, what):
        if rv != 0:
            raise RuntimeError(f"PKCS#11 {what} failed: rv=0x{rv:x} ({_CKR_NAMES.get(rv, 'see PKCS#11 spec')})")

    for fn in ("C_Initialize", "C_Finalize", "C_GetSlotList", "C_GetTokenInfo", "C_OpenSession", "C_CloseSession",
               "C_Login", "C_Logout", "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal",
               "C_GetAttributeValue", "C_SignInit", "C_Sign"):
        getattr(lib, fn).restype = ul
    rv = lib.C_Initialize(None)
    if rv not in (0, 0x191):
        ck(rv, "C_Initialize")
    own_init = rv == 0
    session = ul(0)
    try:
        n = ul(0)
        ck(lib.C_GetSlotList(ctypes.c_ubyte(1), None, ctypes.byref(n)), "C_GetSlotList")
        slots = (ul * max(n.value, 1))()
        ck(lib.C_GetSlotList(ctypes.c_ubyte(1), slots, ctypes.byref(n)), "C_GetSlotList")
        found = []
        for i in range(n.value):
            info = ctypes.create_string_buffer(1024)       # CK_TOKEN_INFO: label is the first 32 bytes, space-padded
            ck(lib.C_GetTokenInfo(ul(slots[i]), info), "C_GetTokenInfo")
            if info.raw[:32].decode("utf-8", "replace").rstrip(" ") == token:
                found.append(slots[i])
        if len(found) != 1:
            raise RuntimeError(f"PKCS#11: {len(found)} tokens labelled {token!r} (exactly 1 required)")
        ck(lib.C_OpenSession(ul(found[0]), ul(0x4), None, None, ctypes.byref(session)), "C_OpenSession")  # SERIAL
        pin_buf = ctypes.create_string_buffer(pin, len(pin))
        try:
            ck(lib.C_Login(session, ul(1), pin_buf, ul(len(pin))), "C_Login")   # CKU_USER
        finally:
            ctypes.memset(pin_buf, 0, len(pin))   # also when the login fails (the caller's str/bytes copies remain)
        cls_v, lab = ul(_CKO_PRIVATE_KEY), label.encode()
        lab_buf = ctypes.create_string_buffer(lab, len(lab))
        tmpl = (_Attr * 2)(_Attr(_CKA_CLASS, ctypes.cast(ctypes.byref(cls_v), ctypes.c_void_p), ctypes.sizeof(ul)),
                           _Attr(_CKA_LABEL, ctypes.cast(lab_buf, ctypes.c_void_p), len(lab)))
        ck(lib.C_FindObjectsInit(session, tmpl, ul(2)), "C_FindObjectsInit")
        objs, cnt = (ul * 2)(), ul(0)
        try:
            ck(lib.C_FindObjects(session, objs, ul(2), ctypes.byref(cnt)), "C_FindObjects")
        finally:
            lib.C_FindObjectsFinal(session)
        if cnt.value != 1:
            raise RuntimeError(f"PKCS#11: {cnt.value} private keys labelled {label!r} on token {token!r} "
                               "(exactly 1 required)")
        key = ul(objs[0])
        ktype, sens, ext, sign = ul(0), ctypes.c_ubyte(0), ctypes.c_ubyte(1), ctypes.c_ubyte(0)
        attrs = (_Attr * 4)(*[_Attr(t, ctypes.cast(ctypes.byref(v), ctypes.c_void_p), ctypes.sizeof(v))
                              for t, v in ((_CKA_KEY_TYPE, ktype), (_CKA_SENSITIVE, sens),
                                           (_CKA_EXTRACTABLE, ext), (_CKA_SIGN, sign))])
        ck(lib.C_GetAttributeValue(session, key, attrs, ul(4)), "C_GetAttributeValue")
        if ktype.value != _CKK_EC_EDWARDS:
            raise RuntimeError(f"PKCS#11: key {label!r} is not an EC_EDWARDS key (type 0x{ktype.value:x})")
        if not sens.value or ext.value or not sign.value:
            raise RuntimeError(f"PKCS#11: key {label!r} refused: CKA_SENSITIVE={sens.value} "
                               f"CKA_EXTRACTABLE={ext.value} CKA_SIGN={sign.value} (required 1, 0, 1)")
        mech = _Mech(_CKM_EDDSA, None, 0)
        ck(lib.C_SignInit(session, ctypes.byref(mech), key), "C_SignInit")
        sig, sl = ctypes.create_string_buffer(64), ul(64)
        ck(lib.C_Sign(session, ctypes.c_char_p(bytes(message)), ul(len(message)), sig, ctypes.byref(sl)), "C_Sign")
        if sl.value != 64:
            raise RuntimeError(f"expected 64-byte Ed25519 signature, got {sl.value}")
        return sig.raw[:64]
    finally:
        if session.value:
            lib.C_Logout(session)
            lib.C_CloseSession(session)
        if own_init:
            lib.C_Finalize(None)


class Pkcs11Backend:
    """PKCS#11 token. Key generation and public-key read via OpenSC pkcs11-tool (subprocess); signing with a
    single-part C_Sign through the module (ctypes, see _p11_sign_direct). The private key never enters this process."""

    name = "pkcs11"

    def __init__(self, module: str, token: str, key: str, pin: str = "env:CRYPTOVALID_PIN", timeout: float = 60.0):
        if shutil.which("pkcs11-tool") is None:
            raise RuntimeError("pkcs11-tool not found (install opensc)")
        if not pin.startswith("env:"):
            raise ValueError("pin must be 'env:VARNAME' (argv PINs leak via ps)")
        if not os.environ.get(pin[4:]):
            raise RuntimeError(f"PIN environment variable {pin[4:]!r} is empty/unset")
        self._module, self._token, self._key, self._pin = module, token, key, pin
        self._timeout = timeout

    def _run(self, extra, login=False, what="call"):
        cmd = ["pkcs11-tool", "--module", self._module, "--token-label", self._token]
        if login:
            cmd += ["--login", "--pin", self._pin]      # pkcs11-tool reads env:VAR itself: the PIN is not on argv
        try:
            r = subprocess.run(cmd + extra, capture_output=True, timeout=self._timeout)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"pkcs11-tool {what}: timeout after {self._timeout} s (token {self._token!r})") from None
        except OSError as e:
            raise RuntimeError(f"pkcs11-tool {what}: cannot run ({type(e).__name__})") from None
        if r.returncode != 0:
            raise RuntimeError(f"pkcs11-tool {what} failed (token {self._token!r}, key {self._key!r}): "
                               f"{r.stderr.decode(errors='replace').strip()[:300]}")
        return r

    def _objects(self):
        """--list-objects with login, parsed into blocks {type, label, Access, Usage, ...}."""
        out = self._run(["--list-objects"], login=True, what="list-objects").stdout.decode(errors="replace")
        blocks, cur = [], None
        for line in out.splitlines():
            if line and not line.startswith(" "):
                cur = {"type": line.split(";")[0].strip()}
                blocks.append(cur)
            elif cur is not None and ":" in line:
                k, _, v = line.strip().partition(":")
                cur[k.strip()] = v.strip()
        return blocks

    def keygen(self) -> str:
        """Generate a NON-EXPORTABLE Ed25519 keypair on the token, usage sign only. Returns public key hex.
        Closed (08/11/2026): a label already on the token is refused (before, a second key with the same label was
        created and later operations picked one of them); after generation the private key must read back as
        sensitive, always sensitive, never extractable, local, usage sign and not derive — else refused."""
        if any(b.get("label") == self._key for b in self._objects()):
            raise RuntimeError(f"pkcs11: an object labelled {self._key!r} already exists on token {self._token!r}")
        self._run(["--keypairgen", "--key-type", "EC:edwards25519", "--usage-sign", "--sensitive",
                   "--label", self._key], login=True, what="keypairgen")
        priv = [b for b in self._objects() if b["type"] == "Private Key Object" and b.get("label") == self._key]
        if len(priv) != 1:
            raise RuntimeError(f"pkcs11: {len(priv)} private keys labelled {self._key!r} after keygen")
        access = {x.strip() for x in priv[0].get("Access", "").split(",")}
        usage = {x.strip() for x in priv[0].get("Usage", "").split(",")}
        # Usage: "sign" required, "derive" refused. DECRYPT/UNWRAP stay at the token default (SoftHSM2 2.6.1 sets them;
        # pkcs11-tool 0.23 has no option to clear them): no mechanism uses them on an EC_EDWARDS key (measured 08/11).
        if not {"sensitive", "always sensitive", "never extractable", "local"} <= access or "extractable" in access \
                or "sign" not in usage or "derive" in usage:
            raise RuntimeError(f"pkcs11: generated key {self._key!r} has Access={sorted(access)} Usage={sorted(usage)}")
        return self.public_key_hex()

    def public_key_hex(self) -> str:
        with tempfile.NamedTemporaryFile(suffix=".spki") as t:
            self._run(["--read-object", "--type", "pubkey",
                       "--label", self._key, "--output-file", t.name], what="read public key")
            with open(t.name, "rb") as f:
                data = f.read()
        try:
            return _raw_from_spki(data).hex()
        except (ValueError, TypeError) as e:   # binascii.Error is a ValueError
            raise RuntimeError(f"pkcs11: public key {self._key!r} is not Ed25519: {e}") from None

    def sign(self, message: bytes) -> bytes:
        import threading
        pin = os.environ.get(self._pin[4:], "")
        if not pin:
            raise RuntimeError(f"PIN environment variable {self._pin[4:]!r} is empty/unset")
        box = {}

        def work():
            if not _P11_LOCK.acquire(timeout=self._timeout):
                box["err"] = RuntimeError("another PKCS#11 signature of this process is still running (timed out?)")
                return
            try:
                box["sig"] = _p11_sign_direct(self._module, self._token, self._key, pin.encode(), bytes(message))
            except Exception as e:  # noqa: BLE001 — carried to the caller as one readable error
                box["err"] = e
            finally:
                _P11_LOCK.release()
        t = threading.Thread(target=work, daemon=True)
        t.start()
        t.join(self._timeout)
        if t.is_alive():
            raise RuntimeError(f"pkcs11 sign: timeout after {self._timeout} s (token {self._token!r})")
        if "err" in box:
            e = box["err"]
            raise RuntimeError(f"pkcs11 sign with key {self._key!r}: {e}" if isinstance(e, RuntimeError)
                               else f"pkcs11 sign with key {self._key!r}: {type(e).__name__}: {str(e)[:200]}") from None
        return box["sig"]

    def describe(self) -> Dict:
        return {"backend": "pkcs11", "module": self._module, "token": self._token,
                "key_label": self._key, "key_in_process_memory": False}


class AwsKmsBackend:
    """AWS KMS, KeySpec ECC_NIST_EDWARDS25519 (EdDSA support since 2025-11).
    SigningAlgorithm ED25519_SHA_512 requires MessageType RAW (PureEdDSA — same as the
    other backends, so verifier.py verifies these signatures unchanged)."""

    name = "awskms"

    def __init__(self, key_id: str, region: Optional[str] = None,
                 profile: Optional[str] = None, client=None):
        self._key_id = key_id
        _aws_region(region)
        if client is not None:          # test/DI hook
            self._client = client
        else:  # pragma: no cover - needs boto3 + real credentials
            try:
                import boto3
            except ImportError as e:
                raise RuntimeError("awskms backend requires 'boto3' (pip install boto3)") from e
            session = boto3.Session(profile_name=profile) if profile else boto3.Session()
            self._client = session.client("kms", region_name=region)

    def public_key_hex(self) -> str:
        try:   # 08/11/2026: boto3/botocore errors (NotFound, credentials, endpoint) = one readable RuntimeError
            r = self._client.get_public_key(KeyId=self._key_id)
            pub = _raw_from_spki(bytes(r["PublicKey"])).hex()
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"AWS KMS GetPublicKey failed for {self._key_id}: {type(e).__name__}: "
                               f"{str(e)[:200]}") from None
        self._arn = r.get("KeyId")
        return pub

    def sign(self, message: bytes) -> bytes:
        try:
            r = self._client.sign(KeyId=self._key_id, Message=message,
                                  MessageType="RAW", SigningAlgorithm="ED25519_SHA_512")
            sig = bytes(r["Signature"])
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"AWS KMS Sign failed for {self._key_id}: {type(e).__name__}: {str(e)[:200]}") from None
        if getattr(self, "_arn", None) and r.get("KeyId") and r["KeyId"] != self._arn:
            raise RuntimeError("AWS KMS signed with a different key than the one whose public key was read")
        if len(sig) != 64:
            raise RuntimeError(f"expected 64-byte Ed25519 signature, got {len(sig)}")
        return sig

    def describe(self) -> Dict:
        return {"backend": "awskms", "key_id": self._key_id,
                "signing_algorithm": "ED25519_SHA_512", "key_in_process_memory": False}


MLDSA65_SPKI_OID = bytes.fromhex("0609608648016503040312")   # 2.16.840.1.101.3.4.3.18 = id-ml-dsa-65 (RFC 9881)
MLDSA65_PK_LEN = 1952


MLDSA65_SPKI_LEN = 1974          # SEQUENCE { AlgorithmIdentifier { id-ml-dsa-65 }, BIT STRING { 0x00 || pk(1952) } } — RFC 9881


def _mldsa65_raw_from_spki(der: bytes) -> bytes:
    """GetPublicKey returns a DER SubjectPublicKeyInfo (RFC 9881: no parameters, BIT STRING with 0 unused bits); the
    raw pkEncode bytes are the last 1952. Not a general ASN.1 parser: the exact shape is checked (total length 1974,
    the id-ml-dsa-65 OID in the header, the BIT STRING unused-bits byte 0x00 right before the key) — anything else is
    refused, and sign_ledger/write_tip self-verify every signature against the extracted key anyway (fail-safe)."""
    if len(der) != MLDSA65_SPKI_LEN or MLDSA65_SPKI_OID not in der[:32] or der[-MLDSA65_PK_LEN - 1] != 0:
        raise RuntimeError("the AWS KMS key is not an ML-DSA-65 SubjectPublicKeyInfo (use KeySpec ML_DSA_65)")
    return der[-MLDSA65_PK_LEN:]


class AwsKmsMlDsaBackend:
    """AWS KMS, KeySpec ML_DSA_65, SigningAlgorithm ML_DSA_SHAKE_256, MessageType RAW (messages <= 4 KB; ours are
    64 bytes for an entry and < 300 for a tip). RAW = pure ML-DSA with the EMPTY context: measured 16/09/2026
    (eu-central-1) — a ledger and a tip signed here verified with `cryptography`, Go `crypto/mldsa` and the JDK 27
    verifier (JS checked the Ed25519 layer only). 08/11/2026: `external_mu=True` (opt-in) signs through MessageType
    EXTERNAL_MU (mu computed here, FIPS 204 §6.2, empty context) — measured live: a 4872-byte SCITT policy signed by
    KMS verified with `cryptography` (RAW refuses it: > 4096). AWS KMS runs its keys in FIPS 140-3 validated HSMs; whether the
    ML-DSA operations fall inside the validated boundary is AWS's statement to check, not measured here. FIPS 204
    allows hedged or deterministic signing: nothing may compare signature bytes. `EXTERNAL_MU` (client-computed mu,
    FIPS 204 §6.2: needed above 4 KB, and it COULD carry a context) is documented by AWS; the ledger/tip profile does
    not use it (default external_mu=False), only callers that opt in. The key MUST be dedicated to this profile (no context = no cross-application guard)
    and its KMS key policy restricted to the signing principal. Sign responses are checked for the same KeyId ARN
    as GetPublicKey (an alias re-pointed in between would otherwise sign with another key) and for the algorithm."""

    name = "awskms-mldsa65"

    def __init__(self, key_id: str, region: Optional[str] = None, profile: Optional[str] = None, client=None,
                 external_mu: bool = False):
        self._key_id = key_id
        if type(external_mu) is not bool:
            raise ValueError("external_mu must be a bool")
        self._external_mu = external_mu
        _aws_region(region)
        if client is not None:          # test/DI hook
            self._client = client
        else:  # pragma: no cover - needs boto3 + real credentials
            try:
                import boto3
            except ImportError as e:
                raise RuntimeError("awskms backend requires 'boto3' (pip install boto3)") from e
            session = boto3.Session(profile_name=profile) if profile else boto3.Session()
            self._client = session.client("kms", region_name=region)
        import base64 as _b64
        try:
            r = self._client.get_public_key(KeyId=key_id)
        except Exception as e:  # noqa: BLE001 — boto3 ClientError / network: one readable error, not a raw stack
            raise RuntimeError(f"AWS KMS GetPublicKey failed for {key_id}: {type(e).__name__}: {str(e)[:200]}") from e
        self.key_arn = str(r.get("KeyId") or key_id)
        self.public_key_b64 = _b64.b64encode(_mldsa65_raw_from_spki(bytes(r["PublicKey"]))).decode()

    def sign(self, message: bytes) -> bytes:
        if not isinstance(message, (bytes, bytearray)):
            raise TypeError("message must be bytes")
        if len(message) > 4096 and not self._external_mu:
            raise ValueError("AWS KMS RAW signing takes at most 4096 bytes (use EXTERNAL_MU for more)")
        if self._external_mu:
            # FIPS 204 Algorithm 7 line 6 with Algorithm 2 (pure ML-DSA, empty context): tr = H(pk, 64),
            # M' = 0x00 || 0x00 || M, mu = H(tr || M', 64), H = SHAKE256. The signature is a signature on M itself:
            # any verifier checks it against M with the empty context (verified after signing by the callers).
            import hashlib
            import base64 as _b64
            tr = hashlib.shake_256(_b64.b64decode(self.public_key_b64)).digest(64)
            body, mtype = hashlib.shake_256(tr + b"\x00\x00" + bytes(message)).digest(64), "EXTERNAL_MU"
        else:
            body, mtype = bytes(message), "RAW"
        try:
            r = self._client.sign(KeyId=self._key_id, Message=body, MessageType=mtype, SigningAlgorithm="ML_DSA_SHAKE_256")
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"AWS KMS Sign failed for {self._key_id}: {type(e).__name__}: {str(e)[:200]}") from e
        if r.get("SigningAlgorithm", "ML_DSA_SHAKE_256") != "ML_DSA_SHAKE_256":
            raise RuntimeError(f"AWS KMS signed with {r.get('SigningAlgorithm')}, not ML_DSA_SHAKE_256")
        if r.get("KeyId") and r["KeyId"] != self.key_arn:
            raise RuntimeError("AWS KMS signed with a different key than the one whose public key was read (alias re-pointed?)")
        sig = bytes(r["Signature"])
        if len(sig) != 3309:
            raise RuntimeError(f"expected a 3309-byte ML-DSA-65 signature, got {len(sig)}")
        return sig

    def describe(self) -> Dict:
        return {"pq_backend": "awskms", "key_id": self._key_id, "key_spec": "ML_DSA_65",
                "signing_algorithm": "ML_DSA_SHAKE_256",
                "message_type": "EXTERNAL_MU" if self._external_mu else "RAW", "key_in_process_memory": False}


# --------------------------------------------------------------------------- #
#  AWS KMS via HTTP + SigV4, NO SDK (added 2026-08-29)                          #
#  Same key spec/algorithm as AwsKmsBackend, but stdlib-only (no boto3). The    #
#  SigV4 signing-key derivation is validated against AWS's official test vector #
#  and the live round-trip was verified end-to-end against real AWS KMS.        #
# --------------------------------------------------------------------------- #
def _sigv4_signing_key(secret_key: str, datestamp: str, region: str, service: str) -> bytes:
    import hashlib
    import hmac

    def _h(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    k_date = _h(("AWS4" + secret_key).encode("utf-8"), datestamp)
    k_region = _h(k_date, region)
    k_service = _h(k_region, service)
    return _h(k_service, "aws4_request")


def _sigv4_headers(host: str, region: str, service: str, target: str, body: bytes,
                   access_key: str, secret_key: str, session_token: Optional[str],
                   amzdate: str, datestamp: str) -> Dict[str, str]:
    import hashlib
    import hmac

    algorithm = "AWS4-HMAC-SHA256"
    ctype = "application/x-amz-json-1.1"
    hdrs = {"content-type": ctype, "host": host, "x-amz-date": amzdate, "x-amz-target": target}
    if session_token:
        hdrs["x-amz-security-token"] = session_token
    signed_headers = ";".join(sorted(hdrs))
    canonical_headers = "".join(f"{k}:{hdrs[k]}\n" for k in sorted(hdrs))
    payload_hash = hashlib.sha256(body).hexdigest()
    canonical_request = f"POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    credential_scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = (f"{algorithm}\n{amzdate}\n{credential_scope}\n"
                      f"{hashlib.sha256(canonical_request.encode()).hexdigest()}")
    signing_key = _sigv4_signing_key(secret_key, datestamp, region, service)
    signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    authorization = (f"{algorithm} Credential={access_key}/{credential_scope}, "
                     f"SignedHeaders={signed_headers}, Signature={signature}")
    out = {"Content-Type": ctype, "X-Amz-Date": amzdate, "X-Amz-Target": target,
           "Authorization": authorization}
    if session_token:
        out["X-Amz-Security-Token"] = session_token
    return out


class AwsKmsHttpBackend:
    """AWS KMS via HTTP + SigV4, stdlib-only (NO boto3). Same KeySpec
    ECC_NIST_EDWARDS25519 / SigningAlgorithm ED25519_SHA_512 / MessageType RAW as
    AwsKmsBackend, so verifier.py verifies these signatures unchanged. Credentials
    come from the environment (never constructor literals — avoids source leaks)."""

    name = "awskms-http"

    def __init__(self, key_id: str, region: str,
                 access_key_env: str = "AWS_ACCESS_KEY_ID",
                 secret_key_env: str = "AWS_SECRET_ACCESS_KEY",
                 session_token_env: str = "AWS_SESSION_TOKEN",
                 endpoint: Optional[str] = None):
        if not region:
            raise ValueError("awskms-http backend requires an explicit region")
        _aws_region(region)   # closed form here too: the region becomes the host the SigV4-signed requests go to
        self._key_id = key_id
        self._region = region
        self._ak = os.environ.get(access_key_env, "")
        self._sk = os.environ.get(secret_key_env, "")
        self._st = os.environ.get(session_token_env) or None
        if not (self._ak and self._sk):
            raise RuntimeError("awskms-http backend: AWS credentials not in environment "
                               f"({access_key_env}/{secret_key_env})")
        self._host = f"kms.{region}.amazonaws.com"
        if endpoint:
            # security (asymmetry fix, 2026-08-29): a custom endpoint must be https OR a
            # loopback host. An http/remote override would leak the session token in the
            # SigV4 headers and let the signed requests (host pinned to kms.{region}) be
            # replayed against real AWS — the same guard VaultTransitBackend already has.
            u = urllib.parse.urlsplit(endpoint)
            if u.scheme != "https" and (u.hostname or "").lower() not in (
                    "127.0.0.1", "localhost", "::1"):
                raise ValueError("awskms-http endpoint must be https (or a loopback host "
                                 "for testing)")
            self._endpoint = endpoint
        else:
            self._endpoint = f"https://{self._host}"

    def _call(self, target: str, payload: Dict) -> Dict:
        import datetime
        import json
        body = json.dumps(payload).encode()
        now = datetime.datetime.now(datetime.timezone.utc)
        amzdate = now.strftime("%Y%m%dT%H%M%SZ")
        datestamp = now.strftime("%Y%m%d")
        headers = _sigv4_headers(self._host, self._region, "kms", target, body,
                                 self._ak, self._sk, self._st, amzdate, datestamp)
        req = urllib.request.Request(self._endpoint.rstrip("/") + "/", data=body,
                                     headers=headers, method="POST")
        op = target.rsplit(".", 1)[-1]
        try:   # 08/11/2026: HTTP/network/answer errors = one readable RuntimeError (no credentials in the text)
            with urllib.request.urlopen(req, timeout=20) as r:  # nosec B310 - fixed AWS endpoint
                return json.load(r)
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"AWS KMS {op} HTTP {e.code} for {self._key_id}: {_http_error_text(e)}") from None
        except urllib.error.URLError as e:
            raise RuntimeError(f"AWS KMS {op}: {self._endpoint} unreachable: {str(e.reason)[:150]}") from None
        except (OSError, ValueError) as e:
            raise RuntimeError(f"AWS KMS {op}: {type(e).__name__}: {str(e)[:150]}") from None

    def public_key_hex(self) -> str:
        r = self._call("TrentService.GetPublicKey", {"KeyId": self._key_id})
        try:
            pub = _raw_from_spki(base64.b64decode(r["PublicKey"])).hex()
        except (KeyError, TypeError, ValueError) as e:
            raise RuntimeError(f"AWS KMS GetPublicKey: not an Ed25519 key ({type(e).__name__}: {e})") from None
        self._arn = r.get("KeyId")
        return pub

    def sign(self, message: bytes) -> bytes:
        r = self._call("TrentService.Sign", {
            "KeyId": self._key_id, "Message": base64.b64encode(message).decode(),
            "MessageType": "RAW", "SigningAlgorithm": "ED25519_SHA_512"})
        try:
            sig = base64.b64decode(r["Signature"])
        except (KeyError, TypeError, ValueError) as e:
            raise RuntimeError(f"AWS KMS Sign: answer without a signature ({type(e).__name__})") from None
        if getattr(self, "_arn", None) and r.get("KeyId") and r["KeyId"] != self._arn:
            raise RuntimeError("AWS KMS signed with a different key than the one whose public key was read")
        if len(sig) != 64:
            raise RuntimeError(f"expected 64-byte Ed25519 signature, got {len(sig)}")
        return sig

    def describe(self) -> Dict:
        return {"backend": "awskms-http", "key_id": self._key_id,
                "signing_algorithm": "ED25519_SHA_512",
                "key_in_process_memory": False, "sdk": "none (stdlib SigV4)"}


def _http_error_text(e) -> str:
    """Short reason from an HTTP error body (Vault {"errors": [...]}, AWS {"__type", "message"}); never the request."""
    try:
        body = json.loads(e.read().decode("utf-8", "replace") or "{}")
    except Exception:  # noqa: BLE001 — a body that is not JSON: only the status is reported
        return ""
    if isinstance(body, dict):
        if isinstance(body.get("errors"), list):
            return "; ".join(str(x) for x in body["errors"])[:200]
        return " ".join(str(body.get(k, "")) for k in ("__type", "message", "Message")).strip()[:200]
    return ""


class VaultTransitBackend:
    """HashiCorp Vault Transit engine, key type ed25519. stdlib-only (urllib).
    Token from $VAULT_TOKEN (never a constructor literal — avoids source-code leaks).
    08/11/2026: every failure is one RuntimeError with the reason (HTTP status + Vault's errors, unreachable, timeout,
    malformed answer); the key version is FIXED when the public key is read and every signature is requested with
    that `key_version` and checked against the `vault:vN:` prefix of the answer — a rotation between reading the
    public key and signing no longer signs with a key other than the declared one (measured with a real Vault 1.20)."""

    name = "vault"
    _SIG_RE = re.compile(r"^vault:v(\d+):(.+)$")

    def __init__(self, url: str, key: str, mount: str = "transit",
                 token_env: str = "VAULT_TOKEN", timeout: float = 30.0):
        token = os.environ.get(token_env, "")
        if not token:
            raise RuntimeError(f"Vault token env var {token_env!r} is empty/unset")
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
        if url.startswith("http://") and host not in ("127.0.0.1", "localhost", "::1"):
            raise RuntimeError("refusing plain http:// to a non-loopback Vault: "
                               "the token would travel in cleartext (use https)")
        if not url.startswith(("http://", "https://")):
            raise ValueError("Vault url must start with https:// (or http:// to a loopback host)")
        self._url, self._key, self._mount, self._token = url.rstrip("/"), key, mount, token
        self._timeout, self._version = timeout, None

    def _req(self, method: str, path: str, body: Optional[Dict] = None) -> Dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"{self._url}/v1/{path}", data=data, method=method,
                                     headers={"X-Vault-Token": self._token,
                                              "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as r:  # nosec B310 - scheme checked in __init__
                raw = r.read()
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"Vault HTTP {e.code} on {method} {path}: {_http_error_text(e)}") from None
        except urllib.error.URLError as e:
            raise RuntimeError(f"Vault unreachable at {self._url}: {str(e.reason)[:150]}") from None
        except (OSError, ValueError) as e:   # socket timeout (TimeoutError), reset, bad URL
            raise RuntimeError(f"Vault unreachable at {self._url}: {type(e).__name__}: {str(e)[:150]}") from None
        try:
            return json.loads(raw.decode())
        except ValueError:
            raise RuntimeError(f"Vault answered {method} {path} with something that is not JSON") from None

    def public_key_hex(self) -> str:
        try:
            d = self._req("GET", f"{self._mount}/keys/{self._key}")["data"]
            latest = d["latest_version"]
            if type(latest) is not int or latest < 1:
                raise RuntimeError(f"Vault key {self._key!r}: latest_version {latest!r} is not a positive integer")
            pk_b64 = d["keys"][str(latest)]["public_key"]
            pub = _raw_from_spki(base64.b64decode(pk_b64)).hex()
        except (KeyError, TypeError, ValueError) as e:
            raise RuntimeError(f"Vault key {self._key!r}: answer without an Ed25519 public key "
                               f"({type(e).__name__}: {str(e)[:100]})") from None
        self._version = latest
        return pub

    def sign(self, message: bytes) -> bytes:
        if self._version is None:
            self.public_key_hex()
        d = self._req("POST", f"{self._mount}/sign/{self._key}",
                      {"input": base64.b64encode(message).decode(), "key_version": self._version})
        try:
            m = self._SIG_RE.match(d["data"]["signature"])
        except (KeyError, TypeError):
            m = None
        if not m:
            raise RuntimeError("unexpected Vault signature format")
        if int(m.group(1)) != self._version:
            raise RuntimeError(f"Vault signed with key version {m.group(1)}, not the version {self._version} "
                               "whose public key was read")
        try:
            sig = base64.b64decode(m.group(2), validate=True)
        except ValueError:
            raise RuntimeError("Vault signature is not base64") from None
        if len(sig) != 64:
            raise RuntimeError(f"expected 64-byte Ed25519 signature, got {len(sig)}")
        return sig

    def describe(self) -> Dict:
        return {"backend": "vault", "url": self._url, "key": self._key,
                "mount": self._mount, "key_version": self._version, "key_in_process_memory": False}


# 08/11/2026 (tests/test_kms_reali.py): the URI is a CLOSED form. Before, an unknown key (e.g. «pim=» for «pin=») was
# ignored in silence and the default was used; a repeated key let the last one win. Now: unknown, repeated, empty or
# malformed = ValueError naming it.
_ALLOWED_KEYS = {"pkcs11": frozenset({"module", "token", "key", "pin", "timeout"}),
                 "awskms": frozenset({"key_id", "region", "profile"}),
                 "awskms-http": frozenset({"key_id", "region", "endpoint"}),
                 "awskms-mldsa65": frozenset({"key_id", "region", "profile", "mu"}),
                 "vault": frozenset({"url", "key", "mount", "token_env", "timeout"}),
                 "nethsm": frozenset({"url", "key", "user", "pass_env"})}
_AWS_REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-[0-9]{1,2}$")   # e.g. eu-central-1, us-gov-west-1 (goes into a hostname)


def _parse_kv(spec: str, allowed=None) -> Dict[str, str]:
    """key=value;key=value. Every segment must be key=value with a non-empty key and value, no key twice; with
    `allowed`, a key outside it is refused. Limit (documented): values cannot contain ';' (no escaping)."""
    out = {}
    for part in spec.split(";"):
        k, sep, v = part.partition("=")
        k, v = k.strip(), v.strip()
        if not sep or not k:
            raise ValueError(f"backend URI: segment {part[:40]!r} is not key=value")
        if not v:
            raise ValueError(f"backend URI: empty value for {k!r}")
        if k in out:
            raise ValueError(f"backend URI: key {k!r} given twice")
        if allowed is not None and k not in allowed:
            raise ValueError(f"backend URI: unknown key {k!r} (allowed: {', '.join(sorted(allowed))})")
        out[k] = v
    return out


def _timeout(kv: Dict[str, str], default: float) -> float:
    """timeout= in seconds, a finite number in (0, 600]; anything else = ValueError."""
    if "timeout" not in kv:
        return default
    try:
        if not re.fullmatch(r"[0-9]+(\.[0-9]+)?", kv["timeout"]):   # ASCII decimal only (float() takes «1_0», «١٠», «nan»)
            raise ValueError
        t = float(kv["timeout"])
    except ValueError:
        raise ValueError(f"backend URI: timeout {kv['timeout'][:20]!r} is not a number") from None
    if not (0 < t <= 600):   # also refuses nan and inf
        raise ValueError("backend URI: timeout must be in (0, 600] seconds")
    return t


def _aws_region(region):
    if region is not None and not _AWS_REGION_RE.fullmatch(region):
        raise ValueError(f"AWS region {region[:40]!r} is not of the form xx-name-N (it becomes part of a hostname)")
    return region


class NetHsmBackend:
    """Nitrokey NetHSM via REST API (stdlib urllib, basic-auth; passphrase from env,
    never a literal in the code). The key lives in the network HSM: never in the process.
    Honest note: the public DEMO instance (nethsmdemo.nitrokey.com, known credentials,
    reset every 8 hours) is an INTEGRATION BENCH, not custody — custody needs
    your own NetHSM (or the operator with a secret passphrase)."""

    name = "nethsm"

    def __init__(self, url: str, key: str, user: str,
                 pass_env: str = "NETHSM_PASS"):
        passphrase = os.environ.get(pass_env, "")
        if not passphrase:
            raise RuntimeError(f"NetHSM passphrase env var {pass_env!r} is empty/unset")
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
        if url.startswith("http://") and host not in ("127.0.0.1", "localhost", "::1"):
            raise RuntimeError("refusing plain http:// to a non-loopback NetHSM: "
                               "credentials would travel in cleartext (use https)")
        self._url, self._key = url.rstrip("/"), key
        self._auth = base64.b64encode(f"{user}:{passphrase}".encode()).decode()

    def _req(self, method: str, path: str, body: Optional[Dict] = None) -> Dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"{self._url}/api/v1/{path}", data=data,
                                     method=method,
                                     headers={"Authorization": f"Basic {self._auth}",
                                              "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            return json.loads(raw.decode()) if raw else {}

    def keygen(self) -> str:
        """Generate the Ed25519 key ON the HSM (requires the Administrator role)."""
        self._req("POST", "keys/generate",
                  {"mechanisms": ["EdDSA_Signature"], "type": "Curve25519",
                   "id": self._key})
        return self.public_key_hex()

    def public_key_hex(self) -> str:
        d = self._req("GET", f"keys/{self._key}")
        return _raw_from_spki(base64.b64decode(d["public"]["data"])).hex()

    def sign(self, message: bytes) -> bytes:
        d = self._req("POST", f"keys/{self._key}/sign",
                      {"mode": "EdDSA",
                       "message": base64.b64encode(message).decode()})
        sig = base64.b64decode(d["signature"])
        if len(sig) != 64:
            raise RuntimeError(f"expected 64-byte Ed25519 signature, got {len(sig)}")
        return sig

    def describe(self) -> Dict:
        return {"backend": "nethsm", "url": self._url, "key": self._key,
                "key_in_process_memory": False}


_REQUIRED_KEYS = {"pkcs11": ("module", "token", "key"),
                  "awskms": ("key_id",), "vault": ("url", "key"),
                  "nethsm": ("url", "key", "user")}


def backend_from_uri(uri: str, **extra):
    """Build a signing backend from a URI-style selector (see module docstring).
    Documented limit: values cannot contain ';' or '=' (no escaping)."""
    scheme, _, rest = uri.partition(":")
    if scheme == "file":
        return FileKeyBackend(rest)
    if scheme not in _ALLOWED_KEYS or scheme == "awskms-mldsa65":
        raise ValueError(f"unknown backend scheme {scheme!r} "
                         "(expected file: | pkcs11: | awskms: | awskms-http: | vault: | nethsm:)")
    kv = _parse_kv(rest, _ALLOWED_KEYS[scheme])
    missing = [k for k in _REQUIRED_KEYS.get(scheme, ()) if not kv.get(k)]
    if missing:
        raise ValueError(f"{scheme}: backend URI is missing required key(s): "
                         f"{', '.join(missing)} (got: {sorted(kv) or 'nothing'})")
    if scheme == "pkcs11":
        return Pkcs11Backend(module=kv["module"], token=kv["token"], key=kv["key"],
                             pin=kv.get("pin", "env:CRYPTOVALID_PIN"), timeout=_timeout(kv, 60.0))
    if scheme == "awskms":
        return AwsKmsBackend(key_id=kv["key_id"], region=_aws_region(kv.get("region")),
                             profile=kv.get("profile"), **extra)
    if scheme == "awskms-http":
        _missing = [k for k in ("key_id", "region") if not kv.get(k)]
        if _missing:
            raise ValueError(f"awskms-http: backend URI is missing required key(s): "
                             f"{', '.join(_missing)}")
        return AwsKmsHttpBackend(key_id=kv["key_id"], region=_aws_region(kv["region"]),
                                 endpoint=kv.get("endpoint"))
    if scheme == "vault":
        return VaultTransitBackend(url=kv["url"], key=kv["key"],
                                   mount=kv.get("mount", "transit"),
                                   token_env=kv.get("token_env", "VAULT_TOKEN"), timeout=_timeout(kv, 30.0))
    if scheme == "nethsm":
        return NetHsmBackend(url=kv["url"], key=kv["key"], user=kv["user"],
                             pass_env=kv.get("pass_env", "NETHSM_PASS"))
    raise AssertionError(scheme)   # unreachable: every scheme of _ALLOWED_KEYS is handled above


try:   # 0.20.3: the one writer of every command (ledger/standalone.py): an outcome is written whole, or exit 74
    from pq_scitt.ledger.standalone import Parser, emit, receipt_cli, say
except ImportError:   # origin branch: the same import here
    from pq_scitt.ledger.standalone import Parser, emit, receipt_cli, say


@receipt_cli
def main(argv=None) -> int:  # pragma: no cover - thin CLI
    import argparse
    p = Parser(prog="pq-scitt kms",
                                description="KMS/HSM signing backends for pq-scitt.")
    sub = p.add_subparsers(dest="cmd")
    for c in ("pubkey", "keygen-hsm", "selftest"):
        s = sub.add_parser(c); s.add_argument("--backend", required=True)
    a = p.parse_args(sys.argv[1:] if argv is None else argv)
    if not a.cmd:
        p.print_help(); return 2
    try:   # 08/11/2026: a backend that refuses (PIN, token, network, timeout, URI) = one line, exit 1, no traceback
        return _main_cmd(a)
    except (RuntimeError, ValueError, OSError) as e:
        if type(e).__name__ in ("ReceiptNotWritten", "OutputNotWritten"):
            raise   # standalone.receipt_cli turns these into exit 74
        say(f"REFUSED {type(e).__name__}: {str(e)[:300]}\n")
        return 1


def _main_cmd(a) -> int:
    be = backend_from_uri(a.backend)
    if a.cmd == "keygen-hsm":
        if not isinstance(be, Pkcs11Backend):
            say("keygen-hsm only applies to pkcs11 backends\n"); return 2
        emit(json.dumps({"public_key_hex": be.keygen(), **be.describe()}, indent=1)); return 0
    if a.cmd == "pubkey":
        emit(json.dumps({"public_key_hex": be.public_key_hex(), **be.describe()}, indent=1)); return 0
    if a.cmd == "selftest":
        msg = b"cryptovalid-kms-selftest"
        sig = be.sign(msg)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(be.public_key_hex())).verify(sig, msg)
        except InvalidSignature:
            raise RuntimeError("the backend signature does not verify with the backend public key") from None
        emit(json.dumps({"selftest": "ok", **be.describe()}, indent=1)); return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
