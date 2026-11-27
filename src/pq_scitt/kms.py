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
import subprocess
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, Optional

from pq_scitt._nucleo.programs import which_absolute   # omega-nucleo-comune 0.1.0 (NOTICE)

ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")  # RFC 8410 SPKI header

# 0.1.2: the URL of a backend (vault url=, nethsm url=, awskms-http endpoint=) is written by `describe()` into what
# `pq-scitt kms` prints, and was repeated by the errors. It MUST be http(s), a host, an optional port and an optional
# path (printed by describe()), no query or fragment (the API path is appended after the URL: with either, no request
# reached the API), no user information (RFC 3986 section 3.2.1: "user:password" in the userinfo "is deprecated"; applications "should reject the
# storage of such data in unencrypted form"), printable ASCII, no space or backslash. Any other is a ValueError that does
# not repeat it.
_URL = re.compile(r'[Hh][Tt][Tt][Pp][Ss]?://(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._~-]+)(?::[0-9]{0,5})?(?:/[!"$-/0->@-\[\]-~]*)?')
_LOOPBACK = ("127.0.0.1", "localhost", "::1")


def _backend_url(url, what: str, https_or_loopback: bool = True) -> str:
    """The URL of a backend, checked as above; with https_or_loopback, http:// only to a loopback host."""
    rule = (f"{what}: the URL must be http:// or https:// and a host, with an optional port, no user information "
            "(user:password@), ASCII and without spaces: it is not repeated here")
    if not isinstance(url, str) or len(url) > 2048 or not _URL.fullmatch(url):
        raise ValueError(rule)
    try:
        u = urllib.parse.urlsplit(url)
        u.port                                  # a port past 65535 is a ValueError here, not at the network
    except ValueError:
        raise ValueError(rule) from None
    # urlsplit gives the scheme in lower case
    if https_or_loopback and u.scheme == "http" and (u.hostname or "").lower() not in _LOOPBACK:
        raise ValueError(f"{what}: plain http:// only to a loopback host: credentials would travel in cleartext "
                         "(use https)")
    return url


def _net_reason(e: BaseException) -> str:
    """0.1.2: what an error says of a service that could not be asked: the kinds of the errors and the errno, never
    their text, which can carry the URL or what a library made of it."""
    r = getattr(e, "reason", None) if isinstance(e, urllib.error.URLError) else None
    if isinstance(r, BaseException):
        e = r
        pre = "URLError: "
    else:
        pre = ""
    n = getattr(e, "errno", None)
    return pre + type(e).__name__ + (f" [Errno {n}]" if isinstance(n, int) else "")


MAX_RISPOSTA = 1 << 20   # 0.1.2: the answer of a KMS/HSM service, at most 1 MiB (it was read whole)


def _risposta(r) -> bytes:
    from pq_scitt.strict_json import leggi_a_pezzi
    dati = leggi_a_pezzi(r, MAX_RISPOSTA)
    if len(dati) > MAX_RISPOSTA:
        raise ValueError("an answer longer than %d bytes" % MAX_RISPOSTA)
    return dati


# 0.1.2: the name of an environment variable is not repeated either: the secret itself may have been put where its name goes
_ENV_UNSET = "the environment variable of the %s is empty/unset (its name is not repeated here)"


class _SameOrigin(urllib.request.HTTPRedirectHandler):
    """0.1.2: a redirect is followed only to the same scheme, host and port. urllib copies every header of the request
    (X-Vault-Token, Authorization, the SigV4 headers) to the address a redirect names, plain http included: the
    credential would leave for a place the user never named."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        a, b = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(newurl)
        try:
            same = (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)
        except ValueError:
            same = False
        if not same:
            return None     # urllib then raises the HTTPError of the 3xx answer: the caller reports its status
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _apri(req, timeout):
    """urlopen for the three HTTP backends: no proxy handling changed, redirects by _SameOrigin."""
    return urllib.request.build_opener(_SameOrigin).open(req, timeout=timeout)


def _nameable(s) -> str:
    """0.1.2: a name an error repeats; one longer than 32 characters could be a secret put where a name goes."""
    return repr(s) if isinstance(s, str) and len(s) <= 32 else f"(a name of {len(s)} characters, not repeated)"


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
            from pq_scitt.strict_json import leggi_file
            # regular file, at most 64 KiB, opened without blocking (a FIFO blocked, /dev/zero exhausted the memory)
            try:   # 0.1.2: no message repeats a byte of the key file (a decoding error named one)
                seed = bytes.fromhex(leggi_file(self._path, 64 * 1024).decode("ascii").strip())
            except ValueError:
                raise ValueError("file: the key file is not one 32-byte hex line") from None
            self._cached = Ed25519PrivateKey.from_private_bytes(seed)
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
_CKO_PUBLIC_KEY, _CKA_EC_PARAMS, _CKA_EC_POINT = 2, 0x180, 0x181
# CKA_EC_PARAMS of an Ed25519 key: the OID 1.3.101.112 or the PrintableString "edwards25519" (PKCS#11 3.0 §2.3.10)
_ED25519_PARAMS = (bytes.fromhex("06032b6570"), b"\x13\x0cedwards25519")


def _ed25519_da_ec_point(punto: bytes, parametri: bytes) -> bytes:
    """The 32 raw bytes of an Ed25519 public key from CKA_EC_POINT, closed: the parameters must name Ed25519; the
    point is either the DER OCTET STRING of PKCS#11 2.40/3.0 (04 20 + 32 bytes) or the raw 32 bytes of PKCS#11 3.1.
    Anything else = ValueError."""
    if bytes(parametri) not in _ED25519_PARAMS:
        raise ValueError("CKA_EC_PARAMS is not Ed25519 (%s)" % bytes(parametri)[:20].hex())
    punto = bytes(punto)
    if len(punto) == 34 and punto[:2] == b"\x04\x20":
        return punto[2:]
    if len(punto) == 32:
        return punto
    raise ValueError("CKA_EC_POINT of %d bytes is neither 04 20 + 32 bytes nor 32 raw bytes" % len(punto))


def _p11_carica(module: str):
    """ctypes.CDLL of a PKCS#11 module. Windows (Python >= 3.8 does not search PATH for the dependencies of a DLL):
    the dependencies are found in the module's own folder (ctypes loads a full path with
    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR) or in the folders listed in PQ_PKCS11_DLL_DIRS (os.pathsep-separated)."""
    import ctypes
    if os.name == "nt":
        for d in filter(None, os.environ.get("PQ_PKCS11_DLL_DIRS", "").split(os.pathsep)):
            os.add_dll_directory(d)
    try:
        return ctypes.CDLL(module)
    except OSError as e:
        raise RuntimeError(f"PKCS#11 module {module!r} cannot be loaded: {str(e)[:160]}") from None


def _p11_strutture():
    """CK_ATTRIBUTE and CK_MECHANISM for ctypes. PKCS#11 2.40 §2.1 (pkcs11.h): on Windows the structures are packed to
    1 byte (#pragma pack(1)); CK_ULONG is an unsigned long there too (32 bits on Windows, 64 on LP64 Unix)."""
    import ctypes
    ul = ctypes.c_ulong

    class _Attr(ctypes.Structure):
        if os.name == "nt":
            _pack_ = 1
        _fields_ = [("type", ul), ("pValue", ctypes.c_void_p), ("ulValueLen", ul)]

    class _Mech(ctypes.Structure):
        if os.name == "nt":
            _pack_ = 1
        _fields_ = [("mechanism", ul), ("pParameter", ctypes.c_void_p), ("ulParameterLen", ul)]
    return _Attr, _Mech
# One PKCS#11 call sequence at a time in this process: each signature runs C_Initialize ... C_Finalize with NULL init
# args, i.e. without telling the module that several threads may call it at once. Without this lock two concurrent
# sign() calls, or a sign() after a timed-out one whose thread is still inside the module, crashed the whole process
# with SIGSEGV on SoftHSM2 2.6.1 (measured 08/11/2026: 5/5 runs with 8 threads, 9/12 runs with short timeouts).
# Not covered: other code in the same process calling the same module directly.
_P11_LOCK = threading.Lock()


def _p11_sign_direct(module: str, token: str, label: str, pin: bytes, message: bytes) -> bytes:
    """Single-part C_Sign with CKM_EDDSA through the PKCS#11 module itself (ctypes, stdlib; LP64 Unix and Windows).
    Why not pkcs11-tool: OpenSC 0.23 signs inputs over 1024 bytes with C_SignUpdate, and EdDSA is single-part only:
    SoftHSM2 2.6.1 answers CKR_OPERATION_NOT_INITIALIZED (measured 08/11/2026: 1024 bytes ok, 1025 refused; a SCITT
    Sig_structure is ~1 KB or more). Closed: exactly one token with the label, exactly one private key with the label,
    key type EC_EDWARDS, CKA_SIGN true, CKA_SENSITIVE true and CKA_EXTRACTABLE false — anything else is refused."""
    import ctypes
    ul = ctypes.c_ulong
    _Attr, _Mech = _p11_strutture()

    lib = _p11_carica(module)

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


def _p11_public_key(module: str, token: str, label: str) -> bytes:
    """The Ed25519 public key labelled `label`, read through the module (ctypes, no login: a public object). Closed:
    exactly one token with the label, exactly one public key with the label, key type EC_EDWARDS, Ed25519 parameters
    and point (_ed25519_da_ec_point). 0.1.1: replaces `pkcs11-tool --read-object --type pubkey --output-file`, which
    failed in CI run 45344690063 on Windows (an open NamedTemporaryFile cannot be opened by another process) and on
    macOS (OpenSC of Homebrew refused the EC_POINT of SoftHSM2 of Homebrew)."""
    import ctypes
    ul = ctypes.c_ulong
    _Attr, _ = _p11_strutture()
    lib = _p11_carica(module)

    def ck(rv, what):
        if rv != 0:
            raise RuntimeError(f"PKCS#11 {what} failed: rv=0x{rv:x} ({_CKR_NAMES.get(rv, 'see PKCS#11 spec')})")

    for fn in ("C_Initialize", "C_Finalize", "C_GetSlotList", "C_GetTokenInfo", "C_OpenSession", "C_CloseSession",
               "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal", "C_GetAttributeValue"):
        getattr(lib, fn).restype = ul
    if not _P11_LOCK.acquire(timeout=60):   # a timed-out signature may still be inside the module
        raise RuntimeError("another PKCS#11 call of this process is still running (timed out?)")
    try:
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
                info = ctypes.create_string_buffer(1024)   # CK_TOKEN_INFO: label is the first 32 bytes, space-padded
                ck(lib.C_GetTokenInfo(ul(slots[i]), info), "C_GetTokenInfo")
                if info.raw[:32].decode("utf-8", "replace").rstrip(" ") == token:
                    found.append(slots[i])
            if len(found) != 1:
                raise RuntimeError(f"PKCS#11: {len(found)} tokens labelled {token!r} (exactly 1 required)")
            ck(lib.C_OpenSession(ul(found[0]), ul(0x4), None, None, ctypes.byref(session)), "C_OpenSession")
            cls_v, lab = ul(_CKO_PUBLIC_KEY), label.encode()
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
                raise RuntimeError(f"PKCS#11: {cnt.value} public keys labelled {label!r} on token {token!r} "
                                   "(exactly 1 required)")
            ktype = ul(0)
            punto, parametri = ctypes.create_string_buffer(256), ctypes.create_string_buffer(64)
            attrs = (_Attr * 3)(
                _Attr(_CKA_KEY_TYPE, ctypes.cast(ctypes.byref(ktype), ctypes.c_void_p), ctypes.sizeof(ul)),
                _Attr(_CKA_EC_POINT, ctypes.cast(punto, ctypes.c_void_p), len(punto)),
                _Attr(_CKA_EC_PARAMS, ctypes.cast(parametri, ctypes.c_void_p), len(parametri)))
            ck(lib.C_GetAttributeValue(session, ul(objs[0]), attrs, ul(3)), "C_GetAttributeValue")
            if ktype.value != _CKK_EC_EDWARDS:
                raise RuntimeError(f"PKCS#11: public key {label!r} is not an EC_EDWARDS key (type 0x{ktype.value:x})")
            try:
                pub = _ed25519_da_ec_point(punto.raw[:attrs[1].ulValueLen], parametri.raw[:attrs[2].ulValueLen])
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                Ed25519PublicKey.from_public_bytes(pub)
            except ValueError as e:
                raise RuntimeError(f"pkcs11: public key {label!r} is not Ed25519: {e}") from None
            return pub
        finally:
            if session.value:
                lib.C_CloseSession(session)
            if own_init:
                lib.C_Finalize(None)
    finally:
        _P11_LOCK.release()


def _env_without(name: Optional[str]) -> Dict[str, str]:
    """0.1.2: this process's environment without the variable `name` (the PIN's): what a child that does not log in
    gets. Windows' environment names are not case sensitive."""
    if not name:
        return os.environ.copy()
    fold = (lambda k: k.upper()) if os.name == "nt" else (lambda k: k)
    return {k: v for k, v in os.environ.items() if fold(k) != fold(name)}


def _p11_lavoratore() -> None:
    """The child process of _Pkcs11Figlio: one JSON request per line on stdin, one JSON answer per line on stdout.
    The PKCS#11 module runs here, so a call that hangs (or crashes the module) can be killed by the parent at its
    time limit, on Linux, macOS and Windows alike. The PIN comes in the sign request on standard input (0.1.2): the
    child is started without the variable that holds it, so neither the module nor a process it starts inherits it.
    The answers go to a private copy of standard output, and descriptor 1 is pointed at standard error: a module
    that prints on standard output cannot put a line into the protocol (NEMESIS 24/11/2026: one line printed by the
    module made every call fail, and through the API a later call got the answer of the one before)."""
    uscita = os.fdopen(os.dup(1), "w", encoding="ascii")
    os.dup2(2, 1)
    for riga in sys.stdin.buffer:
        try:
            r = json.loads(riga)
            if r["op"] == "pub":
                out = _p11_public_key(r["module"], r["token"], r["key"])
            elif r["op"] == "sign":   # 0.1.2: the PIN comes with the request, never from this process's environment
                out = _p11_sign_direct(r["module"], r["token"], r["key"], bytes.fromhex(r["pin"]), bytes.fromhex(r["msg"]))
            else:
                raise RuntimeError("unknown request")
            risposta = {"ok": out.hex()}
        except Exception as e:  # noqa: BLE001 — carried to the parent as one readable error
            risposta = {"err": str(e)[:300] if isinstance(e, RuntimeError) else f"{type(e).__name__}: {str(e)[:200]}"}
        uscita.write(json.dumps(risposta) + "\n")
        uscita.flush()


class _Pkcs11Figlio:
    """The PKCS#11 calls of one backend, in a child process (0.1.1). The time limit of a call is enforced: at the
    limit the child is killed (kill() = SIGKILL on POSIX, TerminateProcess on Windows) and the next call starts a new
    one. Before, the call ran in a thread of this process: the caller stopped waiting at the limit, but the thread
    stayed inside the module and could not be stopped. One call at a time per backend (a lock with the same limit)."""

    def __init__(self, timeout: float, pin_env: Optional[str] = None):
        import weakref
        self._timeout, self._proc, self._righe, self._pin_env = timeout, None, None, pin_env
        self._lock = threading.Lock()
        self._scatola = [None]                       # the live child, killed when this object goes away
        # `python -c` puts the current directory first in sys.path: the child (which holds the PIN) would import a
        # json.py or a pq_scitt/ found there (NEMESIS 24/11/2026). It is removed; the folder this package was
        # loaded from goes last, so that the child finds the same package as its parent.
        self.comando = [sys.executable, "-B", "-c",
                        "import sys; sys.path[:] = [p for p in sys.path if p != '']; sys.path.append(sys.argv[1]); "
                        "from pq_scitt.kms import _p11_lavoratore; _p11_lavoratore()",
                        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))]
        weakref.finalize(self, _Pkcs11Figlio._uccidi, self._scatola)

    @staticmethod
    def _uccidi(scatola):
        p = scatola[0]
        if p is None:
            return
        if p.poll() is None:
            p.kill()
            p.wait()
        for tubo in (p.stdin, p.stdout):   # the pipes too (the CI log showed ResourceWarning: unclosed file)
            try:
                tubo.close()
            except (OSError, ValueError):
                pass

    def _avvia(self):
        import queue
        self._proc = subprocess.Popen(   # 0.1.2: an explicit environment, without the PIN's variable
            self.comando, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=_env_without(self._pin_env))
        self._scatola[0] = self._proc
        self._righe = queue.Queue()
        out, q = self._proc.stdout, self._righe

        def leggi():
            for riga in out:
                q.put(riga)
            q.put(None)
        threading.Thread(target=leggi, daemon=True).start()

    def chiama(self, richiesta: dict, cosa: str) -> bytes:
        import queue
        import time
        fine = time.monotonic() + self._timeout
        if not self._lock.acquire(timeout=self._timeout):
            raise RuntimeError(f"pkcs11 {cosa}: another PKCS#11 call of this backend is still running (timeout "
                               f"{self._timeout} s)")
        try:
            if self._proc is None or self._proc.poll() is not None:
                self._avvia()
            dati, tubo = (json.dumps(richiesta) + "\n").encode(), self._proc.stdin

            def scrivi():   # in a thread: a child that does not read its input must not hold the caller past the limit
                try:
                    tubo.write(dati)
                    tubo.flush()
                except (OSError, ValueError):
                    pass    # the child ended or was killed: the reader says so (None)
            threading.Thread(target=scrivi, daemon=True).start()
            try:
                riga = self._righe.get(timeout=max(0.0, fine - time.monotonic()))
            except queue.Empty:
                riga = "timeout"
            if riga == "timeout" or riga is None:
                rc = self._proc.poll()
                _Pkcs11Figlio._uccidi([self._proc])
                self._proc = None
                if riga == "timeout":
                    raise RuntimeError(f"pkcs11 {cosa}: timeout after {self._timeout} s (the call was stopped)")
                raise RuntimeError(f"pkcs11 {cosa}: the PKCS#11 process ended (rc {rc})")
            try:   # closed: one object, {"ok": hex} or {"err": text}; anything else stops the child (the next
                r = json.loads(riga)   # line would be the answer to this call, read by the next one)
                if type(r) is not dict or len(r) != 1 or type(next(iter(r.values()))) is not str:
                    raise ValueError
                if "err" not in r:
                    return bytes.fromhex(r["ok"])
            except (ValueError, KeyError):
                _Pkcs11Figlio._uccidi([self._proc])
                self._proc = None
                raise RuntimeError(f"pkcs11 {cosa}: answer out of form from the PKCS#11 process (stopped)") from None
            raise RuntimeError(f"pkcs11 {cosa}: {r['err']}")
        finally:
            self._lock.release()


class Pkcs11Backend:
    """PKCS#11 token. Key generation via OpenSC pkcs11-tool (subprocess); public-key read (0.1.1, _p11_public_key) and
    signing with a single-part C_Sign through the module (ctypes, see _p11_sign_direct), both in a child process
    with a time limit that is enforced (_Pkcs11Figlio). The private key never enters this process."""

    name = "pkcs11"

    def __init__(self, module: str, token: str, key: str, pin: str = "env:CRYPTOVALID_PIN", timeout: float = 60.0):
        self._tool = which_absolute("pkcs11-tool")   # 0.1.2: never the one of the current folder
        if self._tool is None:
            raise RuntimeError("pkcs11-tool not found on an absolute folder of PATH (install opensc)")
        if not pin.startswith("env:"):
            raise ValueError("pin must be 'env:VARNAME' (argv PINs leak via ps)")
        if not os.environ.get(pin[4:]):
            raise RuntimeError(_ENV_UNSET % "PIN (pin=env:VAR)")
        self._module, self._token, self._key, self._pin = module, token, key, pin
        self._timeout = timeout
        self._figlio = _Pkcs11Figlio(timeout, pin[4:])

    def _run(self, extra, login=False, what="call"):
        cmd = [self._tool, "--module", self._module, "--token-label", self._token]
        if login:
            cmd += ["--login", "--pin", self._pin]      # pkcs11-tool reads env:VAR itself: the PIN is not on argv
        try:   # 0.1.2: the PIN's variable only in the environment of a call that logs in
            r = subprocess.run(cmd + extra, capture_output=True, timeout=self._timeout,
                               env=os.environ.copy() if login else _env_without(self._pin[4:]))
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
        return self._figlio.chiama({"op": "pub", "module": self._module, "token": self._token, "key": self._key},
                                   "read public key").hex()

    def sign(self, message: bytes) -> bytes:
        if not os.environ.get(self._pin[4:], ""):
            raise RuntimeError(_ENV_UNSET % "PIN (pin=env:VAR)")
        sig = self._figlio.chiama({"op": "sign", "module": self._module, "token": self._token, "key": self._key,
                                   "pin": os.fsencode(os.environ.get(self._pin[4:], "")).hex(),   # the bytes pkcs11-tool reads
                                   "msg": bytes(message).hex()},
                                  f"sign with key {self._key!r}")
        if len(sig) != 64:
            raise RuntimeError(f"expected 64-byte Ed25519 signature, got {len(sig)}")
        return sig

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
            self._endpoint = _backend_url(endpoint, "awskms-http endpoint")
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
            with _apri(req, 20) as r:  # nosec B310 - fixed AWS endpoint
                return json.loads(_risposta(r))
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"AWS KMS {op} HTTP {e.code} for {self._key_id}: {_http_error_text(e)}") from None
        except (OSError, ValueError) as e:   # 0.1.2: the kinds only; the text can carry the endpoint
            raise RuntimeError(f"AWS KMS {op}: unreachable: {_net_reason(e)}") from None

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
        body = json.loads(_risposta(e).decode("utf-8", "replace") or "{}")
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
            raise RuntimeError(_ENV_UNSET % "Vault token (token_env=VAR, default VAULT_TOKEN)")
        _backend_url(url, "Vault url")
        self._url, self._key, self._mount, self._token = url.rstrip("/"), key, mount, token
        self._timeout, self._version = timeout, None

    def _req(self, method: str, path: str, body: Optional[Dict] = None) -> Dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"{self._url}/v1/{path}", data=data, method=method,
                                     headers={"X-Vault-Token": self._token,
                                              "Content-Type": "application/json"})
        try:
            with _apri(req, self._timeout) as r:  # nosec B310 - scheme checked in __init__
                raw = _risposta(r)
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"Vault HTTP {e.code} on {method} {path}: {_http_error_text(e)}") from None
        except (OSError, ValueError) as e:   # unreachable, timeout, reset; 0.1.2: the kinds only, never the URL
            raise RuntimeError(f"Vault unreachable: {_net_reason(e)}") from None
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
            raise ValueError("backend URI: a segment is not key=value (not repeated here: it could be a secret)")
        if not v:
            raise ValueError(f"backend URI: empty value for {_nameable(k)}")
        if k in out:
            raise ValueError(f"backend URI: key {_nameable(k)} given twice")
        if allowed is not None and k not in allowed:
            raise ValueError(f"backend URI: unknown key {_nameable(k)} (allowed: {', '.join(sorted(allowed))})")
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
        raise ValueError("backend URI: timeout is not a number (ASCII digits, an optional fraction)") from None
    if not (0 < t <= 600):   # also refuses nan and inf
        raise ValueError("backend URI: timeout must be in (0, 600] seconds")
    return t


def _aws_region(region):
    if region is not None and not _AWS_REGION_RE.fullmatch(region):
        raise ValueError("AWS region: not of the form xx-name-N (it becomes part of a hostname)")
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
            raise RuntimeError(_ENV_UNSET % "NetHSM passphrase (pass_env=VAR, default NETHSM_PASS)")
        _backend_url(url, "NetHSM url")
        self._url, self._key = url.rstrip("/"), key
        self._auth = base64.b64encode(f"{user}:{passphrase}".encode()).decode()

    def _req(self, method: str, path: str, body: Optional[Dict] = None) -> Dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"{self._url}/api/v1/{path}", data=data,
                                     method=method,
                                     headers={"Authorization": f"Basic {self._auth}",
                                              "Content-Type": "application/json"})
        try:
            with _apri(req, 30) as r:
                raw = _risposta(r)
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"NetHSM HTTP {e.code} on {method} {path}: {_http_error_text(e)}") from None
        except (OSError, ValueError) as e:   # 0.1.2: the kinds only, never the URL
            raise RuntimeError(f"NetHSM unreachable: {_net_reason(e)}") from None
        return json.loads(raw.decode()) if raw else {}

    def keygen(self) -> str:
        """Generate the Ed25519 key ON the HSM (requires the Administrator role)."""
        self._req("POST", "keys/generate",
                  {"mechanisms": ["EdDSA_Signature"], "type": "Curve25519",
                   "id": self._key})
        return self.public_key_hex()

    def public_key_hex(self) -> str:
        d = self._req("GET", f"keys/{self._key}")
        try:   # a malformed answer = one readable RuntimeError, as for Vault and AWS (was a KeyError traceback)
            return _raw_from_spki(base64.b64decode(d["public"]["data"])).hex()
        except (KeyError, TypeError, ValueError) as e:
            raise RuntimeError(f"NetHSM key {self._key!r}: answer without an Ed25519 public key "
                               f"({type(e).__name__})") from None

    def sign(self, message: bytes) -> bytes:
        d = self._req("POST", f"keys/{self._key}/sign",
                      {"mode": "EdDSA",
                       "message": base64.b64encode(message).decode()})
        try:
            sig = base64.b64decode(d["signature"])
        except (KeyError, TypeError, ValueError) as e:
            raise RuntimeError(f"NetHSM Sign: answer without a signature ({type(e).__name__})") from None
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
        raise ValueError(f"unknown backend scheme {_nameable(scheme)} "
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
