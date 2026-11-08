#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pq_scitt/scitt/export.py — exports a hash-chained JSONL ledger as IETF SCITT Transparent Statements (08/11/2026).

ALONGSIDE our own format, not instead of it: the JSONL ledger is not touched (read only). Profile omega-scitt/1,
written before the code:
  - each line = COSE_Sign1 Signed Statement (tag 18), attached payload = canonical JSON of the line, signed by Issuer;
    protected header EXACTLY {1 alg, 3 cty, 4 kid, 15 {1 iss, 2 sub}} (RFC 9943 §6, CWT Claims RFC 9597);
  - leaf 0 = Signed Statement of the registration policy and of the trust anchors (RFC 9943 §5.1.2, bootstrap 2);
  - RFC 9162 tree (VDS RFC9162_SHA256 = 1, RFC 9942 §5.1) over the CBOR bytes of the Signed Statements with an empty
    unprotected header (RFC 9943 §6.3);
  - Receipt = COSE_Sign1 of the TS, detached payload = root, inclusion proof in {396: {-1: [bstr]}} (RFC 9942 §5.2.1);
  - Transparent Statement = Signed Statement with {394: [receipt]} (RFC 9943 §7).
Algorithms: -19 Ed25519 (default, RFC 9864), -8 EdDSA only on request (deprecated by RFC 9864; for external
verifiers that do not know -19), -49 ML-DSA-65 (RFC 9964, empty ctx). The TS key differs from the Issuer key
(RFC 9943 §9.4). Before the export the ledger's hash chain is verified: broken chain = export refused.

Profile amendments 6-7 (08/11): payload `chiaro` (the whole line) or `riservato` (only idx, prev_hash, self_hash);
persistent keys from `file:` (permissions checked) or from the KMS/HSM backends of
pq_scitt/kms.py (reused); every signature produced is verified at once with the declared public key.

Amendments 9-10 (08/11 evening): profile `omega-scitt/2` (new version; /1 stays). Every signature carries `iat` (CWT 6);
the policy declares for each key its validity (≤ 366 days) and a closed list of revoked kids. The v2 `riservato` is
{idx, impegno} with impegno = SHA-256(domain ‖ 32-byte salt ‖ line): salts stay with the exporter, outside the export.
The /1 `riservato` stays verifiable but is NOT confidential against predictable ledgers: a guessed line is confirmed
by its hash.

Dependencies: stdlib + `cryptography`: `mldsa` is imported at startup (≤ 46 ImportError; -49 needs ≥ 48).
To VERIFY, `pq_scitt/ed25519_order.py` is also needed
(imported by pq_scitt/ed25519_keys.py, used by pq_scitt/scitt/verify.py); the KMS/HSM backends import
`pq_scitt/kms.py` only when a URI asks for them. Installation: see the README.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import sys
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

try:
    from pq_scitt.scitt import cbor as cbor
except ImportError:  # source tree
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from pq_scitt.scitt import cbor as cbor

PROFILO = "omega-scitt/1"
PROFILO_2 = "omega-scitt/2"
VERSIONI = (1, 2)
ALG_ED25519 = -19
ALG_EDDSA = -8
ALG_MLDSA65 = -49
LUNGHEZZA_FIRMA = {ALG_ED25519: 64, ALG_EDDSA: 64, ALG_MLDSA65: 3309}
LUNGHEZZA_CHIAVE = {ALG_ED25519: 32, ALG_EDDSA: 32, ALG_MLDSA65: 1952}

H_ALG, H_CTY, H_KID, H_CWT, H_RECEIPTS, H_VDS, H_VDP = 1, 3, 4, 15, 394, 395, 396
CWT_ISS, CWT_SUB = 1, 2
CWT_IAT = 6   # amendment 9a: only in profile /2
VDS_RFC9162_SHA256 = 1
VDP_INCLUSIONE = -1
# Private-use label (IANA registry "COSE Header Parameters": "Reserved for Private Use, less than -65536"): tree_size
# SIGNED in the protected header of the receipt. Reason measured on 08/11 (profile amendment 1): in RFC 9942 the proof
# sits in the UNprotected header and the signature covers only the root; changing tree_size (e.g. from n to n+1)
# rebuilds the same root in 12 of 16 cases tried, and scitt-cose 0.5.0 and pycose 0.9.dev8 accept them.
H_TREE_SIZE_FIRMATO = -65538

CTY_RIGA_OPS = "application/vnd.omega.ledger-entry+json"
CTY_RIGA_OPS_SHA3 = "application/vnd.omega.ledger-entry-sha3+json"
CTY_EVENTO_CHAIN = "application/vnd.omega.chain-event+json"
CTY_POLITICA = "application/vnd.omega.scitt-policy+json"
CTY_COLLEGAMENTO = "application/vnd.omega.ledger-link+json"
CTY_IMPEGNO = "application/vnd.omega.ledger-commitment+json"
CTY_AMMESSI = (CTY_RIGA_OPS, CTY_RIGA_OPS_SHA3, CTY_EVENTO_CHAIN, CTY_POLITICA, CTY_COLLEGAMENTO, CTY_IMPEGNO)
CTY_DI_FORMATO = {"ops": CTY_RIGA_OPS, "ops_sha3": CTY_RIGA_OPS_SHA3, "chain": CTY_EVENTO_CHAIN}
CTY_DI_RIGA = tuple(CTY_DI_FORMATO.values()) + (CTY_COLLEGAMENTO, CTY_IMPEGNO)
CAMPI_OPS = frozenset({"idx", "ts", "data", "prev_hash", "self_hash"})
CAMPI_COLLEGAMENTO = frozenset({"idx", "prev_hash", "self_hash"})
MODI_PAYLOAD = ("chiaro", "riservato")
# Amendment 6d: CLOSED shape of the policy document (leaf 0).
CHIAVI_POLITICA = frozenset({"profilo", "regola", "payload", "formato", "ancore", "ts", "vds"})
CHIAVI_ANCORA = frozenset({"kid", "alg", "pub", "iss"})
CHIAVI_TS_POLITICA = frozenset({"kid", "alg", "iss"})
# Amendment 9b: CLOSED shape of the /2 policy.
CHIAVI_POLITICA_2 = frozenset({"profilo", "regola", "payload", "formato", "ancore", "ts", "politica", "revocate", "vds"})
CHIAVI_ANCORA_2 = frozenset({"kid", "alg", "pub", "iss", "valida_dal", "valida_fino"})
CHIAVI_TS_POLITICA_2 = frozenset({"kid", "alg", "iss", "valida_dal", "valida_fino"})
CHIAVI_CHIAVE_POLITICA_2 = frozenset({"kid", "alg", "valida_dal", "valida_fino"})
MAX_VALIDITA = 366 * 86400
RUOLI = ("issuer", "ts", "politica")
# Amendment 10a.
CAMPI_IMPEGNO = frozenset({"idx", "impegno"})
LUNGHEZZA_SALE = 32
DOMINIO_IMPEGNO = b"omega-scitt/2 impegno-riga\x00"
RE_KID = re.compile(r"[0-9a-f]{32}")
# Amendment 6c: ledger name (sub) and iss in the export. fullmatch: no trailing "\n" accepted by "$".
RE_NOME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
RE_SUB = re.compile(r"omega-ledger:[a-z0-9][a-z0-9._-]{0,63}")
RE_ISS_EXPORT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,8191}")
RE_HEX64 = re.compile(r"[0-9a-f]{64}")

GENESIS = "0" * 64


class ExportError(ValueError):
    pass


# ------------------------------------------------------------------ JSON and ledger hash chains

def json_canonico(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def hash_riga_ops(riga: dict, funzione=hashlib.sha256) -> str:
    """Rule of the "ops" format ledgers: SHA-256 of the canonical JSON without self_hash. With
    funzione=hashlib.sha3_256 it is the SHA3-256 variant of the computation ledgers."""
    d = {k: v for k, v in riga.items() if k != "self_hash"}
    return funzione(json.dumps(d, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def hash_evento_chain(ev: dict) -> str:
    """Rule of the "chain" format events: SHA3-256 of the bound fields."""
    campi = {k: ev[k] for k in ("event_id", "timestamp", "event_type", "origin_node", "payload_sha3", "prev_hash")}
    return hashlib.sha3_256(json.dumps(campi, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
                            .encode("utf-8")).hexdigest()


def payload_sha3_chain(payload) -> str:
    return hashlib.sha3_256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
                            .encode("utf-8")).hexdigest()


def verifica_catena(righe: Sequence[dict], formato: str) -> Optional[str]:
    """None if the chain holds from GENESIS, otherwise the reason. formato: 'ops', 'ops_sha3' or 'chain'."""
    prev = GENESIS
    for n, r in enumerate(righe):
        if not isinstance(r, dict):
            return "line %d is not an object" % n
        if formato in ("ops", "ops_sha3"):
            if set(r) != CAMPI_OPS:
                return "line %d: fields %s" % (n, sorted(r))
            if type(r["idx"]) is not int or r["idx"] != n:
                return "line %d: idx %r" % (n, r["idx"])
            if r["self_hash"] != hash_riga_ops(r, hashlib.sha3_256 if formato == "ops_sha3" else hashlib.sha256):
                return "line %d: self_hash does not recompute" % n
        elif formato == "chain":
            attesi = {"event_id", "timestamp", "event_type", "origin_node", "payload", "payload_sha3", "prev_hash",
                      "self_hash", "signature"}
            if set(r) != attesi:
                return "event %d: fields %s" % (n, sorted(r))
            if r["payload_sha3"] != payload_sha3_chain(r["payload"]):
                return "event %d: payload_sha3 does not recompute" % n
            if r["self_hash"] != hash_evento_chain(r):
                return "event %d: self_hash does not recompute" % n
        elif formato == "collegamento":
            if not collegamento_valido(r) or r["idx"] != n:
                return "link %d out of form or different idx" % n
        else:
            return "unknown format"
        if r["prev_hash"] != prev:
            return "line %d: prev_hash does not link" % n
        prev = r["self_hash"]
    return None


def collegamento_valido(d) -> bool:
    """Payload `riservato` (amendment 6b): exactly {idx: int >= 0, prev_hash: hex64, self_hash: hex64}."""
    return (isinstance(d, dict) and set(d) == CAMPI_COLLEGAMENTO and type(d["idx"]) is int and d["idx"] >= 0
            and type(d["prev_hash"]) is str and RE_HEX64.fullmatch(d["prev_hash"]) is not None
            and type(d["self_hash"]) is str and RE_HEX64.fullmatch(d["self_hash"]) is not None)


def collegamenti(righe: Sequence[dict]) -> List[dict]:
    """Only the link of each line (idx = position; for ops lines it equals their idx)."""
    return [{"idx": n, "prev_hash": r["prev_hash"], "self_hash": r["self_hash"]} for n, r in enumerate(righe)]


def impegno_riga(sale: bytes, riga) -> str:
    """Amendment 10a: SHA-256("omega-scitt/2 impegno-riga" ‖ 0x00 ‖ 32-byte salt ‖ canonical JSON of the line)."""
    if type(sale) is not bytes or len(sale) != LUNGHEZZA_SALE:
        raise ExportError("salt: 32 bytes")
    return hashlib.sha256(DOMINIO_IMPEGNO + sale + json_canonico(riga)).hexdigest()


def impegno_valido(d) -> bool:
    """Payload `riservato` /2: exactly {idx: int >= 0, impegno: hex64}."""
    return (isinstance(d, dict) and set(d) == CAMPI_IMPEGNO and type(d["idx"]) is int and d["idx"] >= 0
            and type(d["impegno"]) is str and RE_HEX64.fullmatch(d["impegno"]) is not None)


def validita_valida(dal, fino) -> bool:
    """Amendment 9b: integers, 0 <= dal < fino <= dal + 366 days."""
    return type(dal) is int and type(fino) is int and 0 <= dal < fino <= dal + MAX_VALIDITA


def revocate_valide(lista) -> bool:
    """Amendment 9b: list of hex kids (32 lowercase digits) in strictly increasing order, possibly empty."""
    return (isinstance(lista, list) and all(type(k) is str and RE_KID.fullmatch(k) for k in lista)
            and all(a < b for a, b in zip(lista, lista[1:])))


# ------------------------------------------------------------------ Merkle RFC 9162 §2.1

def hash_foglia(entry: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry).digest()


def hash_nodo(sx: bytes, dx: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + sx + dx).digest()


def _k(n: int) -> int:
    """The largest power of 2 strictly smaller than n (n > 1)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


class AlberoMerkle:
    """MTH and PATH of RFC 9162 §2.1.1 and §2.1.3.1, with memoized subtrees (O(n) cost to build)."""

    def __init__(self, foglie: Sequence[bytes]):
        if not foglie:
            raise ExportError("empty tree")
        self.h = [hash_foglia(f) for f in foglie]
        self.n = len(self.h)
        self._memo: Dict[tuple, bytes] = {}

    def _mth(self, lo: int, hi: int) -> bytes:
        if hi - lo == 1:
            return self.h[lo]
        chiave = (lo, hi)
        if chiave not in self._memo:
            k = _k(hi - lo)
            self._memo[chiave] = hash_nodo(self._mth(lo, lo + k), self._mth(lo + k, hi))
        return self._memo[chiave]

    def radice(self) -> bytes:
        return self._mth(0, self.n)

    def consistenza(self, m: int) -> List[bytes]:
        """PROOF(m, D_n) of RFC 9162 §2.1.4.1, 0 < m < n."""
        if not 0 < m < self.n:
            raise ExportError("consistency: needs 0 < m < n")

        def sub(m_, lo, hi, b):
            if m_ == hi - lo:
                return [] if b else [self._mth(lo, hi)]
            k = _k(hi - lo)
            if m_ <= k:
                return sub(m_, lo, lo + k, b) + [self._mth(lo + k, hi)]
            return sub(m_ - k, lo + k, hi, False) + [self._mth(lo, lo + k)]
        return sub(m, 0, self.n, True)

    def percorso(self, m: int) -> List[bytes]:
        if not 0 <= m < self.n:
            raise ExportError("index outside the tree")
        out: List[bytes] = []
        lo, hi = 0, self.n
        while hi - lo > 1:
            k = _k(hi - lo)
            if m < lo + k:
                out.append(self._mth(lo + k, hi))
                hi = lo + k
            else:
                out.append(self._mth(lo, lo + k))
                lo = lo + k
        out.reverse()   # PATH(m, D[n]) lists from the bottom up
        return out


# ------------------------------------------------------------------ signers

@dataclass
class Firmatario:
    alg: int
    pub: bytes
    firma: Callable[[bytes], bytes]

    @property
    def kid(self) -> bytes:
        return kid_di(self.pub)


def kid_di(pub: bytes) -> bytes:
    return hashlib.sha256(pub).digest()[:16]


def firmatario_ed25519(chiave: ed25519.Ed25519PrivateKey, alg: int = ALG_ED25519) -> Firmatario:
    if alg not in (ALG_ED25519, ALG_EDDSA):
        raise ExportError("allowed Ed25519 alg: -19, -8")
    return Firmatario(alg, chiave.public_key().public_bytes_raw(), chiave.sign)


def firmatario_mldsa65(chiave: mldsa.MLDSA65PrivateKey) -> Firmatario:
    # RFC 9964: empty ctx. sign(data) without context = empty context (FIPS 204 Algorithm 2).
    return Firmatario(ALG_MLDSA65, chiave.public_key().public_bytes_raw(), chiave.sign)


MAX_FILE_CHIAVE = 64 * 1024
SCHEMI_KMS_ED25519 = ("pkcs11", "awskms", "awskms-http", "vault", "nethsm")


def _leggi_file_chiave(percorso: str) -> bytes:
    """Amendment 7: regular file, last component not a link (O_NOFOLLOW; the directories of the path are not
    checked), owned by the running user, no group or other bits, ≤ 64 KiB.
    Checks on the open descriptor (fstat), not on the name: no window between check and read."""
    try:
        fd = os.open(percorso, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    except (OSError, ValueError) as e:   # ValueError: NUL byte in the path (API only)
        raise ExportError("key file: cannot be opened (%s)" % type(e).__name__) from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ExportError("key file: not a regular file")
        if st.st_uid != os.geteuid():
            raise ExportError("key file: the owner is not the running user")
        if st.st_mode & 0o077:
            raise ExportError("key file: permissions %o, no permissions for group and others (e.g. 0600 or 0400)"
                              % stat.S_IMODE(st.st_mode))
        if st.st_size > MAX_FILE_CHIAVE:
            raise ExportError("key file: over 64 KiB")
        with os.fdopen(fd, "rb") as f:
            fd = -1
            dati = f.read(MAX_FILE_CHIAVE + 1)
        if len(dati) > MAX_FILE_CHIAVE:   # grew after fstat: the limit applies to the bytes read, not only to st_size
            raise ExportError("key file: over 64 KiB")
        return dati
    except OSError as e:   # fstat/read: before, this reached the CLI as "ledger not readable"
        raise ExportError("key file: read error (%s)" % type(e).__name__) from None
    finally:
        if fd >= 0:
            os.close(fd)


def _chiave_da_byte(dati: bytes, alg: int) -> Firmatario:
    """Unencrypted PEM PKCS#8, or 64 hex digits (32-byte seed). Type consistent with alg. Anything else = refusal."""
    testo = dati.strip()
    if testo.startswith(b"-----BEGIN PRIVATE KEY-----"):
        if not testo.endswith(b"-----END PRIVATE KEY-----") or testo.count(b"-----BEGIN") != 1:
            raise ExportError("key file: a single PEM block «PRIVATE KEY» and nothing else")
        try:
            k = serialization.load_pem_private_key(dati, password=None)
        except (ValueError, TypeError, UnsupportedAlgorithm):
            raise ExportError("key file: PEM not readable (encrypted or not PKCS#8)") from None
    elif len(testo) == 64 and re.fullmatch(rb"[0-9a-fA-F]{64}", testo):
        seme = bytes.fromhex(testo.decode("ascii"))
        k = (mldsa.MLDSA65PrivateKey.from_seed_bytes(seme) if alg == ALG_MLDSA65
             else ed25519.Ed25519PrivateKey.from_private_bytes(seme))
    else:
        raise ExportError("key file: allowed formats PEM «PRIVATE KEY» or 64 hex digits")
    if alg == ALG_MLDSA65:
        if not isinstance(k, mldsa.MLDSA65PrivateKey):
            raise ExportError("key file: alg -49 needs an ML-DSA-65 key")
        return firmatario_mldsa65(k)
    if not isinstance(k, ed25519.Ed25519PrivateKey):
        raise ExportError("key file: alg %d needs an Ed25519 key" % alg)
    return firmatario_ed25519(k, alg)


def carica_firmatario(uri: str, alg: int) -> Firmatario:
    """CLOSED list of URIs (amendment 7): file:PATH; pkcs11:/awskms:/awskms-http:/vault:/nethsm: (Ed25519) and
    awskms-mldsa65: (ML-DSA-65) from the backends of pq_scitt/kms.py, reused. The private key of the
    KMS/HSM backends does not enter the process; the file: one does (like the file: backend of cryptovalid_kms)."""
    if alg not in LUNGHEZZA_FIRMA:
        raise ExportError("allowed alg: -19, -8, -49")
    if type(uri) is not str:
        raise ExportError("key URI: string")
    schema, sep, resto = uri.partition(":")
    if not sep or not resto:
        raise ExportError("key URI without scheme")
    if schema == "file":
        return _chiave_da_byte(_leggi_file_chiave(resto), alg)
    if schema in SCHEMI_KMS_ED25519 or schema == "awskms-mldsa65":
        try:
            return _firmatario_kms(_cryptovalid_kms(), schema, resto, uri, alg)
        except ExportError:
            raise
        except Exception as e:   # incomplete URI, network, credentials, missing module, botocore: a readable refusal
            raise ExportError("%s: %s: %s" % (schema, type(e).__name__, str(e)[:200])) from None
    raise ExportError("key scheme not allowed: %s" % schema)


def _firmatario_kms(kms, schema: str, resto: str, uri: str, alg: int) -> Firmatario:
    """The public key comes from the backend; _sign1 verifies every signature with it (backend mismatch = refusal)."""
    if schema == "awskms-mldsa65":
        if alg != ALG_MLDSA65:
            raise ExportError("awskms-mldsa65: only alg -49")
        # kms_reali 08/11: closed-form URI (unknown/duplicate/empty key = refusal) and mu=external to sign beyond the
        # 4096 bytes of AWS KMS RAW (the -49 policy has ~4880: measured live); mu=external is FIPS 204 §6.2,
        # empty context, the signature verifies on the message itself (self-check of _sign1 unchanged).
        kv = kms._parse_kv(resto, kms._ALLOWED_KEYS["awskms-mldsa65"])
        if not kv.get("key_id"):
            raise ExportError("awskms-mldsa65: key_id missing")
        if kv.get("mu", "raw") not in ("raw", "external"):
            raise ExportError("awskms-mldsa65: allowed mu: raw, external")
        b = kms.AwsKmsMlDsaBackend(key_id=kv["key_id"], region=kv.get("region"), profile=kv.get("profile"),
                                   external_mu=kv.get("mu") == "external")
        import base64
        return Firmatario(ALG_MLDSA65, base64.b64decode(b.public_key_b64), b.sign)
    if alg == ALG_MLDSA65:
        raise ExportError("%s: Ed25519 only (alg -19 or -8)" % schema)
    b = kms.backend_from_uri(uri)
    return Firmatario(alg, bytes.fromhex(b.public_key_hex()), b.sign)


def _cryptovalid_kms():
    try:
        from pq_scitt import kms as cryptovalid_kms
    except ImportError:
        try:
            from pq_scitt import kms as cryptovalid_kms  # source tree: here it is the same module
        except ImportError:
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            from pq_scitt import kms as cryptovalid_kms
    return cryptovalid_kms


def _firma_regge(alg: int, pub: bytes, firma: bytes, messaggio: bytes) -> bool:
    try:
        if alg == ALG_MLDSA65:
            mldsa.MLDSA65PublicKey.from_public_bytes(pub).verify(firma, messaggio)
        else:
            ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(firma, messaggio)
    except (InvalidSignature, ValueError):
        return False
    return True


# ------------------------------------------------------------------ COSE_Sign1 (RFC 9052 §4.4)

def sig_structure(protetto: bytes, payload: bytes) -> bytes:
    return cbor.dumps(["Signature1", protetto, b"", payload])


def _sign1(f: Firmatario, protetto_mappa: dict, payload: bytes, attaccato: bool, non_protetto: dict) -> bytes:
    protetto = cbor.dumps(protetto_mappa)
    messaggio = sig_structure(protetto, payload)
    try:
        firma = f.firma(messaggio)
    except Exception as e:   # KMS/HSM backend: network, credentials, 4096-byte limit of AWS KMS RAW (ML-DSA)
        raise ExportError("signature not produced (%d bytes to sign): %s: %s"
                          % (len(messaggio), type(e).__name__, str(e)[:200])) from None
    if len(firma) != LUNGHEZZA_FIRMA[f.alg]:
        raise ExportError("unexpected signature length")
    # Amendment 7: a backend (HSM/KMS) that signs with another key must not produce an export.
    if not _firma_regge(f.alg, f.pub, firma, messaggio):
        raise ExportError("the signature produced does not verify with the declared public key")
    return cbor.dumps(cbor.Tag(cbor.TAG_COSE_SIGN1, [protetto, non_protetto, payload if attaccato else None, firma]))


def _claims(iss: str, sub: str, iat: Optional[int]) -> dict:
    """CWT Claims: {1 iss, 2 sub} in profile /1, {1 iss, 2 sub, 6 iat} in /2 (amendment 9a)."""
    c = {CWT_ISS: iss, CWT_SUB: sub}
    if iat is not None:
        if type(iat) is not int or iat < 0:
            raise ExportError("iat: integer >= 0")
        c[CWT_IAT] = iat
    return c


def signed_statement(f: Firmatario, iss: str, sub: str, cty: str, payload: bytes, iat: Optional[int] = None) -> bytes:
    if cty not in CTY_AMMESSI:
        raise ExportError("cty outside the profile")
    if not (1 <= len(iss) <= 8192) or not sub:
        raise ExportError("iss 1..8192 characters, sub not empty (RFC 9943 §6)")
    prot = {H_ALG: f.alg, H_CTY: cty, H_KID: f.kid, H_CWT: _claims(iss, sub, iat)}
    return _sign1(f, prot, payload, True, {})


def receipt(f: Firmatario, iss: str, sub: str, radice: bytes, tree_size: int, indice: int,
            percorso: List[bytes], iat: Optional[int] = None) -> bytes:
    prova = cbor.dumps([tree_size, indice, list(percorso)])
    prot = {H_ALG: f.alg, H_KID: f.kid, H_CWT: _claims(iss, sub, iat), H_VDS: VDS_RFC9162_SHA256,
            H_TREE_SIZE_FIRMATO: tree_size}
    return _sign1(f, prot, radice, False, {H_VDP: {VDP_INCLUSIONE: [prova]}})


def aggiungi_receipt(statement: bytes, rcpt: bytes) -> bytes:
    t = cbor.loads(statement)
    prot, nonprot, payload, firma = t.value
    if nonprot != {}:
        raise ExportError("the statement must have an empty unprotected header")
    return cbor.dumps(cbor.Tag(cbor.TAG_COSE_SIGN1, [prot, {H_RECEIPTS: [rcpt]}, payload, firma]))


# ------------------------------------------------------------------ export of a ledger

def esporta(righe: Sequence[dict], *, nome: str, formato: str, issuer: Firmatario, ts: Firmatario,
            politica: Firmatario, iss_issuer: str, iss_ts: str, payload: str = "chiaro", versione: int = 1,
            validita: Optional[dict] = None, revocate: Sequence[str] = (), adesso: Optional[int] = None) -> dict:
    """Returns {'radice', 'tree_size', 'sub', 'statements' (leaves), 'transparent' (list of bytes), 'politica', 'sali'}.
    Leaf 0 is the policy; line i of the ledger is leaf i+1. payload: 'chiaro' (the whole line) or
    'riservato': in version 1 only the link idx/prev_hash/self_hash (amendment 6b, NOT confidential against
    predictable ledgers), in version 2 {idx, impegno} with a 32-byte salt per line (amendment 10; the salts are in
    'sali' and do NOT go into the export). Version 2: validita = {'issuer'|'ts'|'politica': (dal, fino)} in UTC seconds,
    revocate = hex kids, adesso = iat of all signatures (default: clock)."""
    if versione not in VERSIONI or type(versione) is not int:
        raise ExportError("allowed versione: 1, 2")
    if versione == 1 and (validita is not None or tuple(revocate) or adesso is not None):
        raise ExportError("validita, revocate and adesso exist only in version 2")
    if formato not in CTY_DI_FORMATO:
        raise ExportError("allowed formato: " + ", ".join(CTY_DI_FORMATO))
    if payload not in MODI_PAYLOAD:
        raise ExportError("allowed payload: chiaro, riservato")
    if type(nome) is not str or not RE_NOME.fullmatch(nome):
        raise ExportError("ledger name: [a-z0-9][a-z0-9._-]{0,63} (amendment 6c)")
    for v in (iss_issuer, iss_ts):
        if type(v) is not str or not RE_ISS_EXPORT.fullmatch(v):
            raise ExportError("iss: [A-Za-z0-9][A-Za-z0-9._:/-]*, no @ or spaces (amendment 6c)")
    if len({issuer.pub, ts.pub, politica.pub}) != 3:
        raise ExportError("Issuer, TS and policy must have different keys (RFC 9943 §9.4)")
    if not righe:
        # review P2: 0 lines = tree of 1 leaf with an empty path, outside the CDDL of RFC 9942
        # (inclusion_path: [ + bstr ]).
        raise ExportError("empty ledger: nothing to export (RFC 9942 needs a non-empty path)")
    motivo = verifica_catena(righe, formato)
    if motivo:
        raise ExportError("invalid ledger hash chain, export refused: " + motivo)
    sub = "omega-ledger:" + nome
    iat, sali = None, None
    if versione == 2:
        iat, revocate = _controlla_chiavi_v2(validita, revocate, adesso, issuer, ts, politica)
    cty, contenuti, sali, catena = _payload_righe(righe, formato, payload, versione, [])
    doc_politica = {
        "profilo": PROFILO,
        "regola": "registra solo Signed Statement firmate da una ancora elencata, con alg uguale a quello "
                  "dell'ancora, header protetto esattamente {1,3,4,15}, cty " + cty + ", sub " + sub + ", " + catena,
        "payload": payload,
        "formato": formato,
        "ancore": [{"kid": issuer.kid.hex(), "alg": issuer.alg, "pub": issuer.pub.hex(), "iss": iss_issuer}],
        "ts": {"kid": ts.kid.hex(), "alg": ts.alg, "iss": iss_ts},
        "vds": "RFC9162_SHA256",
    }
    if versione == 2:
        doc_politica["profilo"] = PROFILO_2
        doc_politica["regola"] = doc_politica["regola"].replace(
            "{1,3,4,15},", "{1,3,4,15}, CWT esattamente {1,2,6} con iat nella validità della chiave, kid non revocato,")
        doc_politica["ancore"][0].update(valida_dal=validita["issuer"][0], valida_fino=validita["issuer"][1])
        doc_politica["ts"].update(valida_dal=validita["ts"][0], valida_fino=validita["ts"][1])
        doc_politica["politica"] = {"kid": politica.kid.hex(), "alg": politica.alg,
                                    "valida_dal": validita["politica"][0], "valida_fino": validita["politica"][1]}
        doc_politica["revocate"] = revocate
    statements = [signed_statement(politica, iss_ts, sub, CTY_POLITICA, json_canonico(doc_politica), iat)]
    for r in contenuti:
        statements.append(signed_statement(issuer, iss_issuer, sub, cty, json_canonico(r), iat))
    return _chiudi(statements, ts, iss_ts, sub, iat, doc_politica, sali, politica)


def _payload_righe(righe, formato: str, payload: str, versione: int, sali_dati: List[bytes]):
    """(cty, contenuti, sali, rule text) for the lines. In /2 riservato the first len(sali_dati) salts are
    reused (extension, amendment 11b), the others are new."""
    if versione == 2 and payload == "riservato":
        sali = list(sali_dati) + [secrets.token_bytes(LUNGHEZZA_SALE) for _ in righe[len(sali_dati):]]
        contenuti = [{"idx": n, "impegno": impegno_riga(s, r)} for n, (s, r) in enumerate(zip(sali, righe))]
        return (CTY_IMPEGNO, contenuti, sali, "payload JSON stretto {idx, impegno}, impegno = SHA-256(dominio, "
                "sale di 32 byte, riga), sali fuori dall'export")
    if payload == "riservato":
        return (CTY_COLLEGAMENTO, collegamenti(righe), None,
                "payload JSON stretto {idx, prev_hash, self_hash} con collegamenti che si legano dal GENESIS")
    return CTY_DI_FORMATO[formato], list(righe), None, "payload JSON stretto con catena hash del registro che si ricalcola"


def _chiudi(statements, ts: Firmatario, iss_ts: str, sub: str, iat, doc_politica, sali, politica_pub) -> dict:
    """Tree, receipt of every leaf, result."""
    albero = AlberoMerkle(statements)
    radice = albero.radice()
    trasparenti = [aggiungi_receipt(s, receipt(ts, iss_ts, sub, radice, albero.n, i, albero.percorso(i), iat))
                   for i, s in enumerate(statements)]
    return {"radice": radice, "tree_size": albero.n, "sub": sub, "statements": statements,
            "transparent": trasparenti, "politica": doc_politica, "sali": sali, "albero": albero,
            "chiavi_pubbliche": {"ts": [ts.alg, ts.pub.hex()],
                                 "politica": [politica_pub.alg, politica_pub.pub.hex()]}}


# ------------------------------------------------------------------ extension and consistency (amendment 11)

def _foglia_da_file(dati: bytes) -> bytes:
    """Transparent Statement → leaf (the statement with an empty unprotected header, RFC 9943 §6.3)."""
    t = cbor.loads(dati)
    prot, _, payload, firma = t.value
    return cbor.dumps(cbor.Tag(cbor.TAG_COSE_SIGN1, [prot, {}, payload, firma]))


def estendi(cartella_precedente: str, righe: Sequence[dict], *, nome: str, formato: str, payload: str,
            issuer: Firmatario, ts: Firmatario, politica: Firmatario, iss_issuer: str, iss_ts: str,
            sali_precedenti: Optional[Sequence[bytes]] = None, adesso: Optional[int] = None) -> dict:
    """Amendment 11b: export that EXTENDS the one in cartella_precedente (same policy, same leading leaves) with
    the new lines appended; adds 'consistenza' = PROOF(m, D_n) of RFC 9162 §2.1.4.1. Different old line =
    ExportError "rewrites the past"."""
    try:
        from pq_scitt.scitt import verify as sv
    except ImportError:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from pq_scitt.scitt import verify as sv
    if type(nome) is not str:   # form of nome, formato and payload: they must be EQUAL to those of the policy, below
        raise ExportError("ledger name: string")
    ev = sv.verifica_cartella(cartella_precedente, alg_statement=issuer.alg, alg_receipt=ts.alg,
                              chiave_ts=(ts.alg, ts.pub), chiave_politica=(politica.alg, politica.pub))
    if not ev.ok:
        raise ExportError("previous export not valid: %s %s" % (ev.motivo, ev.dettaglio))
    m = ev.campi["tree_size"]
    foglie = []
    for i in range(m):
        dati = sv._leggi_file(cartella_precedente, "ts_%06d.cose" % i)
        if isinstance(dati, sv.Esito):
            raise ExportError("previous export: %s" % dati.motivo)
        foglie.append(_foglia_da_file(dati))
    doc = json.loads(cbor.loads(foglie[0]).value[2])
    versione = 2 if doc["profilo"] == PROFILO_2 else 1
    sub = "omega-ledger:" + nome
    if (ev.campi["sub"] != sub or doc["formato"] != formato or doc["payload"] != payload
            or [a["kid"] for a in doc["ancore"]] != [issuer.kid.hex()] or doc["ts"]["iss"] != iss_ts
            or doc["ancore"][0]["iss"] != iss_issuer):
        raise ExportError("the extension uses the policy of the previous export: same nome, formato, payload, keys "
                          "and iss (amendment 11a)")
    if len(righe) < m:
        raise ExportError("nothing to add: the ledger has %d lines, the previous export %d" % (len(righe), m - 1))
    motivo = verifica_catena(righe, formato)
    if motivo:
        raise ExportError("invalid ledger hash chain, export refused: " + motivo)
    vecchi_sali: List[bytes] = []
    if versione == 2 and payload == "riservato":
        if sali_precedenti is None or len(sali_precedenti) != m - 1:
            raise ExportError("the salts of the previous export are needed, one per line (%d)" % (m - 1))
        vecchi_sali = list(sali_precedenti)
    elif sali_precedenti is not None:
        raise ExportError("previous salts given for an export without commitments")
    iat = None
    if versione == 2:
        iat = int(time.time()) if adesso is None else adesso
        if type(iat) is not int:   # negative: outside every window (dal >= 0), refused below
            raise ExportError("adesso: integer")
        # revoked kids of the policy: verifica_cartella already refuses them on the previous export (same keys)
        for voce in (doc["ancore"][0], doc["ts"]):
            if not voce["valida_dal"] <= iat <= voce["valida_fino"]:
                raise ExportError("a key is outside its validity: new series with new keys (amendment 11a)")
    elif adesso is not None:
        raise ExportError("adesso exists only in version 2")
    cty, contenuti, sali, _ = _payload_righe(righe, formato, payload, versione, vecchi_sali)
    for i in range(m - 1):
        if json_canonico(contenuti[i]) != cbor.loads(foglie[i + 1]).value[2]:
            raise ExportError("rewrites the past: line %d is not the one of the previous export" % i)
    statements = foglie + [signed_statement(issuer, iss_issuer, sub, cty, json_canonico(r), iat)
                           for r in contenuti[m - 1:]]
    es = _chiudi(statements, ts, iss_ts, sub, iat, doc, sali, politica)
    es["consistenza"] = {"profilo": doc["profilo"], "sub": sub,
                         "precedente": {"tree_size": m, "radice": ev.campi["radice"]},
                         "attuale": {"tree_size": es["tree_size"], "radice": es["radice"].hex()},
                         "percorso": [h.hex() for h in es["albero"].consistenza(m)]}
    return es


def _controlla_chiavi_v2(validita, revocate, adesso, issuer: Firmatario, ts: Firmatario, politica: Firmatario):
    """Amendment 9c: form of validity and revoked kids; no revoked key or key outside validity at export time.
    Returns (iat, sorted revocate)."""
    if not isinstance(validita, dict) or set(validita) != set(RUOLI):
        raise ExportError("version 2: validita for issuer, ts and politica")
    for ruolo in RUOLI:
        v = validita[ruolo]
        if not isinstance(v, (tuple, list)) or len(v) != 2 or not validita_valida(v[0], v[1]):
            raise ExportError("validity of %s: integers 0 <= dal < fino <= dal + 366 days" % ruolo)
    if not isinstance(revocate, (list, tuple)) or not all(type(k) is str for k in revocate):
        raise ExportError("revocate: list of kids")
    lista = sorted(set(revocate))
    if len(lista) != len(revocate) or not revocate_valide(lista):
        raise ExportError("revocate: kids of 32 lowercase hex digits, no duplicates")
    iat = int(time.time()) if adesso is None else adesso
    if type(iat) is not int or iat < 0:
        raise ExportError("adesso: integer >= 0")
    for ruolo, f in zip(RUOLI, (issuer, ts, politica)):
        if f.kid.hex() in lista:
            raise ExportError("the %s key is among the revoked: export refused" % ruolo)
        if not validita[ruolo][0] <= iat <= validita[ruolo][1]:
            raise ExportError("the %s key is outside its validity at export time" % ruolo)
    return iat, lista


def scrivi_cartella(esito: dict, cartella: str) -> None:
    """One Transparent Statement per file (ts_000000.cose …) + manifest.json (public data only)."""
    os.makedirs(cartella, exist_ok=True)
    for i, t in enumerate(esito["transparent"]):
        with open(os.path.join(cartella, "ts_%06d.cose" % i), "wb") as f:
            f.write(t)
    man = {"profilo": esito["politica"]["profilo"], "sub": esito["sub"], "tree_size": esito["tree_size"],
           "radice_sha256": esito["radice"].hex(), "politica": esito["politica"],
           "chiavi_pubbliche_da_confrontare_fuori_banda": esito["chiavi_pubbliche"]}
    with open(os.path.join(cartella, "manifest.json"), "wb") as f:
        f.write(json_canonico(man) + b"\n")
    if "consistenza" in esito:   # amendment 11c
        with open(os.path.join(cartella, "consistenza.json"), "wb") as f:
            f.write(json_canonico(esito["consistenza"]) + b"\n")


def _intervallo(testo: str):
    """«YYYY-MM-DDTHH:MM:SSZ/YYYY-MM-DDTHH:MM:SSZ» → (dal, fino) in UTC seconds; anything else = ExportError."""
    from datetime import datetime, timezone
    parti = testo.split("/")
    if len(parti) != 2:
        raise ExportError("validity: FROM/UNTIL")
    out = []
    for x in parti:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", x):
            raise ExportError("validity: YYYY-MM-DDTHH:MM:SSZ")
        try:
            out.append(int(datetime.strptime(x, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()))
        except ValueError:
            raise ExportError("validity: nonexistent date") from None
    return out[0], out[1]


def _crea_uscita(cartella: str) -> None:
    """review SCITT2 P2 (CLI): the output directory is NEW, created atomically before writing salts or files.
    Existing (including the directory of the export being extended) = refusal: no old files mixed in, no previous
    export overwritten, two processes on the same output = only one proceeds."""
    try:
        os.mkdir(cartella, 0o755)
    except FileExistsError:
        raise ExportError("output already exists: a new directory is needed (the export does not overwrite)") from None
    except OSError as e:
        raise ExportError("output cannot be created (%s)" % type(e).__name__) from None


def scrivi_sali(sali: Sequence[bytes], percorso: str) -> None:
    """Amendment 10b: NEW file (O_EXCL, no links), 0600, one line {"idx", "sale"} per ledger line."""
    try:
        fd = os.open(percorso, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except (OSError, ValueError) as e:
        raise ExportError("salts: file cannot be created (%s): it must be new" % type(e).__name__) from None
    with os.fdopen(fd, "wb") as f:
        for n, s in enumerate(sali):
            f.write(json_canonico({"idx": n, "sale": s.hex()}) + b"\n")


def leggi_sali(percorso: str) -> List[bytes]:
    """The file of scrivi_sali, closed form: consecutive idx from 0, sale of 64 hex digits."""
    try:
        from pq_scitt import strict_json
    except ImportError:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from pq_scitt import strict_json
    out = []
    # review SCITT2 P4: only a regular file, opened without blocking (a FIFO blocked forever)
    try:
        fd = os.open(percorso, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except (OSError, ValueError, TypeError) as e:
        raise ExportError("salts: file not readable (%s)" % type(e).__name__) from None
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ExportError("salts: not a regular file")
    with os.fdopen(fd, "rb") as f:
        dati = f.read()
    tutte = []
    try:
        for n, riga in enumerate(dati.splitlines(), 1):
            if riga.strip():
                tutte.append(strict_json.loads_object(riga))
    except strict_json.StrictJSONError as e:
        raise ExportError("salts: line %d %s" % (n, e)) from None
    for n, r in enumerate(tutte):
        if (not isinstance(r, dict) or set(r) != {"idx", "sale"} or type(r["idx"]) is not int or r["idx"] != n
                or type(r["sale"]) is not str or not RE_HEX64.fullmatch(r["sale"])):
            raise ExportError("salts: line %d out of form" % n)
        out.append(bytes.fromhex(r["sale"]))
    return out


def _main_estendi(p, a) -> int:
    """CLI of estendi(): three persistent keys, the policy comes from the previous export."""
    uri = (a.chiave_issuer, a.chiave_ts, a.chiave_politica)
    if any(u is None for u in uri):
        p.error("--estendi needs the three keys of the previous export")
    try:
        from pq_scitt import strict_json
    except ImportError:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from pq_scitt import strict_json
    try:
        issuer, ts, politica = (carica_firmatario(u, a.alg) for u in uri)
        vecchi = leggi_sali(a.sali_precedenti) if a.sali_precedenti is not None else None
        righe = strict_json.load_jsonl(a.registro)
        esito = estendi(a.estendi, righe, nome=a.nome, formato=a.formato, payload=a.payload, issuer=issuer, ts=ts,
                        politica=politica, iss_issuer=a.iss, iss_ts=a.iss_ts, sali_precedenti=vecchi)
        if (esito["sali"] is None) != (a.sali is None):
            raise ExportError("--sali is needed if and only if the export has commitments (/2 riservato)")
        _crea_uscita(a.uscita)
        if esito["sali"] is not None:
            scrivi_sali(esito["sali"], a.sali)
    except (ExportError, strict_json.StrictJSONError) as e:
        print("REFUSED %s" % e)
        return 1
    except OSError as e:
        print("REFUSED ledger not readable: %s" % type(e).__name__)
        return 1
    scrivi_cartella(esito, a.uscita)
    c = esito["consistenza"]
    print("extension %d -> %d leaves, root %s, consistenza.json written" % (c["precedente"]["tree_size"],
                                                                                c["attuale"]["tree_size"],
                                                                                c["attuale"]["radice"]))
    return 0


def _main(argv=None) -> int:
    import argparse
    try:
        from pq_scitt import strict_json
    except ImportError:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from pq_scitt import strict_json
    class _UnaVolta(argparse.Action):   # review A2: repeated --payload/--chiave-* = error (before, the last one won)
        def __call__(self, parser, ns, valore, opzione=None):
            if getattr(ns, self.dest) is not None:
                parser.error("%s repeated" % opzione)
            setattr(ns, self.dest, valore)
    p = argparse.ArgumentParser(prog="pq-scitt export",
                                description="Exports a hash-chained JSONL ledger as SCITT Transparent Statements. "
                                "The ledger is only read. Keys: three URIs (file:/pkcs11:/awskms:/awskms-http:/"
                                "vault:/nethsm:/awskms-mldsa65:) or --effimere (the private keys are not saved).")
    p.add_argument("registro")
    p.add_argument("uscita")
    p.add_argument("--nome", required=True)
    p.add_argument("--formato", choices=tuple(CTY_DI_FORMATO), default="ops")
    p.add_argument("--payload", choices=MODI_PAYLOAD, required=True, action=_UnaVolta,
                   help="chiaro = the whole line; riservato = only idx, prev_hash, self_hash")
    p.add_argument("--alg", type=int, choices=(ALG_ED25519, ALG_EDDSA, ALG_MLDSA65), default=ALG_ED25519)
    p.add_argument("--iss", default="pq-scitt.issuer.local")
    p.add_argument("--iss-ts", default="pq-scitt.ts.local")
    p.add_argument("--chiave-issuer", action=_UnaVolta)
    p.add_argument("--chiave-ts", action=_UnaVolta)
    p.add_argument("--chiave-politica", action=_UnaVolta)
    p.add_argument("--effimere", action="store_true", help="new keys at every export, never saved")
    p.add_argument("--versione", type=int, choices=VERSIONI, action=_UnaVolta,
                   help="2 (default): iat, validity and revoked kids; riservato with a salt per line. 1: old format")
    for ruolo in RUOLI:
        p.add_argument("--validita-" + ruolo, action=_UnaVolta, metavar="DAL/FINO",
                       help="version 2: YYYY-MM-DDTHH:MM:SSZ/YYYY-MM-DDTHH:MM:SSZ, at most 366 days")
    p.add_argument("--revocata", action="append", default=[], metavar="KID", help="version 2: revoked kid (repeatable)")
    p.add_argument("--sali", action=_UnaVolta,
                   help="version 2 riservato: NEW file (0600) for salts, outside the output")
    p.add_argument("--estendi", action=_UnaVolta, metavar="CARTELLA",
                   help="extends the export in CARTELLA with the new lines and writes consistenza.json (amendment 11)")
    p.add_argument("--sali-precedenti", action=_UnaVolta,
                   help="with --estendi, /2 riservato: salts of the previous export")
    a = p.parse_args(argv)
    if a.estendi is not None:
        if (a.versione is not None or a.revocata or a.effimere
                or any(getattr(a, "validita_" + r) for r in RUOLI)):
            p.error("--estendi uses the policy of the previous export: no --versione, --validita-*, --revocata, "
                    "--effimere")
        if a.sali is not None:
            u, s_ = os.path.realpath(a.uscita), os.path.realpath(a.sali)
            if os.path.commonpath([u, s_]) == u:
                p.error("--sali must be outside the output directory")
        return _main_estendi(p, a)
    if a.sali_precedenti is not None:
        p.error("--sali-precedenti only with --estendi")
    if a.versione is None:
        a.versione = 2
    if a.versione == 1 and (a.revocata or a.sali or any(getattr(a, "validita_" + r) for r in RUOLI)):
        p.error("--validita-*, --revocata and --sali exist only with --versione 2")
    if a.versione == 2 and (a.sali is None) != (a.payload != "riservato"):
        p.error("--sali is needed with --versione 2 --payload riservato, and only there")
    if a.sali is not None:
        u, s_ = os.path.realpath(a.uscita), os.path.realpath(a.sali)
        if os.path.commonpath([u, s_]) == u:
            p.error("--sali must be outside the output directory")
    uri = (a.chiave_issuer, a.chiave_ts, a.chiave_politica)
    try:
        if all(u is None for u in uri):
            if not a.effimere:
                p.error("--chiave-issuer, --chiave-ts and --chiave-politica are needed, or --effimere")

            def nuovo():
                if a.alg == ALG_MLDSA65:
                    return firmatario_mldsa65(mldsa.MLDSA65PrivateKey.generate())
                return firmatario_ed25519(ed25519.Ed25519PrivateKey.generate(), a.alg)
            issuer, ts, politica = nuovo(), nuovo(), nuovo()
        else:
            if a.effimere or any(u is None for u in uri):
                p.error("three keys or --effimere, not a mix")
            issuer, ts, politica = (carica_firmatario(u, a.alg) for u in uri)
        opz = {}
        if a.versione == 2:
            adesso = int(time.time())
            validita = {}
            for ruolo in RUOLI:
                testo = getattr(a, "validita_" + ruolo)
                if testo is None:
                    if not a.effimere:   # amendment 9d: validity belongs to the persistent key, it must be given
                        p.error("--versione 2 with persistent keys: --validita-issuer, --validita-ts and "
                                "--validita-politica are needed")
                    validita[ruolo] = (adesso, adesso + 365 * 86400)
                else:
                    validita[ruolo] = _intervallo(testo)
            opz = dict(versione=2, validita=validita, revocate=list(a.revocata), adesso=adesso)
        elif a.payload == "riservato":
            print("WARNING format 1: riservato is NOT confidential against predictable ledgers: "
                  "a guessed line is confirmed by its hash")
        righe = strict_json.load_jsonl(a.registro)
        esito = esporta(righe, nome=a.nome, formato=a.formato, issuer=issuer, ts=ts, politica=politica,
                        iss_issuer=a.iss, iss_ts=a.iss_ts, payload=a.payload, **opz)
        _crea_uscita(a.uscita)
        if esito["sali"] is not None:
            scrivi_sali(esito["sali"], a.sali)
    except (ExportError, strict_json.StrictJSONError) as e:
        print("REFUSED %s" % e)
        return 1
    except OSError as e:
        print("REFUSED ledger not readable: %s" % type(e).__name__)
        return 1
    scrivi_cartella(esito, a.uscita)
    print("exported %d Transparent Statements, root %s" % (esito["tree_size"], esito["radice"].hex()))
    return 0


if __name__ == "__main__":
    sys.exit(_main())
