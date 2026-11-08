#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pq_scitt/scitt/verify.py — CLOSED verifier of the omega-scitt/1 Transparent Statements (08/11/2026).

Rules written before the code. Every input outside the profile = rejection with a reason
(closed list MOTIVI). The expected algorithm is REQUIRED (argument without default) both for the statement and for the
receipt; the trusted keys are maps kid → (alg, raw public key). On bytes input it raises no exceptions.

Steps (RFC 9942 §5.2.1, "two sequential steps"): (1) the inclusion proof applied to the bytes of the leaf (Signed
Statement with empty unprotected header, RFC 9943 §6.3) gives a root, with the algorithm of RFC 9162 §2.1.3.2;
(2) the receipt signature is verified with that root as detached payload. Then the statement signature (RFC 9943
§7.1: "Relying Parties MUST apply the verification process as described in Section 4.4 of RFC 9052").

Profile amendments 5-6 (08/11): empty inclusion path rejected (RFC 9942 `[ + bstr ]`); sub only
`omega-ledger:[a-z0-9][a-z0-9._-]{0,63}`; payload `riservato` (cty ledger-link: only idx, prev_hash, self_hash);
policy document of closed shape.

Amendments 9-10 (08/11 evening), profile `omega-scitt/2`: iat (CWT 6) in every signature, validity of every key and
revoked kids in the policy (plus a list given from outside): `chiave_revocata`, `chiave_fuori_validita`. Payload
`riservato` /2 = {idx, impegno}: without salts the shape and idx are checked; with lines and salts every commitment and
the chain.

Dependency: `pq_scitt/ed25519_order.py` through pq_scitt/ed25519_keys.py; without it, the import fails.
"""
from __future__ import annotations

import hashlib
import os
import stat
import sys
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

try:
    from pq_scitt.scitt import cbor as cbor
    from pq_scitt import ed25519_keys, strict_json
    from pq_scitt.scitt import export as sx
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from pq_scitt.scitt import cbor as cbor
    from pq_scitt import ed25519_keys, strict_json
    from pq_scitt.scitt import export as sx

MOTIVI = cbor.MOTIVI + (
    "non_cose_sign1", "forma_cose", "alg_atteso_mancante", "alg_non_atteso", "kid_ignoto", "kid_altro_alg",
    "header_protetto_fuori_profilo", "header_non_protetto_fuori_profilo", "cty_fuori_profilo", "cwt_fuori_profilo",
    "iss_fuori_profilo", "receipt_assente", "troppe_receipt", "vds_non_ammesso", "vdp_fuori_profilo",
    "prova_fuori_profilo", "indice_oltre_albero", "percorso_lunghezza", "payload_receipt_attaccato",
    "payload_statement_assente", "firma_lunghezza", "chiave_ed25519_rifiutata", "firma_receipt_non_valida",
    "firma_statement_non_valida", "sub_diversi", "radice_non_attesa", "tree_size_non_atteso",
    "payload_non_json", "catena_riga_non_valida", "politica_fuori_profilo", "tree_size_non_firmato",
    "chiave_revocata", "chiave_fuori_validita", "revocate_fuori_forma", "impegno_non_valido",
    "politica_diversa", "consistenza_fuori_forma", "testa_non_firmata", "tree_size_non_cresce", "consistenza_non_valida",
)

PROT_STATEMENT = frozenset({sx.H_ALG, sx.H_CTY, sx.H_KID, sx.H_CWT})
PROT_RECEIPT = frozenset({sx.H_ALG, sx.H_KID, sx.H_CWT, sx.H_VDS, sx.H_TREE_SIZE_FIRMATO})
MAX_PERCORSO = 64


@dataclass
class Esito:
    ok: bool
    motivo: Optional[str] = None
    dettaglio: str = ""
    campi: Dict = field(default_factory=dict)


class _Rifiuto(Exception):
    def __init__(self, motivo: str, dettaglio: str = ""):
        assert motivo in MOTIVI, motivo
        self.motivo, self.dettaglio = motivo, dettaglio


def _int(v) -> bool:
    return type(v) is int


def _sign1(dati, cosa: str) -> Tuple[bytes, dict, dict, object, bytes]:
    try:
        t = cbor.loads(dati) if not isinstance(dati, cbor.Tag) else dati
    except cbor.CBORError as e:
        raise _Rifiuto(e.motivo, cosa) from None
    if not isinstance(t, cbor.Tag) or t.tag != cbor.TAG_COSE_SIGN1:
        raise _Rifiuto("non_cose_sign1", cosa)
    v = t.value
    if not isinstance(v, list) or len(v) != 4:
        raise _Rifiuto("forma_cose", cosa)
    prot_b, nonprot, payload, firma = v
    if not isinstance(prot_b, bytes) or not isinstance(nonprot, dict) or not isinstance(firma, bytes):
        raise _Rifiuto("forma_cose", cosa)
    if payload is not None and not isinstance(payload, bytes):
        raise _Rifiuto("forma_cose", cosa + " payload")
    try:
        prot = cbor.loads(prot_b)
    except cbor.CBORError as e:
        raise _Rifiuto(e.motivo, cosa + " protected header") from None
    if not isinstance(prot, dict):
        raise _Rifiuto("forma_cose", cosa + " protected header not a map")
    return prot_b, prot, nonprot, payload, firma


def _cwt(prot: dict, cosa: str) -> Tuple[str, str, Optional[int]]:
    """{1 iss, 2 sub} (profile /1) or {1 iss, 2 sub, 6 iat} (profile /2, amendment 9a); which of the two is decided by
    verifica_cartella with the policy."""
    c = prot.get(sx.H_CWT)
    if not isinstance(c, dict) or set(c) not in ({sx.CWT_ISS, sx.CWT_SUB}, {sx.CWT_ISS, sx.CWT_SUB, sx.CWT_IAT}):
        raise _Rifiuto("cwt_fuori_profilo", cosa)
    iat = c.get(sx.CWT_IAT)
    if sx.CWT_IAT in c and (not _int(iat) or iat < 0):   # also 6: null is outside the profile
        raise _Rifiuto("cwt_fuori_profilo", cosa + " iat")
    iss, sub = c[sx.CWT_ISS], c[sx.CWT_SUB]
    if type(iss) is not str or not (1 <= len(iss) <= 8192):
        raise _Rifiuto("iss_fuori_profilo", cosa)
    if type(sub) is not str or not sx.RE_SUB.fullmatch(sub):
        raise _Rifiuto("cwt_fuori_profilo", cosa + " sub")
    return iss, sub, iat


def _alg_e_chiave(prot: dict, alg_atteso, chiavi: Dict[bytes, Tuple[int, bytes]], cosa: str) -> Tuple[int, bytes]:
    if alg_atteso is None:
        raise _Rifiuto("alg_atteso_mancante", cosa)
    alg = prot.get(sx.H_ALG)
    if not _int(alg) or alg != alg_atteso or alg not in sx.LUNGHEZZA_FIRMA:
        raise _Rifiuto("alg_non_atteso", cosa)
    kid = prot.get(sx.H_KID)
    if not isinstance(kid, bytes) or kid not in chiavi:
        raise _Rifiuto("kid_ignoto", cosa)
    alg_chiave, pub = chiavi[kid]
    if alg_chiave != alg or len(pub) != sx.LUNGHEZZA_CHIAVE[alg] or sx.kid_di(pub) != kid:
        raise _Rifiuto("kid_altro_alg", cosa)
    return alg, pub


def _verifica_firma(alg: int, pub: bytes, firma: bytes, messaggio: bytes, motivo: str, cosa: str) -> None:
    if len(firma) != sx.LUNGHEZZA_FIRMA[alg]:
        raise _Rifiuto("firma_lunghezza", cosa)
    try:
        if alg in (sx.ALG_ED25519, sx.ALG_EDDSA):
            problema = ed25519_keys.signature_problem(pub, firma)
            if problema:
                raise _Rifiuto("chiave_ed25519_rifiutata", cosa + " " + problema)
            ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(firma, messaggio)
        else:
            mldsa.MLDSA65PublicKey.from_public_bytes(pub).verify(firma, messaggio)
    except (InvalidSignature, ValueError):
        raise _Rifiuto(motivo, cosa) from None


def radice_da_prova(foglia: bytes, indice: int, tree_size: int, percorso) -> bytes:
    """RFC 9162 §2.1.3.2, step by step. Raises _Rifiuto if the proof does not close."""
    if indice >= tree_size:
        raise _Rifiuto("indice_oltre_albero")
    fn, sn = indice, tree_size - 1
    r = sx.hash_foglia(foglia)
    for p in percorso:
        if sn == 0:
            raise _Rifiuto("percorso_lunghezza", "too long")
        if fn & 1 or fn == sn:
            r = sx.hash_nodo(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = sx.hash_nodo(r, p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise _Rifiuto("percorso_lunghezza", "too short")
    return r


def _verifica(dati, alg_statement, alg_receipt, chiavi_issuer, chiavi_ts, radice_attesa, tree_size_atteso,
              controllo_dominio) -> Dict:
    prot_b, prot, nonprot, payload, firma = _sign1(dati, "statement")
    if set(prot) != PROT_STATEMENT:
        raise _Rifiuto("header_protetto_fuori_profilo", "statement")
    if set(nonprot) != {sx.H_RECEIPTS}:
        raise _Rifiuto("receipt_assente" if not nonprot else "header_non_protetto_fuori_profilo", "statement")
    cty = prot[sx.H_CTY]
    if type(cty) is not str or cty not in sx.CTY_AMMESSI:
        raise _Rifiuto("cty_fuori_profilo")
    iss, sub, iat = _cwt(prot, "statement")
    lista = nonprot[sx.H_RECEIPTS]
    if not isinstance(lista, list) or not lista:
        raise _Rifiuto("receipt_assente")
    if len(lista) != 1:
        raise _Rifiuto("troppe_receipt", str(len(lista)))
    if not isinstance(lista[0], bytes):
        raise _Rifiuto("forma_cose", "receipt not a bstr")
    if payload is None:
        raise _Rifiuto("payload_statement_assente")

    # Receipt: complete structure BEFORE any computation.
    r_prot_b, r_prot, r_nonprot, r_payload, r_firma = _sign1(lista[0], "receipt")
    if set(r_prot) != PROT_RECEIPT:
        raise _Rifiuto("header_protetto_fuori_profilo", "receipt")
    if not _int(r_prot[sx.H_VDS]) or r_prot[sx.H_VDS] != sx.VDS_RFC9162_SHA256:
        raise _Rifiuto("vds_non_ammesso")
    r_iss, r_sub, r_iat = _cwt(r_prot, "receipt")
    if set(r_nonprot) != {sx.H_VDP}:
        raise _Rifiuto("header_non_protetto_fuori_profilo", "receipt")
    vdp = r_nonprot[sx.H_VDP]
    if not isinstance(vdp, dict) or set(vdp) != {sx.VDP_INCLUSIONE}:
        raise _Rifiuto("vdp_fuori_profilo")
    prove = vdp[sx.VDP_INCLUSIONE]
    if not isinstance(prove, list) or len(prove) != 1 or not isinstance(prove[0], bytes):
        raise _Rifiuto("vdp_fuori_profilo", "exactly one bstr proof")
    try:
        prova = cbor.loads(prove[0])
    except cbor.CBORError as e:
        raise _Rifiuto(e.motivo, "proof") from None
    if (not isinstance(prova, list) or len(prova) != 3 or not _int(prova[0]) or not _int(prova[1])
            or prova[0] < 1 or prova[1] < 0 or not isinstance(prova[2], list) or not prova[2]
            or len(prova[2]) > MAX_PERCORSO
            or any(not isinstance(p, bytes) or len(p) != 32 for p in prova[2])):
        raise _Rifiuto("prova_fuori_profilo")
    tree_size, indice, percorso = prova
    if not _int(r_prot[sx.H_TREE_SIZE_FIRMATO]) or r_prot[sx.H_TREE_SIZE_FIRMATO] != tree_size:
        raise _Rifiuto("tree_size_non_firmato")
    if r_payload is not None:
        raise _Rifiuto("payload_receipt_attaccato")
    r_alg, r_pub = _alg_e_chiave(r_prot, alg_receipt, chiavi_ts, "receipt")
    if r_sub != sub:
        raise _Rifiuto("sub_diversi")

    # Step 1: root from the leaf (statement with empty unprotected header).
    foglia = cbor.dumps(cbor.Tag(cbor.TAG_COSE_SIGN1, [prot_b, {}, payload, firma]))
    radice = radice_da_prova(foglia, indice, tree_size, percorso)
    # Step 2: receipt signature over the root.
    _verifica_firma(r_alg, r_pub, r_firma, sx.sig_structure(r_prot_b, radice), "firma_receipt_non_valida", "receipt")
    if radice_attesa is not None and radice != radice_attesa:
        raise _Rifiuto("radice_non_attesa")
    if tree_size_atteso is not None and tree_size != tree_size_atteso:
        raise _Rifiuto("tree_size_non_atteso")

    # Statement signature.
    s_alg, s_pub = _alg_e_chiave(prot, alg_statement, chiavi_issuer, "statement")
    _verifica_firma(s_alg, s_pub, firma, sx.sig_structure(prot_b, payload), "firma_statement_non_valida", "statement")

    # ledger domain check on the payload (strict JSON + chain of the line).
    dati_payload = None
    if controllo_dominio:
        try:
            dati_payload = strict_json.loads_object(payload)
        except strict_json.StrictJSONError as e:
            raise _Rifiuto("payload_non_json", e.motivo) from None
        if sx.json_canonico(dati_payload) != payload:
            raise _Rifiuto("payload_non_json", "not canonical")
        if cty in (sx.CTY_RIGA_OPS, sx.CTY_RIGA_OPS_SHA3):
            funzione = hashlib.sha256 if cty == sx.CTY_RIGA_OPS else hashlib.sha3_256
            if set(dati_payload) != sx.CAMPI_OPS or dati_payload["self_hash"] != sx.hash_riga_ops(dati_payload, funzione):
                raise _Rifiuto("catena_riga_non_valida")
        elif cty == sx.CTY_COLLEGAMENTO:
            if not sx.collegamento_valido(dati_payload):
                raise _Rifiuto("catena_riga_non_valida", "link out of shape")
        elif cty == sx.CTY_IMPEGNO:
            if not sx.impegno_valido(dati_payload):
                raise _Rifiuto("catena_riga_non_valida", "commitment out of shape")
        elif cty == sx.CTY_EVENTO_CHAIN:
            try:
                ok = (dati_payload["payload_sha3"] == sx.payload_sha3_chain(dati_payload["payload"])
                      and dati_payload["self_hash"] == sx.hash_evento_chain(dati_payload))
            except (KeyError, TypeError):
                ok = False
            if not ok:
                raise _Rifiuto("catena_riga_non_valida")
    return {"iss": iss, "kid": prot[sx.H_KID], "sub": sub, "cty": cty, "ts_iss": r_iss, "tree_size": tree_size, "indice": indice,
            "iat": iat, "ts_iat": r_iat, "ts_kid": r_prot[sx.H_KID],
            "radice": radice.hex(), "foglia_sha256": hashlib.sha256(foglia).hexdigest(), "payload": dati_payload}


def verifica_transparent_statement(dati, *, alg_statement: int, alg_receipt: int,
                                   chiavi_issuer: Dict[bytes, Tuple[int, bytes]],
                                   chiavi_ts: Dict[bytes, Tuple[int, bytes]],
                                   radice_attesa: Optional[bytes] = None, tree_size_atteso: Optional[int] = None,
                                   controllo_dominio: bool = True) -> Esito:
    """Esito(ok, motivo). alg_statement and alg_receipt are required: None = rejection alg_atteso_mancante."""
    try:
        campi = _verifica(dati, alg_statement, alg_receipt, chiavi_issuer or {}, chiavi_ts or {}, radice_attesa,
                          tree_size_atteso, controllo_dominio)
    except _Rifiuto as r:
        return Esito(False, r.motivo, r.dettaglio)
    except RecursionError:
        return Esito(False, "cbor_troppo_profondo")
    return Esito(True, campi=campi)


def _leggi_file(cartella: str, nome: str):
    """review P1: regular files only, opened without blocking (FIFO), limited size; error = rejection Esito."""
    try:
        fd = os.open(os.path.join(cartella, nome), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except OSError as e:
        return Esito(False, "forma_cose", nome + ": " + type(e).__name__)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return Esito(False, "forma_cose", nome + ": not a regular file")
        if st.st_size > cbor.MAX_BYTES:
            return Esito(False, "cbor_troppo_lungo", nome)
        with os.fdopen(fd, "rb") as f:
            fd = -1
            return f.read(cbor.MAX_BYTES + 1)
    except OSError as e:
        return Esito(False, "forma_cose", nome + ": " + type(e).__name__)
    finally:
        if fd >= 0:
            os.close(fd)


def _politica_v2(p: dict, alg_statement: int, chiave_ts, chiave_politica):
    """Amendment 9b: closed shape of the /2 policy. Returns {kid: (dal, fino)} and the set of revoked kids.
    The anchors (shape, kid, iss) are then checked by the common loop. Out of shape = ValueError."""
    if (set(p) != sx.CHIAVI_POLITICA_2 or not isinstance(p["ts"], dict) or set(p["ts"]) != sx.CHIAVI_TS_POLITICA_2
            or not isinstance(p["politica"], dict) or set(p["politica"]) != sx.CHIAVI_CHIAVE_POLITICA_2
            or not sx.revocate_valide(p["revocate"]) or not isinstance(p["ancore"], list)):
        raise ValueError
    validita = {}
    for voce, kid_atteso, alg_atteso in ((p["ts"], sx.kid_di(chiave_ts[1]).hex(), chiave_ts[0]),
                                         (p["politica"], sx.kid_di(chiave_politica[1]).hex(), chiave_politica[0])):
        if voce["kid"] != kid_atteso or voce["alg"] != alg_atteso:
            raise ValueError
        validita[voce["kid"]] = (voce["valida_dal"], voce["valida_fino"])
    if len(validita) != 2:   # review SCITT2 P1: one key per role (the export enforces it, RFC 9943 §9.4)
        raise ValueError
    for a in p["ancore"]:   # anchor shape: checked by the common loop (CHIAVI_ANCORA_2); here KeyError/TypeError
        if a["kid"] in validita:   # same kid in two roles: one window would silently cover the other
            raise ValueError
        validita[a["kid"]] = (a["valida_dal"], a["valida_fino"])
    if not all(sx.validita_valida(dal, fino) for dal, fino in validita.values()):
        raise ValueError
    return validita, set(p["revocate"])


def _chiave_nel_tempo(versione: int, kid: bytes, iat, validita: dict, revocate: set, cosa: str) -> Optional[Esito]:
    """Amendment 9c. Version 1: no iat. Version 2: iat present, kid not revoked, iat within the validity."""
    if versione == 1:
        if kid.hex() in revocate:
            return Esito(False, "chiave_revocata", cosa)
        return None if iat is None else Esito(False, "cwt_fuori_profilo", cosa + " iat in profile /1")
    if iat is None:
        return Esito(False, "cwt_fuori_profilo", cosa + " iat missing in profile /2")
    if kid.hex() in revocate:
        return Esito(False, "chiave_revocata", cosa)
    dal, fino = validita[kid.hex()]
    if not dal <= iat <= fino:
        return Esito(False, "chiave_fuori_validita", cosa)
    return None


def _tempo_di(e: Esito, versione, validita, revocate, cosa: str) -> Optional[Esito]:
    """The signature of the statement and that of its receipt."""
    return (_chiave_nel_tempo(versione, e.campi["kid"], e.campi["iat"], validita, revocate, cosa + " statement")
            or _chiave_nel_tempo(versione, e.campi["ts_kid"], e.campi["ts_iat"], validita, revocate, cosa + " receipt"))


def verifica_cartella(cartella: str, *, alg_statement: int, alg_receipt: int, chiave_ts: Tuple[int, bytes],
                      chiave_politica: Tuple[int, bytes], revocate_esterne=(), righe=None, sali=None) -> Esito:
    """A whole export: leaf 0 = policy signed by the trusted policy key; the anchors of the policy become the
    Issuer keys; all leaves 0..n-1 present once, same root and same tree_size (a single tree).
    The TS and policy keys come from OUTSIDE (fixed by the verifier), not from the manifest.
    revocate_esterne: revoked hex kids given from outside (revocation channel, amendment 9c/9e). righe + sali: /2
    riservato export, verification of the commitments and of the chain (amendment 10d)."""
    if (not isinstance(revocate_esterne, (list, tuple, set, frozenset))
            or not all(type(k) is str and sx.RE_KID.fullmatch(k) for k in revocate_esterne)):
        return Esito(False, "revocate_fuori_forma")
    if (righe is None) != (sali is None):
        return Esito(False, "impegno_non_valido", "both the lines and the salts are needed")
    try:
        nomi = sorted(n for n in os.listdir(cartella) if n.endswith(".cose"))
    except OSError as e:
        return Esito(False, "forma_cose", "folder: " + type(e).__name__)
    if not nomi:
        return Esito(False, "receipt_assente", "empty folder")
    ts = {sx.kid_di(chiave_ts[1]): chiave_ts}
    pol = {sx.kid_di(chiave_politica[1]): chiave_politica}
    dati0 = _leggi_file(cartella, nomi[0])
    if isinstance(dati0, Esito):
        return dati0
    e0 = verifica_transparent_statement(dati0, alg_statement=chiave_politica[0], alg_receipt=alg_receipt,
                                        chiavi_issuer=pol, chiavi_ts=ts)
    if not e0.ok:
        return e0
    if e0.campi["cty"] != sx.CTY_POLITICA or e0.campi["indice"] != 0:
        return Esito(False, "politica_fuori_profilo", "leaf 0")
    p = e0.campi["payload"]
    try:
        # Amendment 9: the version is given by the profile of leaf 0.
        versione = {sx.PROFILO: 1, sx.PROFILO_2: 2}[p["profilo"]]
        validita, revocate = {}, set()
        if versione == 2:
            validita, revocate = _politica_v2(p, alg_statement, chiave_ts, chiave_politica)
        # Amendment 6d: closed shape of the policy, extra keys do not pass silently.
        elif set(p) != sx.CHIAVI_POLITICA or not isinstance(p["ts"], dict) or set(p["ts"]) != sx.CHIAVI_TS_POLITICA:
            raise ValueError
        if (not isinstance(p["ancore"], list) or not p["ancore"]
                or p["vds"] != "RFC9162_SHA256" or p["payload"] not in sx.MODI_PAYLOAD
                or p["formato"] not in sx.CTY_DI_FORMATO):
            raise ValueError
        issuer, iss_di = {}, {}
        for a in p["ancore"]:
            if not isinstance(a, dict) or set(a) != (sx.CHIAVI_ANCORA if versione == 1 else sx.CHIAVI_ANCORA_2):
                raise ValueError
            pub = bytes.fromhex(a["pub"])
            if a["alg"] != alg_statement or sx.kid_di(pub).hex() != a["kid"] or type(a["iss"]) is not str:
                raise ValueError
            issuer[sx.kid_di(pub)] = (a["alg"], pub)
            iss_di[sx.kid_di(pub)] = a["iss"]
        if p["ts"]["kid"] != sx.kid_di(chiave_ts[1]).hex():
            raise ValueError
        # review P1: the policy rule (single cty of the ledger) is reproduced, not just read.
        cty_politica = [c for c in sx.CTY_DI_RIGA if " cty " + c + "," in p["regola"]]
        if len(cty_politica) != 1:
            raise ValueError
        atteso = ({1: sx.CTY_COLLEGAMENTO, 2: sx.CTY_IMPEGNO}[versione] if p["payload"] == "riservato"
                  else sx.CTY_DI_FORMATO[p["formato"]])
        if cty_politica[0] != atteso:
            raise ValueError
    except (KeyError, TypeError, ValueError):
        return Esito(False, "politica_fuori_profilo", "content")
    revocate |= set(revocate_esterne)
    tempo = _tempo_di(e0, versione, validita, revocate, nomi[0])
    if tempo:
        return tempo
    n, radice = e0.campi["tree_size"], bytes.fromhex(e0.campi["radice"])
    if len(nomi) != n:
        return Esito(False, "tree_size_non_atteso", "%d files for %d leaves" % (len(nomi), n))
    visti = {0}
    payloads = {}
    for nome in nomi[1:]:
        dati = _leggi_file(cartella, nome)
        if isinstance(dati, Esito):
            return dati
        e = verifica_transparent_statement(dati, alg_statement=alg_statement, alg_receipt=alg_receipt,
                                           chiavi_issuer=issuer, chiavi_ts=ts, radice_attesa=radice,
                                           tree_size_atteso=n)
        if not e.ok:
            return Esito(False, e.motivo, nome + " " + e.dettaglio)
        if e.campi["cty"] == sx.CTY_POLITICA or e.campi["indice"] in visti or e.campi["sub"] != e0.campi["sub"]:
            return Esito(False, "politica_fuori_profilo", nome)
        if e.campi["cty"] != cty_politica[0] or e.campi["iss"] != iss_di[e.campi["kid"]]:
            return Esito(False, "politica_fuori_profilo", nome + " cty or iss differ from the policy")
        tempo = _tempo_di(e, versione, validita, revocate, nome)
        if tempo:
            return tempo
        visti.add(e.campi["indice"])
        payloads[e.campi["indice"]] = e.campi["payload"]
    # review P1: the ledger hash chain is recomputed over the whole ledger (leaf i+1 = line i), as the rule says.
    pubblici = [payloads[i] for i in range(1, n)]
    impegni = versione == 2 and p["payload"] == "riservato"
    if impegni:
        # Amendment 10d: without salts the chain is not visible; shape and consecutive idx from 0.
        if any(d["idx"] != i for i, d in enumerate(pubblici)):
            return Esito(False, "catena_riga_non_valida", "commitment idx not consecutive")
    else:
        formato = "collegamento" if p["payload"] == "riservato" else p["formato"]
        motivo = sx.verifica_catena(pubblici, formato)
        if motivo:
            return Esito(False, "catena_riga_non_valida", motivo)
    if righe is not None:
        if not impegni:
            return Esito(False, "impegno_non_valido", "lines and salts given for an export without commitments")
        if (not isinstance(righe, (list, tuple)) or not isinstance(sali, (list, tuple))
                or len(righe) != len(pubblici) or len(sali) != len(pubblici)):
            return Esito(False, "impegno_non_valido", "one line and one salt are needed for each commitment")
        for i, (r, s, d) in enumerate(zip(righe, sali, pubblici)):
            try:
                if sx.impegno_riga(s, r) != d["impegno"]:
                    return Esito(False, "impegno_non_valido", "line %d" % i)
            except (sx.ExportError, TypeError, ValueError):
                return Esito(False, "impegno_non_valido", "line %d out of shape" % i)
        if len(set(sali)) != len(sali):   # review SCITT2 P3: one salt per line (amendment 10a), repeated = rejection
            return Esito(False, "impegno_non_valido", "repeated salts")
        motivo = sx.verifica_catena(righe, p["formato"])
        if motivo:
            return Esito(False, "catena_riga_non_valida", motivo)
    return Esito(True, campi={"tree_size": n, "radice": radice.hex(), "sub": e0.campi["sub"], "profilo": p["profilo"]})


def consistenza_regge(m: int, n: int, radice_m: bytes, radice_n: bytes, percorso) -> bool:
    """RFC 9162 §2.1.4.2, step by step (0 < m < n)."""
    if not 0 < m < n or not percorso:                                   # step 1
        return False
    percorso = list(percorso)
    if m & (m - 1) == 0:                                                # step 2: m power of 2
        percorso = [radice_m] + percorso
    fn, sn = m - 1, n - 1                                               # step 3
    while fn & 1:                                                       # step 4
        fn >>= 1
        sn >>= 1
    fr = sr = percorso[0]                                               # step 5
    for c in percorso[1:]:                                              # step 6
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = sx.hash_nodo(c, fr)
            sr = sx.hash_nodo(c, sr)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = sx.hash_nodo(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == radice_m and sr == radice_n and sn == 0                # step 7


def _testa_valida(t) -> bool:
    return (isinstance(t, dict) and set(t) == {"tree_size", "radice"} and _int(t["tree_size"]) and t["tree_size"] >= 1
            and type(t["radice"]) is str and sx.RE_HEX64.fullmatch(t["radice"]) is not None)


def verifica_consistenza(vecchia: str, nuova: str, *, alg_statement: int, alg_receipt: int,
                         chiave_ts: Tuple[int, bytes], chiave_politica: Tuple[int, bytes], revocate_esterne=()) -> Esito:
    """Amendment 11d: the export in `nuova` extends the one in `vecchia` (consistenza.json in `nuova`)."""
    arg = dict(alg_statement=alg_statement, alg_receipt=alg_receipt, chiave_ts=chiave_ts,
               chiave_politica=chiave_politica, revocate_esterne=revocate_esterne)
    teste = []
    for nome, c in (("vecchia", vecchia), ("nuova", nuova)):
        e = verifica_cartella(c, **arg)
        if not e.ok:
            return Esito(False, e.motivo, nome + ": " + e.dettaglio)
        teste.append(e.campi)
    foglie0 = []
    for c in (vecchia, nuova):
        dati = _leggi_file(c, "ts_000000.cose")
        if isinstance(dati, Esito):
            return dati
        foglie0.append(sx._foglia_da_file(dati))
    if foglie0[0] != foglie0[1]:
        return Esito(False, "politica_diversa", "leaf 0")
    dati = _leggi_file(nuova, "consistenza.json")
    if isinstance(dati, Esito):
        return Esito(False, "consistenza_fuori_forma", dati.dettaglio)
    try:
        doc = strict_json.loads_object(dati)
    except strict_json.StrictJSONError as e:
        return Esito(False, "consistenza_fuori_forma", e.motivo)
    if (set(doc) != {"profilo", "sub", "precedente", "attuale", "percorso"} or not _testa_valida(doc["precedente"])
            or not _testa_valida(doc["attuale"]) or not isinstance(doc["percorso"], list)
            or not 1 <= len(doc["percorso"]) <= MAX_PERCORSO
            or not all(type(h) is str and sx.RE_HEX64.fullmatch(h) for h in doc["percorso"])
            or doc["profilo"] not in (sx.PROFILO, sx.PROFILO_2)):
        return Esito(False, "consistenza_fuori_forma")
    vt, nt = teste
    if (doc["sub"] != vt["sub"] or doc["sub"] != nt["sub"] or doc["profilo"] != nt["profilo"]
            or doc["precedente"] != {"tree_size": vt["tree_size"], "radice": vt["radice"]}
            or doc["attuale"] != {"tree_size": nt["tree_size"], "radice": nt["radice"]}):
        return Esito(False, "testa_non_firmata")
    m, n = vt["tree_size"], nt["tree_size"]
    if n <= m:
        return Esito(False, "tree_size_non_cresce", "%d -> %d" % (m, n))
    if not consistenza_regge(m, n, bytes.fromhex(vt["radice"]), bytes.fromhex(nt["radice"]),
                             [bytes.fromhex(h) for h in doc["percorso"]]):
        return Esito(False, "consistenza_non_valida")
    return Esito(True, campi={"precedente": m, "attuale": n, "radice": nt["radice"], "sub": nt["sub"]})


def _main(argv=None) -> int:
    """pq-scitt verify CARTELLA --alg -19 --ts-pub HEX --politica-pub HEX
    The public keys of the TS and of the policy are given from OUTSIDE (they are not read from the manifest)."""
    import argparse
    p = argparse.ArgumentParser(prog="pq-scitt verify",
                                description="Verify an omega-scitt/1 or /2 folder (export of pq-scitt export).")
    p.add_argument("cartella")
    p.add_argument("--alg", type=int, required=True, choices=(sx.ALG_ED25519, sx.ALG_EDDSA, sx.ALG_MLDSA65))
    p.add_argument("--ts-pub", required=True)
    p.add_argument("--politica-pub", required=True)
    p.add_argument("--revocata", action="append", default=[], metavar="KID",
                   help="revoked kid given from outside (repeatable, amendment 9)")
    p.add_argument("--registro", help="profile /2 riservato: the JSONL ledger, with --sali")
    p.add_argument("--sali", help="profile /2 riservato: the salts file of the export, with --registro")
    p.add_argument("--consistenza", metavar="VECCHIA",
                   help="verify that CARTELLA extends the export in VECCHIA (consistenza.json, amendment 11)")
    a = p.parse_args(argv)
    try:
        ts, pol = bytes.fromhex(a.ts_pub), bytes.fromhex(a.politica_pub)
    except ValueError:
        print("REFUSED chiave_non_hex")
        return 2
    if (a.registro is None) != (a.sali is None):
        p.error("--registro and --sali go together")
    if a.consistenza is not None:
        if a.registro is not None:
            p.error("--consistenza does not go with --registro/--sali")
        e = verifica_consistenza(a.consistenza, a.cartella, alg_statement=a.alg, alg_receipt=a.alg,
                                 chiave_ts=(a.alg, ts), chiave_politica=(a.alg, pol), revocate_esterne=a.revocata)
        if e.ok:
            print("OK %s extends %s: %d -> %d leaves, root %s" % (a.cartella, a.consistenza, e.campi["precedente"],
                                                                    e.campi["attuale"], e.campi["radice"]))
            return 0
        print("REFUSED %s %s" % (e.motivo, e.dettaglio))
        return 1
    righe = sali = None
    if a.registro is not None:
        try:
            righe, sali = strict_json.load_jsonl(a.registro), sx.leggi_sali(a.sali)
        except (strict_json.StrictJSONError, sx.ExportError, OSError) as e:
            print("REFUSED impegno_non_valido %s" % (e if not isinstance(e, OSError) else type(e).__name__))
            return 1
    e = verifica_cartella(a.cartella, alg_statement=a.alg, alg_receipt=a.alg, chiave_ts=(a.alg, ts),
                          chiave_politica=(a.alg, pol), revocate_esterne=a.revocata, righe=righe, sali=sali)
    if e.ok:
        print("OK %d leaves, root %s, sub %s, %s%s" % (e.campi["tree_size"], e.campi["radice"], e.campi["sub"],
              e.campi["profilo"], ", commitments and chain verified with the salts" if righe is not None else ""))
        return 0
    print("REFUSED %s %s" % (e.motivo, e.dettaglio))
    return 1


if __name__ == "__main__":
    sys.exit(_main())
