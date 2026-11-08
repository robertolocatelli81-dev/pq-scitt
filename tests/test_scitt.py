#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests of pq_scitt/scitt/cbor.py, pq_scitt/scitt/export.py, pq_scitt/scitt/verify.py (O4 SCITT, 08/11/2026).

Positive control first (a good export passes), then every alteration of the profile must fail with the expected
reason, then generative tests (≥ 20,000 mutants) with the positive control of the bench itself (a deliberately
broken verifier must be caught). Real ledgers are used on a COPY in a temporary folder, sha256 before = after.
"""
import hashlib
import os
import random
import shutil
import sys
import tempfile
import threading
import unittest

RADICE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RADICE)
# origin lines: the modules come from the installed pq_scitt package.
sys.path.insert(1, os.path.join(RADICE, "chain"))

from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa  # noqa: E402

from pq_scitt.scitt import cbor as cbor  # noqa: E402
from pq_scitt.scitt import export as sx  # noqa: E402
from pq_scitt.scitt import verify as sv  # noqa: E402
from pq_scitt import strict_json  # noqa: E402


def _firmatario(alg):
    if alg == sx.ALG_MLDSA65:
        return sx.firmatario_mldsa65(mldsa.MLDSA65PrivateKey.generate())
    return sx.firmatario_ed25519(ed25519.Ed25519PrivateKey.generate(), alg)


def _righe_ops(n):
    righe, prev = [], sx.GENESIS
    for i in range(n):
        r = {"idx": i, "ts": "2026-11-08T12:00:%02dZ" % (i % 60), "data": {"evento": "prova", "n": i, "è": "ünicode"},
             "prev_hash": prev}
        r["self_hash"] = sx.hash_riga_ops(r)
        prev = r["self_hash"]
        righe.append(r)
    return righe


def _eventi_chain(nome):
    """Events of the "chain" format produced on 08/11/2026 by the origin implementation of the event chain (not
    included in this repository) and frozen in tests/data/chain_events.json: vectors external to the code under test."""
    import json
    with open(os.path.join(RADICE, "tests", "data", "chain_events.json"), encoding="utf-8") as f:
        return json.load(f)[nome]


class Banco:
    def __init__(self, alg=sx.ALG_ED25519, n=12, righe=None, formato="ops"):
        self.alg = alg
        self.ISS, self.T, self.P = _firmatario(alg), _firmatario(alg), _firmatario(alg)
        self.es = sx.esporta(righe if righe is not None else _righe_ops(n), nome="prova", formato=formato,
                             issuer=self.ISS, ts=self.T, politica=self.P, iss_issuer="omega.issuer", iss_ts="omega.ts")
        self.ki = {self.ISS.kid: (alg, self.ISS.pub)}
        self.kt = {self.T.kid: (alg, self.T.pub)}
        self.kp = {self.P.kid: (alg, self.P.pub)}

    def verifica(self, dati, i=1, **kw):
        arg = dict(alg_statement=self.alg, alg_receipt=self.alg, chiavi_issuer=self.kp if i == 0 else self.ki,
                   chiavi_ts=self.kt)
        arg.update(kw)
        return sv.verifica_transparent_statement(dati, **arg)


def _scomponi(ts):
    t = cbor.loads(ts)
    prot, nonprot, payload, firma = t.value
    rc = cbor.loads(nonprot[394][0])
    prova = cbor.loads(rc.value[1][396][-1][0])
    return t, rc, prova


ALTRA_FOGLIA = b"altra foglia"   # amendment 5: a 1-leaf tree has an empty path, outside the profile


def _con_receipt(ts, rc_value):
    t = cbor.loads(ts)
    p, _, pl, f = t.value
    return cbor.dumps(cbor.Tag(18, [p, {394: [cbor.dumps(cbor.Tag(18, rc_value))]}, pl, f]))


def _con_prova(ts, prova):
    _, rc, _ = _scomponi(ts)
    v = list(rc.value)
    v[1] = {396: {-1: [cbor.dumps(prova)]}}
    return _con_receipt(ts, v)


class TestCBOR(unittest.TestCase):
    def test_andata_ritorno(self):
        v = cbor.Tag(18, [b"\x01", {1: -19, "a": [None, True, False]}, None, b""])
        self.assertEqual(cbor.loads(cbor.dumps(v)), v)

    def test_rifiuti(self):
        casi = {
            b"\x18\x05": "cbor_non_minimo", b"\x19\x00\x10": "cbor_non_minimo", b"\x9f\x01\xff": "cbor_indefinito",
            b"\xa2\x01\x01\x01\x02": "cbor_chiave_ripetuta", b"\xa2\x02\x01\x01\x02": "cbor_chiavi_non_ordinate",
            b"\xf9\x3c\x00": "cbor_float_o_simple", b"\xf7": "cbor_float_o_simple", b"\xc1\x01": "cbor_tag_ignoto",
            b"\x01\x02": "cbor_byte_in_coda", b"\x82\x01": "cbor_troncato", b"\x62\xc3\x28": "cbor_utf8",
            b"\xa1\x41\x00\x01": "cbor_chiave_tipo", b"\x1c": "cbor_info_riservata", b"\x81" * 40: "cbor_troppo_profondo",
            b"\x9b\xff\xff\xff\xff\xff\xff\xff\xff": "cbor_troppi_elementi",
        }
        for dati, motivo in casi.items():
            with self.assertRaises(cbor.CBORError) as c:
                cbor.loads(dati)
            self.assertEqual(c.exception.motivo, motivo, dati.hex())
        with self.assertRaises(cbor.CBORError):
            cbor.loads("non bytes")


class TestRoundTrip(unittest.TestCase):
    def test_tutti_gli_alg(self):
        for alg in (sx.ALG_ED25519, sx.ALG_EDDSA, sx.ALG_MLDSA65):
            b = Banco(alg, n=9)
            for i, ts in enumerate(b.es["transparent"]):
                e = b.verifica(ts, i, radice_attesa=b.es["radice"], tree_size_atteso=10)
                self.assertTrue(e.ok, (alg, i, e))
                self.assertEqual(e.campi["indice"], i)

    def test_merkle_contro_definizione(self):
        # recursive MTH written here directly from RFC 9162 §2.1.1, compared with the stored tree
        def mth(d):
            if len(d) == 1:
                return sx.hash_foglia(d[0])
            k = sx._k(len(d))
            return sx.hash_nodo(mth(d[:k]), mth(d[k:]))
        for n in list(range(1, 40)) + [64, 65, 100]:
            foglie = [bytes([i % 256, i // 256]) for i in range(n)]
            a = sx.AlberoMerkle(foglie)
            self.assertEqual(a.radice(), mth(foglie))
            for m in range(n):
                self.assertEqual(sv.radice_da_prova(foglie[m], m, n, a.percorso(m)), a.radice())

    def test_vettori_rfc6962(self):
        """Roots for 1..8 leaves from transparency-dev/merkle testonly/constants.go (Apache-2.0, see
        NOTICE): third-party vectors, not written by us."""
        foglie = [bytes.fromhex(h) for h in ("", "00", "10", "2021", "3031", "40414243", "5051525354555657",
                                              "606162636465666768696a6b6c6d6e6f")]
        radici = ["6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
                  "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
                  "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
                  "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
                  "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
                  "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
                  "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
                  "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"]
        for n in range(1, 9):
            a = sx.AlberoMerkle(foglie[:n])
            self.assertEqual(a.radice().hex(), radici[n - 1], n)
            for m in range(n):
                self.assertEqual(sv.radice_da_prova(foglie[m], m, n, a.percorso(m)).hex(), radici[n - 1])


class TestControlloPositivo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.b = Banco(n=12)
        cls.altro = Banco(n=12)  # another tree, other keys
        cls.ts = cls.b.es["transparent"][3]

    def _rifiuta(self, dati, motivo, **kw):
        e = self.b.verifica(dati, **kw)
        self.assertFalse(e.ok)
        self.assertEqual(e.motivo, motivo, e)

    def test_buono_passa(self):
        self.assertTrue(self.b.verifica(self.ts).ok)

    def test_statement_alterato(self):
        t = cbor.loads(self.ts)
        pl = bytearray(t.value[2])
        pl[10] ^= 1
        self._rifiuta(cbor.dumps(cbor.Tag(18, [t.value[0], t.value[1], bytes(pl), t.value[3]])),
                      "firma_receipt_non_valida")

    def test_receipt_altro_albero_stesso_ts(self):
        # different tree signed by the SAME TS: a second export is built with the same T
        b2 = sx.esporta(_righe_ops(12), nome="prova", formato="ops", issuer=_firmatario(-19), ts=self.b.T,
                        politica=_firmatario(-19), iss_issuer="omega.issuer", iss_ts="omega.ts")
        _, rc, _ = _scomponi(b2["transparent"][3])
        self._rifiuta(_con_receipt(self.ts, list(rc.value)), "firma_receipt_non_valida")

    def test_receipt_altro_albero_con_radice_fissata(self):
        b3 = sx.esporta(_righe_ops(12), nome="prova", formato="ops", issuer=self.b.ISS, ts=self.b.T,
                        politica=_firmatario(-19), iss_issuer="omega.issuer", iss_ts="omega.ts")
        _, rc, _ = _scomponi(b3["transparent"][3])
        dati = _con_receipt(self.ts, list(rc.value))
        self.assertTrue(self.b.verifica(dati).ok)  # the statement REALLY is in that tree too
        self._rifiuta(dati, "radice_non_attesa", radice_attesa=self.b.es["radice"])

    def test_indice_sbagliato(self):
        _, _, p = _scomponi(self.ts)
        for indice in (2, 4, 0, 12, 99):
            e = self.b.verifica(_con_prova(self.ts, [p[0], indice, p[2]]))
            self.assertFalse(e.ok)
            self.assertIn(e.motivo, ("firma_receipt_non_valida", "percorso_lunghezza", "indice_oltre_albero"))

    def test_tree_size_sbagliato_e_firmato(self):
        _, _, p = _scomponi(self.ts)
        for n in (p[0] + 1, p[0] - 1, p[0] + 3):
            self._rifiuta(_con_prova(self.ts, [n, p[1], p[2]]), "tree_size_non_firmato")

    def test_prova_troncata_e_allungata(self):
        _, _, p = _scomponi(self.ts)
        self._rifiuta(_con_prova(self.ts, [p[0], p[1], p[2][:-1]]), "percorso_lunghezza")
        self._rifiuta(_con_prova(self.ts, [p[0], p[1], p[2] + [b"\x00" * 32]]), "percorso_lunghezza")
        self._rifiuta(_con_prova(self.ts, [p[0], p[1], p[2][:-1] + [b"\x00" * 31]]), "prova_fuori_profilo")

    def test_alg_atteso_obbligatorio(self):
        self._rifiuta(self.ts, "alg_atteso_mancante", alg_receipt=None)
        e = sv.verifica_transparent_statement(self.ts, alg_statement=None, alg_receipt=-19, chiavi_issuer=self.b.ki,
                                              chiavi_ts=self.b.kt)
        self.assertEqual(e.motivo, "alg_atteso_mancante")
        self._rifiuta(self.ts, "alg_non_atteso", alg_receipt=-8)
        self._rifiuta(self.ts, "alg_non_atteso", alg_statement=-49)

    def test_kid(self):
        self._rifiuta(self.ts, "kid_ignoto", chiavi_ts=self.altro.kt)
        self._rifiuta(self.ts, "kid_ignoto", chiavi_issuer=self.altro.ki)
        self._rifiuta(self.ts, "kid_altro_alg", chiavi_ts={self.b.T.kid: (-8, self.b.T.pub)}, alg_receipt=-19)
        self._rifiuta(self.ts, "kid_altro_alg", chiavi_ts={self.b.T.kid: (-19, self.altro.T.pub)})

    def test_receipt_firmata_dall_issuer(self):
        _, rc, _ = _scomponi(self.ts)
        rp = cbor.loads(rc.value[0])
        rp[4] = self.b.ISS.kid
        rpb = cbor.dumps(rp)
        firma = self.b.ISS.firma(sx.sig_structure(rpb, self.b.es["radice"]))
        dati = _con_receipt(self.ts, [rpb, rc.value[1], None, firma])
        self._rifiuta(dati, "kid_ignoto")
        # even trusting the Issuer key as TS, the profile stays correct only if the key is the pinned one
        self.assertTrue(self.b.verifica(dati, chiavi_ts={self.b.ISS.kid: (-19, self.b.ISS.pub)}).ok)

    def test_etichette_ignote(self):
        t, rc, _ = _scomponi(self.ts)
        # unprotected header of the statement
        p, n, pl, f = t.value
        self._rifiuta(cbor.dumps(cbor.Tag(18, [p, dict(n, **{"x": 1}), pl, f])), "header_non_protetto_fuori_profilo")
        self._rifiuta(cbor.dumps(cbor.Tag(18, [p, {}, pl, f])), "receipt_assente")
        self._rifiuta(cbor.dumps(cbor.Tag(18, [p, {394: [n[394][0], n[394][0]]}, pl, f])), "troppe_receipt")
        # unprotected header of the receipt and vdp
        v = list(rc.value)
        v[1] = {**v[1], 999: 1}
        self._rifiuta(_con_receipt(self.ts, v), "header_non_protetto_fuori_profilo")
        v = list(rc.value)
        v[1] = {396: {**v[1][396], -2: []}}
        self._rifiuta(_con_receipt(self.ts, v), "vdp_fuori_profilo")
        # payload attached to the receipt
        v = list(rc.value)
        v[2] = self.b.es["radice"]
        self._rifiuta(_con_receipt(self.ts, v), "payload_receipt_attaccato")

    def test_header_protetto_ignoto_firmato_davvero(self):
        """VALID statement and receipt with one extra label (99): the closed profile refuses it; with the profile
        widened to 99 it would pass (positive control: the refusal comes from the closure, not from something else)."""
        ISS, T = self.b.ISS, self.b.T
        prot = {1: -19, 3: sx.CTY_RIGA_OPS, 4: ISS.kid, 15: {1: "omega.issuer", 2: "omega-ledger:prova"}, 99: "x"}
        st = sx._sign1(ISS, prot, sx.json_canonico(_righe_ops(1)[0]), True, {})
        a = sx.AlberoMerkle([st, ALTRA_FOGLIA])
        rc = sx.receipt(T, "omega.ts", "omega-ledger:prova", a.radice(), 2, 0, a.percorso(0))
        dati = sx.aggiungi_receipt(st, rc)
        self._rifiuta(dati, "header_protetto_fuori_profilo")
        vecchio = sv.PROT_STATEMENT
        try:
            sv.PROT_STATEMENT = vecchio | {99}
            self.assertTrue(self.b.verifica(dati).ok)
        finally:
            sv.PROT_STATEMENT = vecchio

    def test_sub_e_iss(self):
        ISS, T = self.b.ISS, self.b.T
        st = sx.signed_statement(ISS, "omega.issuer", "omega-ledger:a", sx.CTY_RIGA_OPS,
                                 sx.json_canonico(_righe_ops(1)[0]))
        a = sx.AlberoMerkle([st, ALTRA_FOGLIA])
        dati = sx.aggiungi_receipt(st, sx.receipt(T, "omega.ts", "omega-ledger:b", a.radice(), 2, 0, a.percorso(0)))
        self._rifiuta(dati, "sub_diversi")
        with self.assertRaises(sx.ExportError):
            sx.signed_statement(ISS, "x" * 8193, "s", sx.CTY_RIGA_OPS, b"{}")

    def test_dominio_omega(self):
        ISS, T = self.b.ISS, self.b.T
        r = _righe_ops(1)[0]
        r["data"]["n"] = 7  # self_hash no longer valid
        st = sx.signed_statement(ISS, "omega.issuer", "omega-ledger:prova", sx.CTY_RIGA_OPS, sx.json_canonico(r))
        a = sx.AlberoMerkle([st, ALTRA_FOGLIA])
        dati = sx.aggiungi_receipt(st, sx.receipt(T, "omega.ts", "omega-ledger:prova", a.radice(), 2, 0,
                                                  a.percorso(0)))
        self._rifiuta(dati, "catena_riga_non_valida")
        self.assertTrue(self.b.verifica(dati, controllo_dominio=False).ok)

    def test_catena_rotta_export_rifiutato(self):
        righe = _righe_ops(5)
        righe[2]["data"]["n"] = 99
        with self.assertRaises(sx.ExportError):
            sx.esporta(righe, nome="x", formato="ops", issuer=self.b.ISS, ts=self.b.T, politica=self.b.P,
                       iss_issuer="i", iss_ts="t")
        with self.assertRaises(sx.ExportError):  # same key for two roles
            sx.esporta(_righe_ops(2), nome="x", formato="ops", issuer=self.b.ISS, ts=self.b.ISS, politica=self.b.P,
                       iss_issuer="i", iss_ts="t")

    def test_ed25519_ordine_piccolo(self):
        # identity key (small order) trusted on purpose: pq_scitt/ed25519_keys must stop it before the signature
        neutra = bytes([1]) + bytes(31)
        e = self.b.verifica(self.ts, chiavi_ts={sx.kid_di(neutra): (-19, neutra)})
        self.assertEqual(e.motivo, "kid_ignoto")  # different kid: the kid is bound to the key
        _, rc, _ = _scomponi(self.ts)
        rp = cbor.loads(rc.value[0])
        rp[4] = sx.kid_di(neutra)
        rpb = cbor.dumps(rp)
        dati = _con_receipt(self.ts, [rpb, rc.value[1], None, neutra + bytes(32)])
        e = self.b.verifica(dati, chiavi_ts={sx.kid_di(neutra): (-19, neutra)})
        self.assertEqual(e.motivo, "chiave_ed25519_rifiutata")


class TestMotiviEsatti(unittest.TestCase):
    """Every guard of the verifier has a REALLY SIGNED case (valid statement and receipt) that only it stops:
    born from the 13 surviving mutants of the first round (guard removed = test still green)."""

    @classmethod
    def setUpClass(cls):
        cls.b = Banco(n=2)

    def _costruisci(self, prot=None, payload=None, rc_prot=None, firma_stmt=None, cty=sx.CTY_RIGA_OPS,
                    sub="omega-ledger:prova"):
        ISS, T = self.b.ISS, self.b.T
        if prot is None:
            prot = {1: -19, 3: cty, 4: ISS.kid, 15: {1: "omega.issuer", 2: sub}}
        if payload is None:
            payload = sx.json_canonico(_righe_ops(1)[0])
        pb = cbor.dumps(prot)
        firma = firma_stmt if firma_stmt is not None else ISS.firma(sx.sig_structure(pb, payload))
        st = cbor.dumps(cbor.Tag(18, [pb, {}, payload, firma]))
        a = sx.AlberoMerkle([st, ALTRA_FOGLIA])
        if rc_prot is None:
            rc_prot = {1: -19, 4: T.kid, 15: {1: "omega.ts", 2: sub}, 395: 1, -65538: 2}
        rpb = cbor.dumps(rc_prot)
        rc = cbor.dumps(cbor.Tag(18, [rpb, {396: {-1: [cbor.dumps([2, 0, a.percorso(0)])]}}, None,
                                      T.firma(sx.sig_structure(rpb, a.radice()))]))
        return cbor.dumps(cbor.Tag(18, [pb, {394: [rc]}, payload, firma]))

    def _motivo(self, dati, motivo, **kw):
        e = self.b.verifica(dati, **kw)
        self.assertFalse(e.ok)
        self.assertEqual(e.motivo, motivo, e)

    def test_costruttore_buono(self):
        self.assertTrue(self.b.verifica(self._costruisci()).ok)

    def test_non_tag(self):
        t = cbor.loads(self._costruisci())
        self._motivo(cbor.dumps(t.value), "non_cose_sign1")
        self._motivo(cbor.dumps(5), "non_cose_sign1")

    def test_payload_tipo(self):
        self._motivo(self._costruisci(payload=7), "forma_cose", controllo_dominio=False)

    def test_payload_nil(self):
        ISS = self.b.ISS
        prot = {1: -19, 3: sx.CTY_RIGA_OPS, 4: ISS.kid, 15: {1: "omega.issuer", 2: "omega-ledger:prova"}}
        pb = cbor.dumps(prot)
        dati = self._costruisci(prot=prot)
        t = cbor.loads(dati)
        self._motivo(cbor.dumps(cbor.Tag(18, [pb, t.value[1], None, t.value[3]])), "payload_statement_assente")

    def test_iss_sub(self):
        ISS = self.b.ISS
        for iss in ("", "x" * 8193, 5):
            prot = {1: -19, 3: sx.CTY_RIGA_OPS, 4: ISS.kid, 15: {1: iss, 2: "omega-ledger:prova"}}
            self._motivo(self._costruisci(prot=prot), "iss_fuori_profilo")
        self.assertTrue(self.b.verifica(self._costruisci(
            prot={1: -19, 3: sx.CTY_RIGA_OPS, 4: ISS.kid, 15: {1: "x" * 8192, 2: "omega-ledger:prova"}})).ok)
        self._motivo(self._costruisci(sub=""), "cwt_fuori_profilo")

    def test_cty(self):
        ISS = self.b.ISS
        for cty in ("application/json", 50):
            prot = {1: -19, 3: cty, 4: ISS.kid, 15: {1: "omega.issuer", 2: "omega-ledger:prova"}}
            self._motivo(self._costruisci(prot=prot), "cty_fuori_profilo")

    def test_firma_lunghezza(self):
        self._motivo(self._costruisci(firma_stmt=b"\x01" * 63), "firma_lunghezza")

    def test_receipt_non_bstr(self):
        t = cbor.loads(self._costruisci())
        self._motivo(cbor.dumps(cbor.Tag(18, [t.value[0], {394: [5]}, t.value[2], t.value[3]])), "forma_cose")

    def test_vds(self):
        T = self.b.T
        for vds in (2, 0, "1"):
            rp = {1: -19, 4: T.kid, 15: {1: "omega.ts", 2: "omega-ledger:prova"}, 395: vds, -65538: 2}
            self._motivo(self._costruisci(rc_prot=rp), "vds_non_ammesso")

    def test_tree_size_atteso(self):
        self._motivo(self._costruisci(), "tree_size_non_atteso", tree_size_atteso=3)

    def test_payload_json(self):
        r = _righe_ops(1)[0]
        self._motivo(self._costruisci(payload=b"\xff\xfe"), "payload_non_json")
        self._motivo(self._costruisci(payload=b'{"a":1,"a":2}'), "payload_non_json")
        import json
        self._motivo(self._costruisci(payload=json.dumps(r).encode()), "payload_non_json")  # not canonical
        self.assertTrue(self.b.verifica(self._costruisci(payload=json.dumps(r).encode()),
                                        controllo_dominio=False).ok)

    def test_evento_chain_non_valido(self):
        ev = _eventi_chain("n1")[0]
        self.assertTrue(self.b.verifica(self._costruisci(payload=sx.json_canonico(ev), cty=sx.CTY_EVENTO_CHAIN)).ok)
        for campo, valore in (("payload", {"n": 2}), ("origin_node", "altro"), ("payload_sha3", None)):
            ev2 = dict(ev, **{campo: valore})
            if valore is None:
                del ev2[campo]
            self._motivo(self._costruisci(payload=sx.json_canonico(ev2), cty=sx.CTY_EVENTO_CHAIN),
                         "catena_riga_non_valida")


class TestCartellaERegistriVeri(unittest.TestCase):
    def test_cartella(self):
        b = Banco(n=6)
        d = tempfile.mkdtemp()
        try:
            sx.scrivi_cartella(b.es, d)
            arg = dict(alg_statement=-19, alg_receipt=-19, chiave_ts=(-19, b.T.pub), chiave_politica=(-19, b.P.pub))
            self.assertTrue(sv.verifica_cartella(d, **arg).ok)
            self.assertFalse(sv.verifica_cartella(d, **dict(arg, chiave_ts=(-19, Banco(n=1).T.pub))).ok)
            os.remove(os.path.join(d, "ts_000004.cose"))
            self.assertEqual(sv.verifica_cartella(d, **arg).motivo, "tree_size_non_atteso")
            shutil.copy(os.path.join(d, "ts_000003.cose"), os.path.join(d, "ts_000004.cose"))
            self.assertEqual(sv.verifica_cartella(d, **arg).motivo, "politica_fuori_profilo")
        finally:
            shutil.rmtree(d)

    def test_eventi_chain(self):
        ev = _eventi_chain("t7")
        b = Banco(righe=ev, formato="chain")
        for i, ts in enumerate(b.es["transparent"]):
            self.assertTrue(b.verifica(ts, i).ok)
        ev[3]["payload"]["n"] = 99
        with self.assertRaises(sx.ExportError):
            Banco(righe=ev, formato="chain")


# ------------------------------------------------------------------ generative

def _avvolgi(v):
    """bstr that contain CBOR of the subset (and re-encode identically) become nested nodes."""
    if isinstance(v, bytes) and v[:1] in (b"\x82", b"\x83", b"\x84", b"\xa1", b"\xa2", b"\xa3", b"\xa4", b"\xa5",
                                          b"\xa6", b"\xd2"):
        try:
            x = cbor.loads(v)
            if cbor.dumps(x) == v:
                return ("W", _avvolgi(x))
        except cbor.CBORError:
            pass
    if isinstance(v, cbor.Tag):
        return cbor.Tag(v.tag, _avvolgi(v.value))
    if isinstance(v, list):
        return [_avvolgi(x) for x in v]
    if isinstance(v, dict):
        return {k: _avvolgi(x) for k, x in v.items()}
    return v


def _svolgi(v):
    if isinstance(v, tuple) and len(v) == 2 and v[0] == "W":
        return cbor.dumps(_svolgi(v[1]))
    if isinstance(v, cbor.Tag):
        return cbor.Tag(v.tag, _svolgi(v.value))
    if isinstance(v, list):
        return [_svolgi(x) for x in v]
    if isinstance(v, dict):
        return {k: _svolgi(x) for k, x in v.items()}
    return v


ALTERNATIVE = [0, 1, -1, -19, 2 ** 40, "", "x", b"", b"\x00" * 32, [], [1], {}, {1: 1}, None, True, False]


def _mutanti_strutturali(albero):
    """Every node: new keys, removed keys, values of the wrong type, extra/missing elements."""
    out = []

    def visita(nodo, rimetti):
        if isinstance(nodo, tuple) and nodo[0] == "W":
            visita(nodo[1], lambda x: rimetti(("W", x)))
            return
        if isinstance(nodo, cbor.Tag):
            visita(nodo.value, lambda x: rimetti(cbor.Tag(nodo.tag, x)))
            return
        for alt in ALTERNATIVE:
            if alt != nodo or type(alt) is not type(nodo):
                out.append(rimetti(alt))
        if isinstance(nodo, dict):
            for nuova in (7, -70000, "ignota", 394, 2):
                if nuova not in nodo:
                    out.append(rimetti(dict(nodo, **{nuova: 1}) if isinstance(nuova, str) else {**nodo, nuova: 1}))
            for k in list(nodo):
                out.append(rimetti({j: x for j, x in nodo.items() if j != k}))
                visita(nodo[k], lambda x, k=k: rimetti({**nodo, k: x}))
        elif isinstance(nodo, list):
            out.append(rimetti(nodo + [nodo[-1] if nodo else 0]))
            if nodo:
                out.append(rimetti(nodo[:-1]))
            for i in range(len(nodo)):
                visita(nodo[i], lambda x, i=i: rimetti(nodo[:i] + [x] + nodo[i + 1:]))
    visita(albero, lambda x: x)
    return out


def _mutanti_byte(dati, rnd, quanti):
    out = [dati[:i] for i in range(len(dati))]                       # all truncations
    out += [dati + b"\x00", dati + dati[:5]]
    for _ in range(quanti):
        b = bytearray(dati)
        scelta = rnd.random()
        pos = rnd.randrange(len(b))
        if scelta < 0.6:
            b[pos] ^= 1 << rnd.randrange(8)
        elif scelta < 0.8:
            b[pos] = rnd.choice((0x00, 0x18, 0x19, 0x1f, 0x5f, 0x7f, 0x9f, 0xbf, 0xf9, 0xfa, 0xfb, 0xf7, 0xff, 0xc1))
        else:
            b[pos:pos] = bytes([rnd.randrange(256)])
        out.append(bytes(b))
    return out


def _non_minimo(dati):
    """Rewrites the first 1-byte CBOR head (<24) in 2-byte form: not deterministic."""
    out = []
    for pos in range(len(dati)):
        x = dati[pos]
        if x >> 5 in (0, 1) and (x & 31) < 24 and pos > 0:
            out.append(dati[:pos] + bytes([(x & 0xE0) | 24, x & 31]) + dati[pos + 1:])
    return out


class TestGenerativi(unittest.TestCase):
    N_BYTE = 16000

    def _banco(self, verifica, b, mutanti, originale):
        accettati = 0
        for m in mutanti:
            if m == originale:
                continue
            try:
                e = verifica(m)
            except Exception as ex:  # noqa: BLE001
                self.fail("unhandled exception %s on %s" % (type(ex).__name__, m[:40].hex()))
            accettati += bool(e.ok)
        return accettati

    def test_mutanti_rifiutati(self):
        rnd = random.Random(20261108)
        b = Banco(n=12)
        totale = 0
        for i in (0, 1, 7, 12):
            ts = b.es["transparent"][i]

            def ver(m, i=i):
                return b.verifica(m, i)
            self.assertTrue(ver(ts).ok)                    # positive control
            strutt = [cbor.dumps(_svolgi(x)) for x in _mutanti_strutturali(_avvolgi(cbor.loads(ts)))]
            byte = _mutanti_byte(ts, rnd, self.N_BYTE // 4)
            nonmin = _non_minimo(ts)
            mutanti = strutt + byte + nonmin
            totale += len(mutanti)
            self.assertEqual(self._banco(ver, b, mutanti, ts), 0, "mutants accepted on leaf %d" % i)
        self.assertGreaterEqual(totale, 20000)

    def test_controllo_positivo_del_banco(self):
        """A verifier that does NOT check the proof (root taken as good) must be caught by the bench."""
        rnd = random.Random(7)
        b = Banco(n=12)
        ts = b.es["transparent"][5]
        vecchia = sv.radice_da_prova
        try:
            sv.radice_da_prova = lambda foglia, indice, n, percorso: b.es["radice"]
            mutanti = [cbor.dumps(_svolgi(x)) for x in _mutanti_strutturali(_avvolgi(cbor.loads(ts)))]
            mutanti += _mutanti_byte(ts, rnd, 3000)
            self.assertGreater(self._banco(lambda m: b.verifica(m, 5), b, mutanti, ts), 0)
        finally:
            sv.radice_da_prova = vecchia

    def test_cbor_generativo_mai_eccezioni_estranee(self):
        rnd = random.Random(1)
        for _ in range(20000):
            dati = bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 24)))
            try:
                cbor.loads(dati)
            except cbor.CBORError:
                pass


class TestRevisioneP1P2(unittest.TestCase):
    """review 08/11: folder with FIFO/folders/unreadable files; policy reproduced (cty, iss, chain); empty export."""

    def _cartella(self, b):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        sx.scrivi_cartella(b.es, d)
        return d, dict(alg_statement=-19, alg_receipt=-19, chiave_ts=(-19, b.T.pub), chiave_politica=(-19, b.P.pub))

    def test_file_non_regolari(self):
        b = Banco(n=4)
        for tipo in ("fifo", "dir", "illeggibile"):
            d, arg = self._cartella(b)
            self.assertTrue(sv.verifica_cartella(d, **arg).ok)          # positive control
            p = os.path.join(d, "ts_000003.cose")
            if tipo == "illeggibile":
                os.chmod(p, 0)
                if os.access(p, os.R_OK):
                    continue                                              # root reads everything
            else:
                os.remove(p)
                os.mkfifo(p) if tipo == "fifo" else os.mkdir(p)
            esiti = []
            th = threading.Thread(target=lambda: esiti.append(sv.verifica_cartella(d, **arg)), daemon=True)
            th.start()
            th.join(20)
            self.assertTrue(esiti, tipo + ": verification blocked or exception")
            e = esiti[0]
            self.assertEqual((e.ok, e.motivo), (False, "forma_cose"), tipo)
            if tipo == "illeggibile":
                os.chmod(p, 0o600)

    def _foglia_in_piu(self, b, cty, iss, riga):
        st = list(b.es["statements"]) + [sx.signed_statement(b.ISS, iss, b.es["sub"], cty, sx.json_canonico(riga))]
        a = sx.AlberoMerkle(st)
        tr = [sx.aggiungi_receipt(s, sx.receipt(b.T, "omega.ts", b.es["sub"], a.radice(), a.n, i, a.percorso(i)))
              for i, s in enumerate(st)]
        return dict(b.es, transparent=tr, tree_size=a.n, radice=a.radice())

    def _riga(self, b, funzione=hashlib.sha256, prev=None):
        ultima = strict_json.loads_object(cbor.loads(b.es["statements"][-1]).value[2])
        r = {"idx": ultima["idx"] + 1, "ts": "t", "data": {}, "prev_hash": prev or ultima["self_hash"]}
        r["self_hash"] = sx.hash_riga_ops(r, funzione)
        return r

    def test_politica_riprodotta(self):
        b = Banco(n=3)
        casi = {"buono": (sx.CTY_RIGA_OPS, "omega.issuer", self._riga(b), True),
                "cty_diverso": (sx.CTY_RIGA_OPS_SHA3, "omega.issuer", self._riga(b, hashlib.sha3_256), False),
                "iss_diverso": (sx.CTY_RIGA_OPS, "altro.issuer", self._riga(b), False),
                "catena_rotta": (sx.CTY_RIGA_OPS, "omega.issuer", self._riga(b, prev="f" * 64), False)}
        for nome, (cty, iss, riga, atteso) in casi.items():
            d = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, d, True)
            sx.scrivi_cartella(self._foglia_in_piu(b, cty, iss, riga), d)
            e = sv.verifica_cartella(d, alg_statement=-19, alg_receipt=-19, chiave_ts=(-19, b.T.pub),
                                     chiave_politica=(-19, b.P.pub))
            self.assertEqual(e.ok, atteso, (nome, e))
            if not atteso:
                self.assertIn(e.motivo, ("politica_fuori_profilo", "catena_riga_non_valida"), nome)

    def test_registro_vuoto(self):
        b = Banco(n=1)
        with self.assertRaises(sx.ExportError):
            sx.esporta([], nome="v", formato="ops", issuer=b.ISS, ts=b.T, politica=b.P, iss_issuer="i", iss_ts="t")
    # ---- review P3: missing tests (surviving mutants on scitt_verify.py)
    def test_indice_uguale_o_negativo(self):
        b = Banco(n=1)
        s0 = b.es["statements"][1]
        T = b.T
        for size, idx, path, motivo in ((1, 1, [], "prova_fuori_profilo"),       # amendment 5: empty path
                                        (2, 2, [sx.hash_foglia(b"x")], "indice_oltre_albero")):
            # root that the algorithm WITHOUT the guard would rebuild: leaf (size 1) or node (leaf, x) (size 2)
            rad = sx.hash_foglia(s0) if size == 1 else sx.hash_nodo(sx.hash_foglia(s0), path[0])
            rc = sx.receipt(T, "omega.ts", b.es["sub"], rad, size, idx, path)
            e = b.verifica(sx.aggiungi_receipt(s0, rc), 1)
            self.assertEqual((e.ok, e.motivo), (False, motivo), (size, idx))
        b = Banco(n=3)                      # 4 leaves: the last (3) has the same computation shape as index -1
        ts = b.es["transparent"][3]
        _, _, prova = _scomponi(ts)
        self.assertTrue(b.verifica(ts, 3).ok)
        nuovo = _con_prova(ts, [prova[0], -1, prova[2]])
        e = b.verifica(nuovo, 3)
        self.assertEqual((e.ok, e.motivo), (False, "prova_fuori_profilo"))

    def test_iss_di_un_carattere(self):
        b = Banco(n=1)
        st = sx.signed_statement(b.ISS, "a", b.es["sub"], sx.CTY_RIGA_OPS, cbor.loads(b.es["statements"][1]).value[2])
        a = sx.AlberoMerkle([b.es["statements"][0], st])
        ts = sx.aggiungi_receipt(st, sx.receipt(b.T, "t", b.es["sub"], a.radice(), 2, 1, a.percorso(1)))
        self.assertTrue(b.verifica(ts, 1).ok)

    def _esito(self, d, b):
        return sv.verifica_cartella(d, alg_statement=-19, alg_receipt=-19, chiave_ts=(-19, b.T.pub),
                                    chiave_politica=(-19, b.P.pub))

    def test_cartella_ogni_rifiuto_ha_ok_falso(self):
        b = Banco(n=4)
        d, arg = self._cartella(b)
        self.assertTrue(self._esito(d, b).ok)
        # leaf 1 altered (the first after the policy): it must be verified too
        p1 = os.path.join(d, "ts_000001.cose")
        dati = bytearray(open(p1, "rb").read())
        dati[-70] ^= 1
        open(p1, "wb").write(bytes(dati))
        e = self._esito(d, b)
        self.assertFalse(e.ok)
        # empty folder, missing folder
        vuota = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, vuota, True)
        self.assertEqual((self._esito(vuota, b).ok, self._esito(vuota, b).motivo), (False, "receipt_assente"))
        e = self._esito(os.path.join(vuota, "manca"), b)
        self.assertEqual((e.ok, e.motivo), (False, "forma_cose"))
        # one file fewer, a duplicate
        d, arg = self._cartella(b)
        os.remove(os.path.join(d, "ts_000004.cose"))
        e = self._esito(d, b)
        self.assertEqual((e.ok, e.motivo), (False, "tree_size_non_atteso"))
        shutil.copy(os.path.join(d, "ts_000003.cose"), os.path.join(d, "ts_000004.cose"))
        e = self._esito(d, b)
        self.assertEqual((e.ok, e.motivo), (False, "politica_fuori_profilo"))

    def _albero(self, b, statements):
        a = sx.AlberoMerkle(statements)
        tr = [sx.aggiungi_receipt(s, sx.receipt(b.T, "omega.ts", b.es["sub"], a.radice(), a.n, i, a.percorso(i)))
              for i, s in enumerate(statements)]
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for i, t in enumerate(tr):
            open(os.path.join(d, "ts_%06d.cose" % i), "wb").write(t)
        return d

    def test_politica_fuori_posto_o_contenuto_sbagliato(self):
        b = Banco(n=2)
        st = b.es["statements"]
        pol_doc = dict(b.es["politica"])
        # policy in position 1, file with a name that sorts first
        d = self._albero(b, [st[1], st[0], st[2]])
        os.rename(os.path.join(d, "ts_000001.cose"), os.path.join(d, "a.cose"))
        e = self._esito(d, b)
        self.assertEqual((e.ok, e.motivo, e.dettaglio), (False, "politica_fuori_profilo", "leaf 0"))
        # leaf 0 signed by the policy key but with a line cty
        riga0 = sx.signed_statement(b.P, "omega.ts", b.es["sub"], sx.CTY_RIGA_OPS, cbor.loads(st[1]).value[2])
        e = self._esito(self._albero(b, [riga0, st[1], st[2]]), b)
        self.assertEqual((e.ok, e.motivo, e.dettaglio), (False, "politica_fuori_profilo", "leaf 0"))
        # content of the policy: alg of the anchor, kid of the anchor, profile, kid of the TS
        anc = dict(pol_doc["ancore"][0])
        for nome, doc in (("alg", dict(pol_doc, ancore=[dict(anc, alg=-8)])),
                          ("kid", dict(pol_doc, ancore=[dict(anc, kid="00" * 16)])),
                          ("profilo", dict(pol_doc, profilo="altro/1")),
                          ("ts", dict(pol_doc, ts=dict(pol_doc["ts"], kid="00" * 16)))):
            p0 = sx.signed_statement(b.P, "omega.ts", b.es["sub"], sx.CTY_POLITICA, sx.json_canonico(doc))
            e = self._esito(self._albero(b, [p0, st[1], st[2]]), b)
            self.assertEqual((e.ok, e.motivo), (False, "politica_fuori_profilo"), nome)

    def test_cli_codici_di_uscita(self):
        b = Banco(n=2)
        d, arg = self._cartella(b)
        self.assertEqual(sv._main([d, "--alg", "-19", "--ts-pub", b.T.pub.hex(), "--politica-pub", b.P.pub.hex()]), 0)
        self.assertEqual(sv._main([d, "--alg", "-19", "--ts-pub", "zz", "--politica-pub", b.P.pub.hex()]), 2)
        self.assertEqual(sv._main([d, "--alg", "-19", "--ts-pub", b.P.pub.hex(), "--politica-pub", b.P.pub.hex()]), 1)
    def test_recursion_error_diventa_rifiuto(self):
        from unittest import mock
        with mock.patch.object(sv, "_verifica", side_effect=RecursionError):
            e = sv.verifica_transparent_statement(b"x", alg_statement=-19, alg_receipt=-19, chiavi_issuer={},
                                                  chiavi_ts={})
        self.assertEqual((e.ok, e.motivo), (False, "cbor_troppo_profondo"))

    def test_descrittore_zero_chiuso_dopo_rifiuto(self):
        """Stdin closed: os.open gives descriptor 0 to the first file; a non-regular file must be refused AND closed."""
        import subprocess
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        os.mkfifo(os.path.join(d, "ts_000000.cose"))
        codice = ("import os,sys; sys.path[:0]=[%r,%r]; from pq_scitt.scitt import verify as sv; os.close(0)\n"
                  "e = sv._leggi_file(%r, 'ts_000000.cose'); print(e.motivo)\n"
                  "try:\n os.fstat(0); print('APERTO')\nexcept OSError: print('CHIUSO')\n"
                  % (RADICE, os.path.join(RADICE, "chain"), d))
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        r = subprocess.run([sys.executable, "-c", codice], capture_output=True, env=env, timeout=60)
        self.assertEqual(r.stdout.split(), [b"forma_cose", b"CHIUSO"], r.stderr[-300:])

    def test_file_troppo_grande_o_errore_di_lettura(self):
        b = Banco(n=3)
        d, arg = self._cartella(b)
        p = os.path.join(d, "ts_000002.cose")
        with open(p, "r+b") as f:
            f.truncate(cbor.MAX_BYTES + 1)                                 # sparse file, no disk
        e = sv.verifica_cartella(d, **arg)
        self.assertEqual((e.ok, e.motivo), (False, "cbor_troppo_lungo"))
        with open(p, "r+b") as f:
            f.truncate(cbor.MAX_BYTES)                                     # at the limit: read, then refused by CBOR
        e = sv.verifica_cartella(d, **arg)
        self.assertFalse(e.ok)
        self.assertNotEqual(e.motivo, "cbor_troppo_lungo")
        d, arg = self._cartella(b)
        from unittest import mock
        with mock.patch.object(sv.os, "fstat", side_effect=OSError("EIO")):
            e = sv.verifica_cartella(d, **arg)
        self.assertEqual((e.ok, e.motivo), (False, "forma_cose"))


# ---------------------------------------------------------------- closure A2 (08/11): amendments 5-8 and mutants R6
def _chiave_file(d, nome, contenuto: bytes, modo=0o600):
    p = os.path.join(d, nome)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(contenuto)
    os.chmod(p, modo)
    return p


def _pem(k):
    from cryptography.hazmat.primitives import serialization as ser
    return k.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())


class TestPercorsoVuoto(unittest.TestCase):
    """Amendment 5: RFC 9942 `inclusion_path: [ + bstr ]`. A REALLY SIGNED receipt with an empty path (1-leaf
    tree) must be refused; the same leaf in a 2-leaf tree passes (positive control)."""

    def test_percorso_vuoto(self):
        b = Banco(n=1)
        st = b.es["statements"][1]
        rc = sx.receipt(b.T, "omega.ts", b.es["sub"], sx.hash_foglia(st), 1, 0, [])
        e = b.verifica(sx.aggiungi_receipt(st, rc))
        self.assertEqual((e.ok, e.motivo), (False, "prova_fuori_profilo"))
        a = sx.AlberoMerkle([st, ALTRA_FOGLIA])
        rc = sx.receipt(b.T, "omega.ts", b.es["sub"], a.radice(), 2, 0, a.percorso(0))
        self.assertTrue(b.verifica(sx.aggiungi_receipt(st, rc)).ok)
        # tree_size 1 with one node in the path: allowed shape, then the path is too long for the tree
        rc = sx.receipt(b.T, "omega.ts", b.es["sub"], a.radice(), 1, 0, a.percorso(0))
        e = b.verifica(sx.aggiungi_receipt(st, rc))
        self.assertEqual((e.ok, e.motivo, e.dettaglio), (False, "percorso_lunghezza", "too long"))

    def test_percorso_massimo(self):
        """MAX_PERCORSO = 64: a tree of 2^64 - 1 leaves (the maximum of a CBOR uint) has 64-node paths for
        leaf 0, allowed; 65 nodes: outside the profile. Receipt really signed by the TS on the root the path gives."""
        b = Banco(n=1)
        st = b.es["statements"][1]
        n = 2 ** 64 - 1
        for lunghezza, ok in ((64, True), (65, False)):
            path = [hashlib.sha256(bytes([i])).digest() for i in range(lunghezza)]
            rad = sx.hash_foglia(st)
            for p in path:
                rad = sx.hash_nodo(rad, p)
            e = b.verifica(sx.aggiungi_receipt(st, sx.receipt(b.T, "omega.ts", b.es["sub"], rad, n, 0, path)))
            self.assertEqual(e.ok, ok, (lunghezza, e))
            if not ok:
                self.assertEqual(e.motivo, "prova_fuori_profilo")


class TestCBORConfini(unittest.TestCase):
    """R6 (review): CBOR boundaries never tested. Every vector is written by hand from RFC 8949, not by the encoder."""

    def test_codifica_ai_confini(self):
        attesi = {0: "00", 23: "17", 24: "1818", 255: "18ff", 256: "190100", 65535: "19ffff", 65536: "1a00010000",
                  2 ** 32 - 1: "1affffffff", 2 ** 32: "1b0000000100000000", 2 ** 64 - 1: "1bffffffffffffffff",
                  -1: "20", -24: "37", -25: "3818", -257: "390100"}
        for v, h in attesi.items():
            self.assertEqual(cbor.dumps(v).hex(), h, v)
            self.assertEqual(cbor.loads(bytes.fromhex(h)), v, v)
        for v in (2 ** 64, -(2 ** 64) - 1):
            with self.assertRaises(cbor.CBORError) as c:
                cbor.dumps(v)
            self.assertEqual(c.exception.motivo, "cbor_tipo_non_codificabile")
        self.assertEqual(cbor.dumps(b"x" * 24).hex()[:4], "5818")
        self.assertEqual(cbor.dumps("é").hex(), "62c3a9")

    def test_codifica_rifiuti(self):
        class D(dict):                      # dict that enumerates the same key twice
            def items(self):
                return [(1, "a"), (1, "b")]
        for v, motivo in ((cbor.Tag(19, 0), "cbor_tag_ignoto"), ({1.5: 1}, "cbor_chiave_tipo"),
                          ({b"k": 1}, "cbor_chiave_tipo"), (D({1: "a"}), "cbor_chiave_ripetuta"),
                          (1.5, "cbor_tipo_non_codificabile"), (object(), "cbor_tipo_non_codificabile")):
            with self.assertRaises(cbor.CBORError) as c:
                cbor.dumps(v)
            self.assertEqual(c.exception.motivo, motivo, v)
        self.assertEqual(cbor.dumps({"b": 1, 10: 2, "a": 3, -1: 4}).hex(), "a40a0220046161036162" + "01")

    def test_argomento_minimo_ai_confini(self):
        for h, v in (("1818", 24), ("190100", 256), ("1a00010000", 65536), ("1b0000000100000000", 2 ** 32)):
            self.assertEqual(cbor.loads(bytes.fromhex(h)), v)
        for h in ("1817", "1900ff", "1a0000ffff", "1b00000000ffffffff"):
            with self.assertRaises(cbor.CBORError) as c:
                cbor.loads(bytes.fromhex(h))
            self.assertEqual(c.exception.motivo, "cbor_non_minimo", h)

    def test_profondita_esatta(self):
        # 16 nested arrays + 0: the innermost element is at depth 16 = MAX_DEPTH, allowed; 17: refused
        self.assertEqual(cbor.loads(b"\x81" * 16 + b"\x00"), eval("[" * 16 + "0" + "]" * 16))
        with self.assertRaises(cbor.CBORError) as c:
            cbor.loads(b"\x81" * 17 + b"\x00")
        self.assertEqual(c.exception.motivo, "cbor_troppo_profondo")
        # map at depth 15: key and value at 16 (allowed); tag at 15 with value at 16 (allowed)
        self.assertEqual(cbor.loads(b"\x81" * 15 + b"\xa1\x00\x00"), eval("[" * 15 + "{0: 0}" + "]" * 15))
        self.assertTrue(cbor.loads(b"\x81" * 15 + b"\xd2\x00"))
        for coda in (b"\xa1\x00\x00", b"\xd2\x00"):
            with self.assertRaises(cbor.CBORError) as c:
                cbor.loads(b"\x81" * 16 + coda)
            self.assertEqual(c.exception.motivo, "cbor_troppo_profondo")

    def test_numero_di_elementi_al_limite(self):
        # 65536 elements declared without data: the count is allowed, then truncated; 65537: too many elements
        for maggiore in (0x9a, 0xba):
            c1 = self._motivo(bytes([maggiore]) + (65536).to_bytes(4, "big"))
            c2 = self._motivo(bytes([maggiore]) + (65537).to_bytes(4, "big"))
            self.assertEqual((c1, c2), ("cbor_troncato", "cbor_troppi_elementi"))

    def _motivo(self, b):
        with self.assertRaises(cbor.CBORError) as c:
            cbor.loads(b)
        return c.exception.motivo

    def test_break_e_chiavi_motivo_esatto(self):
        self.assertEqual(self._motivo(b"\xff"), "cbor_indefinito")
        self.assertEqual(self._motivo(b"\x82\x00\xff"), "cbor_indefinito")
        self.assertEqual(self._motivo(bytes.fromhex("a2010101 01".replace(" ", ""))), "cbor_chiave_ripetuta")
        self.assertEqual(self._motivo(bytes.fromhex("a202010101")), "cbor_chiavi_non_ordinate")
        self.assertEqual(self._motivo(bytes.fromhex("a2616101 0101".replace(" ", ""))), "cbor_chiavi_non_ordinate")
        self.assertEqual(cbor.loads(bytes.fromhex("a201010202")), {1: 1, 2: 2})

    def test_float_e_simple_motivo_esatto(self):
        for h in ("f90000", "fa00000000", "fb0000000000000000", "f7", "f820", "e0"):
            self.assertEqual(self._motivo(bytes.fromhex(h)), "cbor_float_o_simple", h)

    def test_lunghezza_massima_esatta(self):
        testa = b"\x5a" + (cbor.MAX_BYTES - 5).to_bytes(4, "big")
        dati = testa + bytes(cbor.MAX_BYTES - 5)
        self.assertEqual(len(dati), cbor.MAX_BYTES)
        self.assertEqual(len(cbor.loads(dati)), cbor.MAX_BYTES - 5)
        oltre = b"\x5a" + (cbor.MAX_BYTES - 4).to_bytes(4, "big") + bytes(cbor.MAX_BYTES - 4)
        self.assertEqual(self._motivo(oltre), "cbor_troppo_lungo")


class TestExportGuardie(unittest.TestCase):
    """R6: writer-only guards and hash functions, with fixed vectors or with the origin code as reference."""

    def test_json_canonico_vettore_fisso(self):
        self.assertEqual(sx.json_canonico({"b": 1, "a": [2, "é"]}), b'{"a":[2,"\\u00e9"],"b":1}')
        for v in (float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                sx.json_canonico({"x": v})
            with self.assertRaises(ValueError):
                sx.hash_riga_ops({"x": v})
        self.assertEqual(sx.PROFILO, "omega-scitt/1")

    def test_hash_chain_come_l_implementazione_d_origine(self):
        ev = _eventi_chain("u1")[0]
        self.assertEqual(sx.hash_evento_chain(ev), ev["self_hash"])
        self.assertEqual(sx.payload_sha3_chain(ev["payload"]), ev["payload_sha3"])

    def test_verifica_catena_idx(self):
        righe = _righe_ops(3)
        r = dict(righe[0], idx=5)
        r["self_hash"] = sx.hash_riga_ops(r)
        self.assertIn("idx", sx.verifica_catena([r], "ops"))
        r = dict(righe[0], idx=True)
        r["self_hash"] = sx.hash_riga_ops(r)
        self.assertIn("idx", sx.verifica_catena([r], "ops"))
        self.assertEqual(sx.verifica_catena(righe, "altro"), "unknown format")

    def test_merkle_e_firmatari(self):
        with self.assertRaises(sx.ExportError):
            sx.AlberoMerkle([])
        a = sx.AlberoMerkle([b"a", b"b", b"c"])
        for m in (3, -1):
            with self.assertRaises(sx.ExportError):
                a.percorso(m)
        with self.assertRaises(sx.ExportError):
            sx.firmatario_ed25519(ed25519.Ed25519PrivateKey.generate(), sx.ALG_MLDSA65)
        k = ed25519.Ed25519PrivateKey.generate()
        corta = sx.Firmatario(sx.ALG_ED25519, k.public_key().public_bytes_raw(), lambda m: k.sign(m)[:63])
        with self.assertRaises(sx.ExportError) as c:
            sx.signed_statement(corta, "i", "omega-ledger:a", sx.CTY_RIGA_OPS, b"{}")
        self.assertIn("signature length", str(c.exception))
        altra = ed25519.Ed25519PrivateKey.generate()
        falsa = sx.Firmatario(sx.ALG_ED25519, k.public_key().public_bytes_raw(), altra.sign)
        with self.assertRaises(sx.ExportError):
            sx.signed_statement(falsa, "i", "omega-ledger:a", sx.CTY_RIGA_OPS, b"{}")

    def test_statement_guardie(self):
        f = _firmatario(sx.ALG_ED25519)
        for iss, sub, cty in (("i", "omega-ledger:a", "text/plain"), ("", "omega-ledger:a", sx.CTY_RIGA_OPS),
                              ("x" * 8193, "omega-ledger:a", sx.CTY_RIGA_OPS), ("i", "", sx.CTY_RIGA_OPS)):
            with self.assertRaises(sx.ExportError):
                sx.signed_statement(f, iss, sub, cty, b"{}")
        for iss in ("a", "x" * 8192):
            sx.signed_statement(f, iss, "omega-ledger:a", sx.CTY_RIGA_OPS, b"{}")
        with self.assertRaises(sx.ExportError) as c:
            sx.signed_statement(f, "", "omega-ledger:a", sx.CTY_RIGA_OPS, b"{}")
        self.assertIn("iss 1..8192", str(c.exception))
        st = sx.signed_statement(f, "i", "omega-ledger:a", sx.CTY_RIGA_OPS, b"{}")
        con = sx.aggiungi_receipt(st, b"r")
        with self.assertRaises(sx.ExportError):
            sx.aggiungi_receipt(con, b"r")

    def test_esporta_guardie(self):
        b = Banco(n=1)
        righe = _righe_ops(2)
        base = dict(nome="a", formato="ops", issuer=b.ISS, ts=b.T, politica=b.P, iss_issuer="i", iss_ts="t")
        for cambio in ({"formato": "xml"}, {"payload": "metà"}, {"ts": b.ISS}, {"politica": b.T},
                       {"nome": "A"}, {"nome": "a b"}, {"nome": "a\n"}, {"nome": "x" * 65}, {"nome": ""},
                       {"iss_issuer": "roberto@example.org"}, {"iss_ts": "omega ts"}, {"iss_issuer": ""}):
            with self.assertRaises(sx.ExportError, msg=str(cambio)) as c:
                sx.esporta(righe, **dict(base, **cambio))
            if "formato" in cambio:
                self.assertIn("allowed formato", str(c.exception))
            if "nome" in cambio:
                self.assertIn("[a-z0-9][a-z0-9._-]{0,63}", str(c.exception))
        sx.esporta(righe, **dict(base, nome="x" * 64, iss_issuer="https://omega.example/issuer"))


class TestPrivacyRiservato(unittest.TestCase):
    """Amendment 6: confidential payload (link only), closed sub, closed-shape policy."""

    def _cartella(self, es):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        sx.scrivi_cartella(es, d)
        return d

    def _arg(self, b):
        return dict(alg_statement=b.alg, alg_receipt=b.alg, chiave_ts=(b.alg, b.T.pub), chiave_politica=(b.alg, b.P.pub))

    def _banco(self, formato="ops", righe=None, alg=sx.ALG_ED25519):
        b = Banco(alg=alg, n=1)
        righe = righe if righe is not None else _righe_ops(5)
        b.es = sx.esporta(righe, nome="prova", formato=formato, issuer=b.ISS, ts=b.T, politica=b.P,
                          iss_issuer="omega.issuer", iss_ts="omega.ts", payload="riservato")
        return b

    def test_riservato_passa_e_non_porta_dati(self):
        for formato, righe in (("ops", _righe_ops(5)), ("chain", _eventi_chain("n4"))):
            b = self._banco(formato, righe)
            self.assertEqual((b.es["politica"]["payload"], b.es["politica"]["formato"]), ("riservato", formato))
            for i, st in enumerate(b.es["statements"][1:]):
                t = cbor.loads(st)
                self.assertEqual(cbor.loads(t.value[0])[3], sx.CTY_COLLEGAMENTO)
                self.assertEqual(t.value[2], sx.json_canonico({"idx": i, "prev_hash": righe[i]["prev_hash"],
                                                               "self_hash": righe[i]["self_hash"]}))
                self.assertNotIn(b"data", t.value[2])
            e = sv.verifica_cartella(self._cartella(b.es), **self._arg(b))
            self.assertTrue(e.ok, (formato, e))

    def test_collegamento_fuori_forma(self):
        b = self._banco()
        r = _righe_ops(1)[0]
        buono = {"idx": 0, "prev_hash": r["prev_hash"], "self_hash": r["self_hash"]}
        for cattivo in (dict(buono, ts="x"), {"idx": 0, "prev_hash": r["prev_hash"]}, dict(buono, idx=True),
                        dict(buono, idx=-1), dict(buono, idx="0"), dict(buono, self_hash=r["self_hash"].upper()),
                        dict(buono, prev_hash=r["prev_hash"][:63]), dict(buono, self_hash=r["self_hash"] + "\n"),
                        dict(buono, prev_hash=None)):
            st = sx.signed_statement(b.ISS, "omega.issuer", "omega-ledger:prova", sx.CTY_COLLEGAMENTO,
                                     sx.json_canonico(cattivo))
            a = sx.AlberoMerkle([st, ALTRA_FOGLIA])
            dati = sx.aggiungi_receipt(st, sx.receipt(b.T, "omega.ts", "omega-ledger:prova", a.radice(), 2, 0,
                                                      a.percorso(0)))
            e = b.verifica(dati)
            self.assertEqual((e.ok, e.motivo), (False, "catena_riga_non_valida"), cattivo)
        st = sx.signed_statement(b.ISS, "omega.issuer", "omega-ledger:prova", sx.CTY_COLLEGAMENTO,
                                 sx.json_canonico(buono))
        a = sx.AlberoMerkle([st, ALTRA_FOGLIA])
        self.assertTrue(b.verifica(sx.aggiungi_receipt(st, sx.receipt(b.T, "omega.ts", "omega-ledger:prova",
                                                                      a.radice(), 2, 0, a.percorso(0)))).ok)

    def _rifai(self, b, doc=None, contenuti=None, cty=None):
        """Tree rebuilt with the same policy key and the same Issuer key: only what is passed changes."""
        cty = cty or sx.CTY_COLLEGAMENTO
        doc = doc if doc is not None else b.es["politica"]
        st = [sx.signed_statement(b.P, "omega.ts", b.es["sub"], sx.CTY_POLITICA, sx.json_canonico(doc))]
        for c in contenuti if contenuti is not None else [cbor.loads(s).value[2] for s in b.es["statements"][1:]]:
            st.append(sx.signed_statement(b.ISS, "omega.issuer", b.es["sub"], cty, c))
        a = sx.AlberoMerkle(st)
        es = dict(b.es, statements=st, radice=a.radice(), tree_size=a.n,
                  transparent=[sx.aggiungi_receipt(s, sx.receipt(b.T, "omega.ts", b.es["sub"], a.radice(), a.n, i,
                                                                 a.percorso(i))) for i, s in enumerate(st)])
        return sv.verifica_cartella(self._cartella(es), **self._arg(b))

    def test_verifica_catena_collegamento(self):
        col = sx.collegamenti(_righe_ops(4))
        self.assertIsNone(sx.verifica_catena(col, "collegamento"))
        spostati = [dict(c, idx=c["idx"] + 1) for c in col]          # good shape, good chain, wrong idx
        self.assertIn("idx", sx.verifica_catena(spostati, "collegamento"))
        in_piu = [dict(col[0], ts="x")] + col[1:]                    # right idx, wrong shape
        self.assertIn("form", sx.verifica_catena(in_piu, "collegamento"))

    def test_catena_dei_collegamenti(self):
        b = self._banco()
        self.assertTrue(self._rifai(b).ok)                      # positive control: the same tree rebuilt passes
        col = [cbor.loads(s).value[2] for s in b.es["statements"][1:]]
        import json
        righe = [json.loads(c) for c in col]
        scambiate = [col[0], col[2], col[1], col[3], col[4]]
        tolta = col[:2] + col[3:]
        rotta = list(col)
        rotta[3] = sx.json_canonico(dict(righe[3], prev_hash="0" * 64))
        for nome, cc in (("swapped", scambiate), ("removed", tolta), ("broken", rotta)):
            e = self._rifai(b, contenuti=cc)
            self.assertEqual((e.ok, e.motivo), (False, "catena_riga_non_valida"), nome)

    def test_politica_forma_chiusa(self):
        b = self._banco()
        doc = b.es["politica"]
        anc = doc["ancore"][0]
        for nome, d in (("extra key", dict(doc, nota="x")), ("key removed", {k: v for k, v in doc.items()
                                                                                  if k != "formato"}),
                        ("extra in anchor", dict(doc, ancore=[dict(anc, scade="2027")])),
                        ("empty anchors", dict(doc, ancore=[])), ("anchors not a list", dict(doc, ancore=anc)),
                        ("anchor not an object", dict(doc, ancore=["x"])),
                        ("ts extra", dict(doc, ts=dict(doc["ts"], pub="00"))), ("ts not object", dict(doc, ts="x")),
                        ("vds", dict(doc, vds="CCF")), ("payload", dict(doc, payload="misto")),
                        ("payload chiaro with riservato cty", dict(doc, payload="chiaro")),
                        ("formato", dict(doc, formato="xml"))):
            e = self._rifai(b, doc=d)
            self.assertEqual((e.ok, e.motivo), (False, "politica_fuori_profilo"), nome)
        # chiaro declared but lines with link cty, and vice versa
        bc = Banco(n=3)
        e = self._rifai(bc, doc=dict(bc.es["politica"], payload="riservato"), cty=sx.CTY_RIGA_OPS)
        self.assertEqual((e.ok, e.motivo), (False, "politica_fuori_profilo"))
        self.assertTrue(self._rifai(bc, cty=sx.CTY_RIGA_OPS).ok)
        bs = Banco(n=3, righe=None)
        e = self._rifai(bs, doc=dict(bs.es["politica"], formato="ops_sha3"), cty=sx.CTY_RIGA_OPS)
        self.assertEqual((e.ok, e.motivo), (False, "politica_fuori_profilo"))

    def test_sub_chiuso_nel_verificatore(self):
        b = Banco(n=1)
        for sub in ("omega-ledger:A", "omega-ledger:", "altro:prova", "omega-ledger:a\n", "omega-ledger:" + "x" * 65):
            st = sx.signed_statement(b.ISS, "omega.issuer", sub, sx.CTY_RIGA_OPS, sx.json_canonico(_righe_ops(1)[0]))
            a = sx.AlberoMerkle([st, ALTRA_FOGLIA])
            dati = sx.aggiungi_receipt(st, sx.receipt(b.T, "omega.ts", sub, a.radice(), 2, 0, a.percorso(0)))
            e = b.verifica(dati)
            self.assertEqual((e.ok, e.motivo), (False, "cwt_fuori_profilo"), sub)


class TestChiaviPersistenti(unittest.TestCase):
    """Amendment 7: files with checked permissions, KMS/HSM backends of pq_scitt/kms.py reused."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def test_file_formati_ammessi(self):
        ke = ed25519.Ed25519PrivateKey.generate()
        km = mldsa.MLDSA65PrivateKey.generate()
        seme_m = os.urandom(32)
        casi = ((_pem(ke), -19, ke.public_key().public_bytes_raw()),
                (_pem(ke), -8, ke.public_key().public_bytes_raw()),
                (ke.private_bytes_raw().hex().encode() + b"\n", -19, ke.public_key().public_bytes_raw()),
                (_pem(km), -49, km.public_key().public_bytes_raw()),
                (seme_m.hex().upper().encode(), -49,
                 mldsa.MLDSA65PrivateKey.from_seed_bytes(seme_m).public_key().public_bytes_raw()))
        for i, (contenuto, alg, pub) in enumerate(casi):
            for modo in (0o600, 0o400):
                p = _chiave_file(self.d, "k%d_%o" % (i, modo), contenuto, modo)
                f = sx.carica_firmatario("file:" + p, alg)
                self.assertEqual((f.alg, f.pub), (alg, pub), (i, modo))
                sx.signed_statement(f, "i", "omega-ledger:a", sx.CTY_RIGA_OPS, b"{}")   # sign and self-verify

    def test_file_rifiutati(self):
        from cryptography.hazmat.primitives import serialization as ser
        ke = ed25519.Ed25519PrivateKey.generate()
        km = mldsa.MLDSA65PrivateKey.generate()
        buono = _chiave_file(self.d, "buono", _pem(ke))
        cifrato = ke.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.BestAvailableEncryption(b"pw"))
        casi = [("file:" + _chiave_file(self.d, "g", _pem(ke), 0o640), -19, "permissions"),
                ("file:" + _chiave_file(self.d, "o", _pem(ke), 0o604), -19, "permissions"),
                ("file:" + _chiave_file(self.d, "x", _pem(ke), 0o700), -19, None),       # owner execute bit: allowed
                ("file:" + _chiave_file(self.d, "m", _pem(km)), -19, "Ed25519"),
                ("file:" + _chiave_file(self.d, "e", _pem(ke)), -49, "ML-DSA"),
                ("file:" + _chiave_file(self.d, "c", cifrato), -19, "PEM"),
                ("file:" + _chiave_file(self.d, "h", b"zz" * 32), -19, "allowed formats"),
                ("file:" + _chiave_file(self.d, "h2", b"ab" * 33), -19, "allowed formats"),
                ("file:" + _chiave_file(self.d, "pub", ke.public_key().public_bytes(
                    ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)), -19, "allowed formats"),
                ("file:" + _chiave_file(self.d, "grande", b"0" * (64 * 1024 + 1)), -19, "64 KiB"),
                ("file:" + self.d, -19, "regular"), ("file:" + os.path.join(self.d, "manca"), -19, "cannot be opened"),
                ("file:", -19, "scheme"), ("file", -19, "scheme"), ("http://x", -19, "scheme"),
                ("ftp:x", -19, "scheme"), (5, -19, "string"), ("file:" + buono, 7, "allowed alg: -19, -8, -49"),
                ("file:" + _chiave_file(self.d, "limite", b"0" * (64 * 1024)), -19, "allowed formats")]   # 64 KiB: read
        link = os.path.join(self.d, "link")
        os.symlink(buono, link)
        casi.append(("file:" + link, -19, "cannot be opened"))
        fifo = os.path.join(self.d, "fifo")
        os.mkfifo(fifo, 0o600)
        casi.append(("file:" + fifo, -19, "regular file"))
        for uri, alg, testo in casi:
            if testo is None:
                sx.carica_firmatario(uri, alg)
                continue
            with self.assertRaises(sx.ExportError, msg=uri) as c:
                sx.carica_firmatario(uri, alg)
            self.assertIn(testo, str(c.exception), uri)
        from unittest import mock
        with mock.patch.object(sx.os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaises(sx.ExportError) as c:
                sx.carica_firmatario("file:" + buono, -19)
        self.assertIn("owner", str(c.exception))
        with mock.patch.object(sx.os, "fstat", side_effect=OSError("EIO")):
            with self.assertRaises(sx.ExportError) as c:   # review A2: refusal of the key, not "ledger"
                sx.carica_firmatario("file:" + buono, -19)
        self.assertIn("read error", str(c.exception))

    def test_descrittore_chiuso_anche_se_zero(self):
        """With stdin closed os.open returns descriptor 0: after a refusal it must be closed all the same."""
        import subprocess
        p = _chiave_file(self.d, "g", _pem(ed25519.Ed25519PrivateKey.generate()), 0o640)
        codice = ("import os,sys; sys.path[:0]=[%r,%r]; from pq_scitt.scitt import export as sx; os.close(0)\n"
                  "try:\n sx.carica_firmatario('file:'+%r, -19)\nexcept sx.ExportError: pass\n"
                  "try:\n os.fstat(0); print('APERTO')\nexcept OSError: print('CHIUSO')\n"
                  % (RADICE, os.path.join(RADICE, "chain"), p))
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        r = subprocess.run([sys.executable, "-c", codice], capture_output=True, env=env, timeout=60)
        self.assertEqual(r.stdout.strip(), b"CHIUSO", r.stderr[-300:])

    def _vault(self, chiave_pub, chiave_firma):
        import base64
        from unittest import mock
        from cryptography.hazmat.primitives import serialization as ser
        kms = sx._cryptovalid_kms()
        spki = chiave_pub.public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)

        def req(self_, metodo, percorso, corpo=None):    # Vault Transit: same response shapes as the API
            if metodo == "GET":
                return {"data": {"latest_version": 1, "keys": {"1": {"public_key": base64.b64encode(spki).decode()}}}}
            firma = chiave_firma.sign(base64.b64decode(corpo["input"]))
            return {"data": {"signature": "vault:v1:" + base64.b64encode(firma).decode()}}
        return [mock.patch.object(kms.VaultTransitBackend, "_req", req),
                mock.patch.dict(os.environ, {"VAULT_TOKEN": "t"})]

    def test_kms_riusato_e_autoverifica(self):
        k, altra = ed25519.Ed25519PrivateKey.generate(), ed25519.Ed25519PrivateKey.generate()
        uri = "vault:url=http://127.0.0.1:8200;key=scitt"
        for firma_con, esito in ((k, True), (altra, False)):
            patch = self._vault(k, firma_con)
            for p in patch:
                p.start()
            try:
                f = sx.carica_firmatario(uri, -19)
                self.assertEqual(f.pub, k.public_key().public_bytes_raw())
                if esito:
                    sx.signed_statement(f, "i", "omega-ledger:a", sx.CTY_RIGA_OPS, b"{}")
                else:
                    with self.assertRaises(sx.ExportError) as c:
                        sx.signed_statement(f, "i", "omega-ledger:a", sx.CTY_RIGA_OPS, b"{}")
                    self.assertIn("does not verify", str(c.exception))
            finally:
                for p in patch:
                    p.stop()
        for uri, alg, testo in (("vault:url=http://127.0.0.1:8200", -19, "vault"),
                                ("vault:url=http://127.0.0.1:8200;key=k", -49, "Ed25519 only"),
                                ("awskms-mldsa65:region=x", -49, "key_id"),
                                ("awskms-mldsa65:key_id=k", -19, "only alg -49")):
            with self.assertRaises(sx.ExportError, msg=uri) as c:
                sx.carica_firmatario(uri, alg)
            self.assertIn(testo, str(c.exception), uri)

    def test_kms_mldsa_riusato(self):
        from unittest import mock
        from cryptography.hazmat.primitives import serialization as ser
        kms = sx._cryptovalid_kms()
        km = mldsa.MLDSA65PrivateKey.generate()
        spki = km.public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)

        class Client:          # shape of the AWS KMS GetPublicKey/Sign responses (RAW, ML_DSA_SHAKE_256)
            def get_public_key(self, KeyId):
                return {"KeyId": "arn:k", "PublicKey": spki}

            def sign(self, KeyId, Message, MessageType, SigningAlgorithm):
                return {"KeyId": "arn:k", "SigningAlgorithm": SigningAlgorithm, "Signature": km.sign(Message)}
        vero = kms.AwsKmsMlDsaBackend
        with mock.patch.object(kms, "AwsKmsMlDsaBackend", lambda **kw: vero(client=Client(), **kw)):
            f = sx.carica_firmatario("awskms-mldsa65:key_id=k;region=eu-central-1", -49)
            self.assertEqual(f.pub, km.public_key().public_bytes_raw())
            sx.signed_statement(f, "i", "omega-ledger:a", sx.CTY_RIGA_OPS, b"{}")


class TestCLIExport(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.reg = os.path.join(self.d, "reg.jsonl")
        with open(self.reg, "wb") as f:
            for r in _righe_ops(4):
                f.write(sx.json_canonico(r) + b"\n")

    def _verifica(self, uscita, alg):
        import json
        with open(os.path.join(uscita, "manifest.json")) as f:
            m = json.load(f)["chiavi_pubbliche_da_confrontare_fuori_banda"]
        return sv._main([uscita, "--alg", str(alg), "--ts-pub", m["ts"][1], "--politica-pub", m["politica"][1]])

    def test_alg_mldsa_riservato_effimere(self):
        u = os.path.join(self.d, "u")
        self.assertEqual(sx._main([self.reg, u, "--nome", "r", "--versione", "1", "--payload", "riservato", "--alg", "-49",
                                   "--effimere"]), 0)
        self.assertEqual(self._verifica(u, -49), 0)
        self.assertEqual(self._verifica(u, -19), 1)

    def test_scelte_obbligatorie(self):
        u = os.path.join(self.d, "u")
        for argv in ([self.reg, u, "--nome", "r", "--effimere"],                       # --payload missing
                     [self.reg, u, "--nome", "r", "--payload", "chiaro"],              # neither keys nor --effimere
                     [self.reg, u, "--nome", "r", "--payload", "chiaro", "--chiave-ts", "file:x"],
                     [self.reg, u, "--nome", "r", "--payload", "chiaro", "--effimere", "--chiave-ts", "file:x",
                      "--chiave-issuer", "file:y", "--chiave-politica", "file:z"]):
            with self.assertRaises(SystemExit) as c:
                sx._main(argv)
            self.assertEqual(c.exception.code, 2, argv)
        self.assertFalse(os.path.exists(u))

    def test_chiavi_da_file_e_rifiuti(self):
        chiavi = []
        for n in ("i", "t", "p"):
            chiavi.append(_chiave_file(self.d, n, _pem(ed25519.Ed25519PrivateKey.generate())))
        arg = ["--chiave-issuer", "file:" + chiavi[0], "--chiave-ts", "file:" + chiavi[1],
               "--chiave-politica", "file:" + chiavi[2]]
        u1, u2 = os.path.join(self.d, "u1"), os.path.join(self.d, "u2")
        self.assertEqual(sx._main([self.reg, u1, "--nome", "r", "--versione", "1", "--payload", "chiaro"] + arg), 0)
        self.assertEqual(sx._main([self.reg, u2, "--nome", "r", "--versione", "1", "--payload", "chiaro"] + arg), 0)
        self.assertEqual(self._verifica(u1, -19), 0)
        # persistent keys: two exports of the same ledger are identical byte for byte (deterministic Ed25519)
        for n in sorted(os.listdir(u1)):
            with open(os.path.join(u1, n), "rb") as f1, open(os.path.join(u2, n), "rb") as f2:
                self.assertEqual(f1.read(), f2.read(), n)
        os.chmod(chiavi[1], 0o644)
        self.assertEqual(sx._main([self.reg, os.path.join(self.d, "u3"), "--nome", "r", "--versione", "1", "--payload", "chiaro"] + arg), 1)
        os.chmod(chiavi[1], 0o600)
        arg_uguali = ["--chiave-issuer", "file:" + chiavi[0], "--chiave-ts", "file:" + chiavi[0],
                      "--chiave-politica", "file:" + chiavi[2]]
        self.assertEqual(sx._main([self.reg, os.path.join(self.d, "u4"), "--nome", "r", "--versione", "1", "--payload", "chiaro"]
                                  + arg_uguali), 1)

    def test_registro_non_json_o_mancante(self):
        nan = os.path.join(self.d, "nan.jsonl")
        with open(nan, "w") as f:
            f.write('{"idx":0,"x":NaN}\n')
        for reg in (nan, os.path.join(self.d, "manca.jsonl")):
            self.assertEqual(sx._main([reg, os.path.join(self.d, "u"), "--nome", "r", "--payload", "chiaro",
                                       "--effimere"]), 1)


class TestRevisioneA2(unittest.TestCase):
    """review A2 (08/11): PEM with something after the END, NUL in the path, errors of the KMS backends (at load and at
    signing, including the 4096-byte limit of AWS KMS RAW), shape of the link with a longer prev_hash."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        from cryptography.hazmat.primitives import serialization as ser
        self.k = ed25519.Ed25519PrivateKey.generate()
        self.pem = self.k.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())

    def _file(self, nome, dati):
        p = os.path.join(self.d, nome)
        with open(p, "wb") as f:
            f.write(dati)
        os.chmod(p, 0o600)
        return "file:" + p

    def test_pem_solo_un_blocco(self):
        self.assertEqual(sx.carica_firmatario(self._file("ok.pem", self.pem + b"\n"), -19).pub,
                         self.k.public_key().public_bytes_raw())
        from cryptography.hazmat.primitives import serialization as ser
        altra = ed25519.Ed25519PrivateKey.generate().private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
                                                                    ser.NoEncryption())
        for nome, dati in (("coda.pem", self.pem + b"\nSPAZZATURA\n"), ("due.pem", self.pem + altra)):
            with self.assertRaises(sx.ExportError, msg=nome) as c:
                sx.carica_firmatario(self._file(nome, dati), -19)
            self.assertIn("a single PEM block", str(c.exception))

    def test_nul_nel_percorso(self):
        with self.assertRaises(sx.ExportError):
            sx.carica_firmatario("file:" + self.d + "/k\x00x", -19)

    def test_errori_kms_al_caricamento_leggibili(self):
        from unittest import mock
        kms = sx._cryptovalid_kms()

        class Strano(Exception):
            pass
        for exc in (ImportError("PyKCS11 missing"), Strano("botocore NoRegionError"), KeyError("k")):
            with mock.patch.object(kms, "backend_from_uri", side_effect=exc):
                with self.assertRaises(sx.ExportError, msg=repr(exc)):
                    sx.carica_firmatario("pkcs11:module=/x;key=k", -19)

    def test_errore_alla_firma_leggibile(self):
        def rotta(m):
            raise RuntimeError("network")
        f = sx.Firmatario(-19, self.k.public_key().public_bytes_raw(), rotta)
        with self.assertRaises(sx.ExportError) as c:
            sx.signed_statement(f, "i", "omega-ledger:a", sx.CTY_RIGA_OPS, b"{}")
        self.assertIn("RuntimeError", str(c.exception))

    def test_aws_mldsa_politica_oltre_4096_byte(self):
        """The policy with alg -49 contains the ML-DSA public key in hex (3904 characters): with AWS KMS RAW (at most
        4096 bytes) it cannot be signed. Before: an unhandled ValueError (traceback from the CLI); now a refusal."""
        from unittest import mock
        from cryptography.hazmat.primitives import serialization as ser
        kms = sx._cryptovalid_kms()
        chiavi = {n: mldsa.MLDSA65PrivateKey.generate() for n in "itp"}

        def client(km):
            spki = km.public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)

            class C:
                def get_public_key(self, KeyId):
                    return {"KeyId": "arn:" + KeyId, "PublicKey": spki}

                def sign(self, KeyId, Message, MessageType, SigningAlgorithm):
                    return {"KeyId": "arn:" + KeyId, "SigningAlgorithm": SigningAlgorithm, "Signature": km.sign(Message)}
            return C()
        vero = kms.AwsKmsMlDsaBackend
        with mock.patch.object(kms, "AwsKmsMlDsaBackend", lambda **kw: vero(client=client(chiavi[kw["key_id"]]), **kw)):
            F = {n: sx.carica_firmatario("awskms-mldsa65:key_id=%s;region=eu-central-1" % n, -49) for n in chiavi}
            with self.assertRaises(sx.ExportError) as c:
                sx.esporta(_righe_ops(2), nome="r", formato="ops", issuer=F["i"], ts=F["t"], politica=F["p"],
                           iss_issuer="i", iss_ts="t", payload="riservato")
            self.assertIn("4096", str(c.exception))
            # positive control: issuer on AWS, local TS and policy, confidential payload: passes
            loc = lambda: sx.firmatario_mldsa65(mldsa.MLDSA65PrivateKey.generate())
            es = sx.esporta(_righe_ops(2), nome="r", formato="ops", issuer=F["i"], ts=loc(), politica=loc(),
                            iss_issuer="i", iss_ts="t", payload="riservato")
            self.assertEqual(es["tree_size"], 3)

    def test_file_cresciuto_dopo_fstat(self):
        """st_size says 100 bytes, the file has 64 KiB + 10: the limit applies to the bytes read."""
        from unittest import mock
        uri = self._file("grande.pem", self.pem + b"x" * (sx.MAX_FILE_CHIAVE + 10))
        vero = os.fstat

        def finto(fd):
            st = vero(fd)
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid, st.st_gid, 100,
                                   st.st_atime, st.st_mtime, st.st_ctime))
        with mock.patch.object(sx.os, "fstat", finto):
            with self.assertRaises(sx.ExportError) as c:
                sx.carica_firmatario(uri, -19)
        self.assertIn("over 64 KiB", str(c.exception))

    def test_opzioni_ripetute_rifiutate(self):
        reg = os.path.join(self.d, "reg.jsonl")
        with open(reg, "wb") as f:
            for r in _righe_ops(2):
                f.write(sx.json_canonico(r) + b"\n")
        for extra in (["--payload", "riservato", "--payload", "chiaro", "--effimere"],
                      ["--payload", "riservato", "--chiave-issuer", "file:/a", "--chiave-issuer", "file:/b",
                       "--chiave-ts", "file:/c", "--chiave-politica", "file:/d"]):
            with self.assertRaises(SystemExit) as c:
                sx._main([reg, os.path.join(self.d, "u"), "--nome", "r", "--versione", "1"] + extra)
            self.assertEqual(c.exception.code, 2)
            self.assertFalse(os.path.exists(os.path.join(self.d, "u")))
        self.assertEqual(sx._main([reg, os.path.join(self.d, "u"), "--nome", "r", "--versione", "1", "--payload", "riservato",
                                   "--effimere"]), 0)                       # positive control

    def test_misto_chiavi_effimere_codice_2(self):
        """Surviving mutants in review A2: `any`→`all` and p.error(mixed)→pass. Mixing is a usage error (rc 2),
        before touching files or the ledger."""
        reg = os.path.join(self.d, "reg.jsonl")
        with open(reg, "wb") as f:
            for r in _righe_ops(2):
                f.write(sx.json_canonico(r) + b"\n")
        k = [self._file("k%d" % i, ed25519.Ed25519PrivateKey.generate().private_bytes_raw().hex().encode())
             for i in range(3)]
        for extra in (["--chiave-issuer", k[0], "--chiave-ts", k[1]],
                      ["--effimere", "--chiave-issuer", k[0], "--chiave-ts", k[1], "--chiave-politica", k[2]]):
            with self.assertRaises(SystemExit, msg=extra) as c:
                sx._main([reg, os.path.join(self.d, "u"), "--nome", "r", "--versione", "1", "--payload", "riservato"] + extra)
            self.assertEqual(c.exception.code, 2)
        self.assertEqual(sx._main([reg, os.path.join(self.d, "u"), "--nome", "r", "--versione", "1", "--payload", "riservato",
                                   "--chiave-issuer", k[0], "--chiave-ts", k[1], "--chiave-politica", k[2]]), 0)

    def test_regola_della_politica_vettore(self):
        """The rule text is published in leaf 0: fixed vector (the verifier reads only its cty)."""
        b = Banco(n=1)
        F = {n: _firmatario(-19) for n in "itp"}
        for modo, cty, coda in (("riservato", sx.CTY_COLLEGAMENTO, "payload JSON stretto {idx, prev_hash, self_hash} "
                                 "con collegamenti che si legano dal GENESIS"),
                                ("chiaro", sx.CTY_RIGA_OPS, "payload JSON stretto con catena hash del registro che si ricalcola")):
            es = sx.esporta(_righe_ops(1), nome="r", formato="ops", issuer=F["i"], ts=F["t"], politica=F["p"],
                            iss_issuer="i", iss_ts="t", payload=modo)
            self.assertEqual(es["politica"]["regola"],
                             "registra solo Signed Statement firmate da una ancora elencata, con alg uguale a quello "
                             "dell'ancora, header protetto esattamente {1,3,4,15}, cty " + cty + ", sub omega-ledger:r, "
                             + coda)
        del b

    def test_collegamento_prev_hash_esatto(self):
        buono = {"idx": 0, "prev_hash": "0" * 64, "self_hash": "a" * 64}
        self.assertTrue(sx.collegamento_valido(buono))
        for v in ("0" * 65, "0" * 64 + "\n", "0" * 63):
            self.assertFalse(sx.collegamento_valido(dict(buono, prev_hash=v)), repr(v))
            self.assertFalse(sx.collegamento_valido(dict(buono, self_hash=v)), repr(v))


ADESSO = 1_793_000_000           # about 2026-10-26: fixed iat of the tests
ANNO = (ADESSO - 86400, ADESSO - 86400 + 365 * 86400)


def _v2(righe=None, payload="chiaro", validita=None, revocate=(), adesso=ADESSO, alg=sx.ALG_ED25519, formato="ops"):
    b = Banco(alg=alg, n=1)
    b.es = sx.esporta(righe if righe is not None else _righe_ops(5), nome="prova", formato=formato, issuer=b.ISS, ts=b.T,
                      politica=b.P, iss_issuer="omega.issuer", iss_ts="omega.ts", payload=payload, versione=2,
                      validita=validita or {r: ANNO for r in sx.RUOLI}, revocate=list(revocate), adesso=adesso)
    return b


def _cartella_di(tc, es):
    d = tempfile.mkdtemp()
    tc.addCleanup(shutil.rmtree, d, True)
    sx.scrivi_cartella(es, d)
    return d


def _arg_cartella(b, **kw):
    a = dict(alg_statement=b.alg, alg_receipt=b.alg, chiave_ts=(b.alg, b.T.pub), chiave_politica=(b.alg, b.P.pub))
    a.update(kw)
    return a


def _v2_forzato(validita=None, revocate=()):
    """Export /2 that the real export would refuse (key out of validity or revoked): used to test the VERIFIER.
    Only the export check is skipped, the signature stays real."""
    from unittest import mock
    with mock.patch.object(sx, "_controlla_chiavi_v2", lambda *a: (ADESSO, sorted(revocate))):
        return _v2(validita=validita, revocate=revocate)


class TestRotazioneChiavi(unittest.TestCase):
    """Amendment 9 (decision A of Roberto 08/11): signed iat, validity ≤ 366 days, revoked in policy and from outside."""

    def test_v2_passa_con_iat_in_ogni_firma(self):
        for alg in (sx.ALG_ED25519, sx.ALG_MLDSA65):
            b = _v2(alg=alg)
            e = sv.verifica_cartella(_cartella_di(self, b.es), **_arg_cartella(b))
            self.assertTrue(e.ok, e)
            self.assertEqual(e.campi["profilo"], "omega-scitt/2")
            for t in b.es["transparent"]:
                c = b.verifica(t, i=0) if t is b.es["transparent"][0] else b.verifica(t)
                self.assertTrue(c.ok, c)
                self.assertEqual((c.campi["iat"], c.campi["ts_iat"]), (ADESSO, ADESSO))
            pol = b.es["politica"]
            self.assertEqual(set(pol), sx.CHIAVI_POLITICA_2)
            self.assertEqual(pol["politica"]["kid"], b.P.kid.hex())
            self.assertEqual((pol["ts"]["valida_dal"], pol["ts"]["valida_fino"]), ANNO)

    def test_v1_resta_com_era(self):
        b = Banco(n=3)
        self.assertEqual(b.es["politica"]["profilo"], "omega-scitt/1")
        self.assertNotIn(sx.CWT_IAT, cbor.loads(cbor.loads(b.es["statements"][1]).value[0])[sx.H_CWT])
        self.assertTrue(sv.verifica_cartella(_cartella_di(self, b.es), **_arg_cartella(b)).ok)

    def test_revocata_da_fuori(self):
        b = _v2()
        d = _cartella_di(self, b.es)
        self.assertTrue(sv.verifica_cartella(d, **_arg_cartella(b, revocate_esterne=["0" * 32])).ok)  # control
        for f in (b.ISS, b.T, b.P):
            e = sv.verifica_cartella(d, **_arg_cartella(b, revocate_esterne=[f.kid.hex()]))
            self.assertEqual((e.ok, e.motivo), (False, "chiave_revocata"))
        # also on an export /1 (revocation channel)
        b1 = Banco(n=2)
        e = sv.verifica_cartella(_cartella_di(self, b1.es), **_arg_cartella(b1, revocate_esterne=[b1.ISS.kid.hex()]))
        self.assertEqual((e.ok, e.motivo), (False, "chiave_revocata"))
        for cattiva in (["0" * 31], ["0" * 33], ["0" * 32 + "\n"], ["A" * 32], [b"0" * 32], "0" * 32, [None]):
            e = sv.verifica_cartella(d, **_arg_cartella(b, revocate_esterne=cattiva))
            self.assertEqual((e.ok, e.motivo), (False, "revocate_fuori_forma"), cattiva)

    def test_revocata_nella_politica(self):
        b = _v2(revocate=["f" * 32, "0" * 32])
        self.assertEqual(b.es["politica"]["revocate"], ["0" * 32, "f" * 32])
        self.assertTrue(sv.verifica_cartella(_cartella_di(self, b.es), **_arg_cartella(b)).ok)
        for ruolo in ("issuer", "ts", "politica"):
            with self.assertRaises(sx.ExportError):
                bb = Banco(n=1)
                f = {"issuer": bb.ISS, "ts": bb.T, "politica": bb.P}[ruolo]
                sx.esporta(_righe_ops(2), nome="p", formato="ops", issuer=bb.ISS, ts=bb.T, politica=bb.P,
                           iss_issuer="i", iss_ts="t", versione=2, validita={r: ANNO for r in sx.RUOLI},
                           revocate=[f.kid.hex()], adesso=ADESSO)
        # forced export with the Issuer key among the revoked: the verifier refuses it
        bf = _v2_forzato(revocate=[])
        kid = bf.ISS.kid.hex()
        from unittest import mock
        with mock.patch.object(sx, "_controlla_chiavi_v2", lambda *a: (ADESSO, [kid])):
            bf.es = sx.esporta(_righe_ops(3), nome="prova", formato="ops", issuer=bf.ISS, ts=bf.T, politica=bf.P,
                               iss_issuer="omega.issuer", iss_ts="omega.ts", versione=2,
                               validita={r: ANNO for r in sx.RUOLI}, adesso=ADESSO)
        e = sv.verifica_cartella(_cartella_di(self, bf.es), **_arg_cartella(bf))
        self.assertEqual((e.ok, e.motivo), (False, "chiave_revocata"))

    def test_fuori_validita(self):
        prima, dopo = (ADESSO - 400 * 86400, ADESSO - 40 * 86400), (ADESSO + 1, ADESSO + 86400)
        for ruolo in sx.RUOLI:
            for finestra in (prima, dopo):
                val = {r: ANNO for r in sx.RUOLI}
                val[ruolo] = finestra
                with self.assertRaises(sx.ExportError, msg=(ruolo, finestra)):
                    _v2(validita=val)
                bf = _v2_forzato(validita=val)
                e = sv.verifica_cartella(_cartella_di(self, bf.es), **_arg_cartella(bf))
                self.assertEqual((e.ok, e.motivo), (False, "chiave_fuori_validita"), (ruolo, finestra))
        # at the edges: iat == dal and iat == fino pass
        for finestra in ((ADESSO, ADESSO + 10), (ADESSO - 10, ADESSO)):
            b = _v2(validita={r: finestra for r in sx.RUOLI})
            self.assertTrue(sv.verifica_cartella(_cartella_di(self, b.es), **_arg_cartella(b)).ok, finestra)

    def test_validita_e_revocate_forma(self):
        M = sx.MAX_VALIDITA
        self.assertEqual(M, 366 * 86400)
        for dal, fino, ok in ((0, 1, True), (5, 5 + M, True), (5, 6 + M, False), (5, 5, False), (5, 4, False),
                              (-1, 3, False), (True, 3, False), (1, 2.0, False), ("1", 2, False)):
            self.assertEqual(sx.validita_valida(dal, fino), ok, (dal, fino))
        for lista, ok in (([], True), (["0" * 32, "1" * 32], True), (["1" * 32, "0" * 32], False),
                          (["0" * 32, "0" * 32], False), (["A" * 32], False), (["0" * 33], False),
                          (["0" * 32 + "\n"], False), ("0" * 32, False), ([0], False)):
            self.assertEqual(sx.revocate_valide(lista), ok, lista)
        for val in ({r: ANNO for r in ("issuer", "ts")}, dict({r: ANNO for r in sx.RUOLI}, altro=ANNO),
                    dict({r: ANNO for r in sx.RUOLI}, ts=(ADESSO - 10, ADESSO - 10 + M + 1)),
                    dict({r: ANNO for r in sx.RUOLI}, ts=(ADESSO,)), None):
            with self.assertRaises(sx.ExportError, msg=val):
                bb = Banco(n=1)
                sx.esporta(_righe_ops(2), nome="p", formato="ops", issuer=bb.ISS, ts=bb.T, politica=bb.P,
                           iss_issuer="i", iss_ts="t", versione=2, validita=val, adesso=ADESSO)
        for rev in (["0" * 32, "0" * 32], ["x" * 32], [1], "0" * 32):
            with self.assertRaises(sx.ExportError, msg=rev):
                _v2(revocate=rev) if not isinstance(rev, str) else sx.esporta(
                    _righe_ops(1), nome="p", formato="ops", issuer=_firmatario(-19), ts=_firmatario(-19),
                    politica=_firmatario(-19), iss_issuer="i", iss_ts="t", versione=2,
                    validita={r: ANNO for r in sx.RUOLI}, revocate=rev, adesso=ADESSO)
        for v in (0, 3, True, "2"):
            with self.assertRaises(sx.ExportError, msg=v):
                Banco(n=1).es and sx.esporta(_righe_ops(1), nome="p", formato="ops", issuer=_firmatario(-19),
                                             ts=_firmatario(-19), politica=_firmatario(-19), iss_issuer="i",
                                             iss_ts="t", versione=v)
        for extra in (dict(validita={r: ANNO for r in sx.RUOLI}), dict(revocate=["0" * 32]), dict(adesso=ADESSO)):
            with self.assertRaises(sx.ExportError, msg=extra):
                sx.esporta(_righe_ops(1), nome="p", formato="ops", issuer=_firmatario(-19), ts=_firmatario(-19),
                           politica=_firmatario(-19), iss_issuer="i", iss_ts="t", **extra)
        for adesso in (-1, 1.5, "1"):
            with self.assertRaises(sx.ExportError, msg=adesso):
                _v2(adesso=adesso)
        # edge: iat = 0 is a valid NumericDate
        b0 = _v2(adesso=0, validita={r: (0, 100) for r in sx.RUOLI})
        self.assertTrue(sv.verifica_cartella(_cartella_di(self, b0.es), **_arg_cartella(b0)).ok)
        self.assertTrue(sx.signed_statement(b0.ISS, "i", "omega-ledger:p", sx.CTY_RIGA_OPS, b"{}", 0))
        # revocate that is not a list: refusal even if the content looks good
        for rev in ({"0" * 32}, frozenset(), None):
            with self.assertRaises(sx.ExportError, msg=rev):
                sx.esporta(_righe_ops(1), nome="p", formato="ops", issuer=_firmatario(-19), ts=_firmatario(-19),
                           politica=_firmatario(-19), iss_issuer="i", iss_ts="t", versione=2,
                           validita={r: ANNO for r in sx.RUOLI}, revocate=rev, adesso=ADESSO)

    def test_regola_v2_vettore(self):
        b = _v2(righe=_righe_ops(1), payload="riservato")
        self.assertEqual(b.es["politica"]["regola"],
                         "registra solo Signed Statement firmate da una ancora elencata, con alg uguale a quello "
                         "dell'ancora, header protetto esattamente {1,3,4,15}, CWT esattamente {1,2,6} con iat nella "
                         "validità della chiave, kid non revocato, cty " + sx.CTY_IMPEGNO + ", sub omega-ledger:prova, "
                         "payload JSON stretto {idx, impegno}, impegno = SHA-256(dominio, sale di 32 byte, riga), "
                         "sali fuori dall'export")

    def test_dettaglio_della_foglia_0(self):
        b = _v2()
        d = _cartella_di(self, b.es)
        e = sv.verifica_cartella(d, **_arg_cartella(b, revocate_esterne=[b.P.kid.hex()]))
        self.assertEqual(e.motivo, "chiave_revocata")
        self.assertIn("ts_000000.cose", e.dettaglio)

    def test_politica_v2_forma_chiusa(self):
        b = _v2()
        doc = b.es["politica"]
        anc, tsd, pol = doc["ancore"][0], doc["ts"], doc["politica"]
        cattivi = (("extra key", dict(doc, nota="x")),
                   ("revocate removed", {k: v for k, v in doc.items() if k != "revocate"}),
                   ("politica removed", {k: v for k, v in doc.items() if k != "politica"}),
                   ("anchor no validity", dict(doc, ancore=[{k: v for k, v in anc.items() if k != "valida_fino"}])),
                   ("anchor with extra", dict(doc, ancore=[dict(anc, x=1)])),
                   ("anchor validity too long", dict(doc, ancore=[dict(anc, valida_fino=anc["valida_dal"] + 366 * 86400 + 1)])),
                   ("ts without validity", dict(doc, ts={k: v for k, v in tsd.items() if k != "valida_dal"})),
                   ("ts with extra", dict(doc, ts=dict(tsd, x=1))), ("ts not an object", dict(doc, ts=sorted(tsd))),
                   ("politica list of the keys", dict(doc, politica=sorted(pol))),
                   ("anchor not an object", dict(doc, ancore=["x"])), ("anchor list", dict(doc, ancore=[sorted(anc)])),
                   ("anchor kid not a string", dict(doc, ancore=[dict(anc, kid=1)])),
                   ("ts validity reversed", dict(doc, ts=dict(tsd, valida_dal=tsd["valida_fino"]))),
                   ("politica other kid", dict(doc, politica=dict(pol, kid="0" * 32))),
                   ("politica other alg", dict(doc, politica=dict(pol, alg=-8))),
                   ("politica with extra", dict(doc, politica=dict(pol, pub="00"))),
                   ("politica not an object", dict(doc, politica="x")),
                   ("revocate unsorted", dict(doc, revocate=["1" * 32, "0" * 32])),
                   ("revocate not a list", dict(doc, revocate="0" * 32)),
                   ("unknown profilo", dict(doc, profilo="omega-scitt/3")),
                   ("profilo /1 with /2 shape", dict(doc, profilo="omega-scitt/1")),
                   ("profilo not a string", dict(doc, profilo=["omega-scitt/2"])))
        self.assertTrue(self._rifai(b).ok)                                  # positive control
        for nome, d in cattivi:
            e = self._rifai(b, doc=d)
            self.assertEqual((e.ok, e.motivo), (False, "politica_fuori_profilo"), nome)
        # policy /1 on leaves with iat, and policy /2 on leaves without iat: refusal
        b1 = Banco(n=3)
        e = self._rifai(b1, iat=ADESSO)
        self.assertEqual((e.ok, e.motivo), (False, "cwt_fuori_profilo"))
        e = self._rifai(b, iat=None)
        self.assertEqual((e.ok, e.motivo), (False, "cwt_fuori_profilo"))
        e = self._rifai(b, iat_receipt=None)
        self.assertEqual((e.ok, e.motivo), (False, "cwt_fuori_profilo"))

    def _rifai(self, b, doc=None, iat="uguale", iat_receipt="uguale"):
        doc = doc if doc is not None else b.es["politica"]
        i_st = ADESSO if (iat == "uguale" and doc.get("profilo") != "omega-scitt/1"
                          and b.es["politica"]["profilo"] == "omega-scitt/2") else (None if iat == "uguale" else iat)
        i_rc = i_st if iat_receipt == "uguale" else iat_receipt
        cty = cbor.loads(cbor.loads(b.es["statements"][1]).value[0])[sx.H_CTY]
        st = [sx.signed_statement(b.P, "omega.ts", b.es["sub"], sx.CTY_POLITICA, sx.json_canonico(doc), i_st)]
        for s in b.es["statements"][1:]:
            st.append(sx.signed_statement(b.ISS, "omega.issuer", b.es["sub"], cty, cbor.loads(s).value[2], i_st))
        a = sx.AlberoMerkle(st)
        es = dict(b.es, statements=st, radice=a.radice(), tree_size=a.n,
                  transparent=[sx.aggiungi_receipt(s, sx.receipt(b.T, "omega.ts", b.es["sub"], a.radice(), a.n, i,
                                                                 a.percorso(i), i_rc)) for i, s in enumerate(st)])
        return sv.verifica_cartella(_cartella_di(self, es), **_arg_cartella(b))

    def test_cwt_iat_forma(self):
        b = Banco(n=1)
        for iat in (-1, "1", 1.5, True, None):
            prot = {sx.H_CWT: {1: "i", 2: "omega-ledger:p", 6: iat}}
            with self.assertRaises(sv._Rifiuto) as c:
                sv._cwt(prot, "x")
            self.assertEqual(c.exception.motivo, "cwt_fuori_profilo", iat)
        for chiavi in ({1: "i", 2: "omega-ledger:p", 7: 1}, {1: "i", 6: 1}, {1: "i", 2: "omega-ledger:p", 6: 1, 4: 1}):
            with self.assertRaises(sv._Rifiuto):
                sv._cwt({sx.H_CWT: chiavi}, "x")
        self.assertEqual(sv._cwt({sx.H_CWT: {1: "i", 2: "omega-ledger:p", 6: 0}}, "x"), ("i", "omega-ledger:p", 0))
        with self.assertRaises(sx.ExportError):
            sx.signed_statement(b.ISS, "i", "omega-ledger:p", sx.CTY_RIGA_OPS, b"{}", -1)
        with self.assertRaises(sx.ExportError):
            sx.signed_statement(b.ISS, "i", "omega-ledger:p", sx.CTY_RIGA_OPS, b"{}", True)

    def test_chiave_nel_tempo_rami(self):
        k = b"\x01" * 16
        val = {k.hex(): (10, 20)}
        self.assertIsNone(sv._chiave_nel_tempo(1, k, None, {}, set(), "x"))
        self.assertEqual(sv._chiave_nel_tempo(1, k, 15, {}, set(), "x").motivo, "cwt_fuori_profilo")
        self.assertIn("/1", sv._chiave_nel_tempo(1, k, 15, {}, set(), "x").dettaglio)
        self.assertEqual(sv._chiave_nel_tempo(1, k, None, {}, {k.hex()}, "x").motivo, "chiave_revocata")
        self.assertEqual(sv._chiave_nel_tempo(2, k, None, val, set(), "x").motivo, "cwt_fuori_profilo")
        self.assertEqual(sv._chiave_nel_tempo(2, k, 15, val, {k.hex()}, "x").motivo, "chiave_revocata")
        for iat, motivo in ((9, "chiave_fuori_validita"), (21, "chiave_fuori_validita")):
            self.assertEqual(sv._chiave_nel_tempo(2, k, iat, val, set(), "x").motivo, motivo)
        for iat in (10, 15, 20):
            self.assertIsNone(sv._chiave_nel_tempo(2, k, iat, val, set(), "x"))


class TestSalePerRiga(unittest.TestCase):
    """Amendment 10 (decision B, 08/11): riservato /2 = {idx, impegno} with a 32-byte salt per line."""

    def test_impegno_vettore_fisso(self):
        sale = bytes(range(32))
        riga = {"idx": 0, "x": "è"}
        atteso = hashlib.sha256(b"omega-scitt/2 impegno-riga\x00" + sale + b'{"idx":0,"x":"\\u00e8"}').hexdigest()
        self.assertEqual(sx.impegno_riga(sale, riga), atteso)
        for s in (bytes(31), bytes(33), bytearray(32), "0" * 64, None):
            with self.assertRaises(sx.ExportError, msg=s):
                sx.impegno_riga(s, riga)
        self.assertTrue(sx.impegno_valido({"idx": 0, "impegno": atteso}))
        for d in ({"idx": 0, "impegno": atteso.upper()}, {"idx": -1, "impegno": atteso}, {"idx": 0},
                  {"idx": True, "impegno": atteso}, {"idx": 0, "impegno": atteso, "self_hash": atteso},
                  {"idx": 0, "impegno": atteso + "\n"}, {"idx": 0, "impegno": atteso[:-1]}, [0, atteso]):
            self.assertFalse(sx.impegno_valido(d), d)

    def test_riservato_v2_non_porta_collegamenti(self):
        righe = _righe_ops(6)
        b = _v2(righe=righe, payload="riservato")
        sali = b.es["sali"]
        self.assertEqual(len(sali), 6)
        self.assertTrue(all(type(s) is bytes and len(s) == 32 for s in sali))
        self.assertEqual(len(set(sali)), 6)
        tutto = b"".join(b.es["transparent"])
        for i, r in enumerate(righe):
            p = cbor.loads(b.es["statements"][i + 1]).value[2]
            self.assertEqual(p, sx.json_canonico({"idx": i, "impegno": sx.impegno_riga(sali[i], r)}))
            for h in (r["self_hash"], r["prev_hash"]) if i else (r["self_hash"],):
                self.assertNotIn(h.encode(), tutto)
            # whoever knows the WHOLE line but not the salt cannot confirm it
            import json
            self.assertNotEqual(sx.impegno_riga(b"\x00" * 32, r), json.loads(p)["impegno"])
            self.assertNotEqual(sx.hash_riga_ops(r), json.loads(p)["impegno"])
        for s in sali:
            self.assertNotIn(s, tutto)
            self.assertNotIn(s.hex().encode(), tutto)
        # positive control: in riservato /1 the self_hash values are there, and confirm the line
        b1 = Banco(n=1)
        b1.es = sx.esporta(righe, nome="prova", formato="ops", issuer=b1.ISS, ts=b1.T, politica=b1.P,
                           iss_issuer="omega.issuer", iss_ts="omega.ts", payload="riservato")
        self.assertIn(righe[3]["self_hash"].encode(), b"".join(b1.es["transparent"]))
        self.assertIsNone(b1.es["sali"])
        # new salts at every export
        b2 = _v2(righe=righe, payload="riservato")
        self.assertNotEqual(b.es["statements"][1:], b2.es["statements"][1:])

    def test_verifica_senza_e_con_sali(self):
        for formato, righe in (("ops", _righe_ops(5)), ("chain", _eventi_chain("n4")[:3])):
            b = _v2(righe=righe, payload="riservato", formato=formato)
            d = _cartella_di(self, b.es)
            sali = b.es["sali"]
            self.assertEqual(json_manifest(d)["profilo"], "omega-scitt/2")
            self.assertNotIn("sali", json_manifest(d))
            self.assertTrue(sv.verifica_cartella(d, **_arg_cartella(b)).ok)
            e = sv.verifica_cartella(d, **_arg_cartella(b, righe=righe, sali=sali))
            self.assertTrue(e.ok, (formato, e))
            cattivi = (("salt changed", righe, [sali[0], bytes(32)] + sali[2:], "impegno_non_valido"),
                       ("line changed", [dict(righe[0], prev_hash="1" * 64)] + righe[1:], sali, "impegno_non_valido"),
                       ("salts swapped", righe, [sali[1], sali[0]] + sali[2:], "impegno_non_valido"),
                       ("salt short", righe, [sali[0][:31]] + sali[1:], "impegno_non_valido"),
                       ("salt not bytes", righe, [None] + sali[1:], "impegno_non_valido"),
                       ("one salt fewer", righe, sali[:-1], "impegno_non_valido"),
                       ("one extra line", righe + [righe[0]], sali + [sali[0]], "impegno_non_valido"),
                       ("lines only", righe, None, "impegno_non_valido"),
                       ("salts only", None, sali, "impegno_non_valido"),
                       ("lines not a list", "x", sali, "impegno_non_valido"))
            for nome, rr, ss, motivo in cattivi:
                e = sv.verifica_cartella(d, **_arg_cartella(b, righe=rr, sali=ss))
                self.assertEqual((e.ok, e.motivo), (False, motivo), (formato, nome))
        # right commitments on lines with a broken chain: the commitments hold, the chain does not
        rotte = _righe_ops(3)
        rotte[1]["prev_hash"] = "2" * 64
        rotte[1]["self_hash"] = sx.hash_riga_ops(rotte[1])
        from unittest import mock
        with mock.patch.object(sx, "verifica_catena", lambda *a: None):
            bf = _v2(righe=rotte, payload="riservato")
        e = sv.verifica_cartella(_cartella_di(self, bf.es), **_arg_cartella(bf, righe=rotte, sali=bf.es["sali"]))
        self.assertEqual((e.ok, e.motivo), (False, "catena_riga_non_valida"))
        self.assertTrue(sv.verifica_cartella(_cartella_di(self, bf.es), **_arg_cartella(bf)).ok)  # not seen without salts

    def test_sali_per_export_senza_impegni(self):
        righe = _righe_ops(3)
        for b in (_v2(righe=righe), Banco(righe=righe)):
            e = sv.verifica_cartella(_cartella_di(self, b.es), **_arg_cartella(b, righe=righe, sali=[bytes(32)] * 3))
            self.assertEqual((e.ok, e.motivo), (False, "impegno_non_valido"))

    def test_idx_degli_impegni(self):
        b = _v2(payload="riservato")
        imp = [cbor.loads(s).value[2] for s in b.es["statements"][1:]]
        self.assertTrue(TestRotazioneChiavi._rifai(self, b).ok)
        import json
        spostati = [sx.json_canonico(dict(json.loads(p), idx=json.loads(p)["idx"] + 1)) for p in imp]
        st = [b.es["statements"][0]] + [sx.signed_statement(b.ISS, "omega.issuer", b.es["sub"], sx.CTY_IMPEGNO, p, ADESSO)
                                        for p in spostati]
        a = sx.AlberoMerkle(st)
        es = dict(b.es, statements=st, radice=a.radice(), tree_size=a.n,
                  transparent=[sx.aggiungi_receipt(s, sx.receipt(b.T, "omega.ts", b.es["sub"], a.radice(), a.n, i,
                                                                 a.percorso(i), ADESSO)) for i, s in enumerate(st)])
        e = sv.verifica_cartella(_cartella_di(self, es), **_arg_cartella(b))
        self.assertEqual((e.ok, e.motivo), (False, "catena_riga_non_valida"))
        # a single wrong idx (the last) is enough
        uno = [cbor.loads(s).value[2] for s in b.es["statements"][1:]]
        uno[-1] = sx.json_canonico(dict(json.loads(uno[-1]), idx=99))
        st = [b.es["statements"][0]] + [sx.signed_statement(b.ISS, "omega.issuer", b.es["sub"], sx.CTY_IMPEGNO, p, ADESSO)
                                        for p in uno]
        a = sx.AlberoMerkle(st)
        es = dict(b.es, statements=st, radice=a.radice(), tree_size=a.n,
                  transparent=[sx.aggiungi_receipt(s, sx.receipt(b.T, "omega.ts", b.es["sub"], a.radice(), a.n, i,
                                                                 a.percorso(i), ADESSO)) for i, s in enumerate(st)])
        e = sv.verifica_cartella(_cartella_di(self, es), **_arg_cartella(b))
        self.assertEqual((e.ok, e.motivo), (False, "catena_riga_non_valida"))
        # wrong shape of the commitment: refused already on the leaf
        st = sx.signed_statement(b.ISS, "omega.issuer", b.es["sub"], sx.CTY_IMPEGNO,
                                 sx.json_canonico({"idx": 0, "impegno": "x"}), ADESSO)
        a = sx.AlberoMerkle([st, ALTRA_FOGLIA])
        dati = sx.aggiungi_receipt(st, sx.receipt(b.T, "omega.ts", b.es["sub"], a.radice(), 2, 0, a.percorso(0), ADESSO))
        self.assertEqual(b.verifica(dati).motivo, "catena_riga_non_valida")

    def test_leggi_e_scrivi_sali(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        f = os.path.join(d, "sali.jsonl")
        sali = [os.urandom(32) for _ in range(3)]
        sx.scrivi_sali(sali, f)
        self.assertEqual(os.stat(f).st_mode & 0o777, 0o600)
        self.assertEqual(sx.leggi_sali(f), sali)
        with self.assertRaises(sx.ExportError):
            sx.scrivi_sali(sali, f)                                   # does not overwrite
        link = os.path.join(d, "link")
        os.symlink(os.path.join(d, "altro"), link)
        with self.assertRaises(sx.ExportError):
            sx.scrivi_sali(sali, link)
        self.assertFalse(os.path.exists(os.path.join(d, "altro")))
        for righe in ('{"idx":1,"sale":"%s"}\n' % ("0" * 64), '{"idx":0,"sale":"%s"}\n' % ("0" * 63),
                      '{"idx":0,"sale":"%s","x":1}\n' % ("0" * 64), '{"idx":0,"sale":"%s"}\n' % ("A" * 64),
                      '[0]\n', '{"idx":true,"sale":"%s"}\n' % ("0" * 64), '{"idx":0,"sale":"%s\\n"}\n' % ("0" * 64)):
            g = os.path.join(d, "g%d" % hash(righe))
            with open(g, "w") as h:
                h.write(righe)
            with self.assertRaises(sx.ExportError, msg=righe):
                sx.leggi_sali(g)


def json_manifest(d):
    import json
    with open(os.path.join(d, "manifest.json")) as f:
        return json.load(f)


class TestCLIVersione2(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.reg = os.path.join(self.d, "reg.jsonl")
        self.righe = _righe_ops(4)
        with open(self.reg, "wb") as f:
            for r in self.righe:
                f.write(sx.json_canonico(r) + b"\n")

    def _pub(self, u):
        m = json_manifest(u)["chiavi_pubbliche_da_confrontare_fuori_banda"]
        return ["--ts-pub", m["ts"][1], "--politica-pub", m["politica"][1]]

    def test_riservato_v2_con_sali(self):
        u, s = os.path.join(self.d, "u"), os.path.join(self.d, "sali.jsonl")
        self.assertEqual(sx._main([self.reg, u, "--nome", "r", "--payload", "riservato", "--effimere", "--sali", s]), 0)
        self.assertEqual(os.stat(s).st_mode & 0o777, 0o600)
        self.assertEqual(json_manifest(u)["profilo"], "omega-scitt/2")
        self.assertEqual(sv._main([u, "--alg", "-19"] + self._pub(u)), 0)
        self.assertEqual(sv._main([u, "--alg", "-19", "--registro", self.reg, "--sali", s] + self._pub(u)), 0)
        altro = os.path.join(self.d, "altro.jsonl")
        with open(altro, "wb") as f:
            for r in _righe_ops(4)[:3]:
                f.write(sx.json_canonico(r) + b"\n")
        self.assertEqual(sv._main([u, "--alg", "-19", "--registro", altro, "--sali", s] + self._pub(u)), 1)
        self.assertEqual(sv._main([u, "--alg", "-19", "--registro", self.reg, "--sali", self.reg] + self._pub(u)), 1)
        self.assertEqual(sv._main([u, "--alg", "-19", "--registro", self.reg, "--sali", s + "x"] + self._pub(u)), 1)
        with self.assertRaises(SystemExit) as c:
            sv._main([u, "--alg", "-19", "--registro", self.reg] + self._pub(u))
        self.assertEqual(c.exception.code, 2)
        kid = sx.kid_di(bytes.fromhex(json_manifest(u)["politica"]["ancore"][0]["pub"])).hex()
        self.assertEqual(sv._main([u, "--alg", "-19", "--revocata", kid] + self._pub(u)), 1)
        # salts file already exists: refusal
        self.assertEqual(sx._main([self.reg, os.path.join(self.d, "u2"), "--nome", "r", "--payload", "riservato",
                                   "--effimere", "--sali", s]), 1)

    def test_errori_d_uso(self):
        u, s = os.path.join(self.d, "u"), os.path.join(self.d, "sali.jsonl")
        base = [self.reg, u, "--nome", "r", "--effimere"]
        for extra in (["--payload", "riservato"],                                   # v2 riservato without --sali
                      ["--payload", "chiaro", "--sali", s],                         # --sali without riservato
                      ["--payload", "riservato", "--sali", os.path.join(u, "s")],   # salts inside the output
                      ["--payload", "riservato", "--sali", u],
                      ["--payload", "riservato", "--versione", "1", "--sali", s],
                      ["--payload", "chiaro", "--versione", "1", "--revocata", "0" * 32],
                      ["--payload", "chiaro", "--versione", "1", "--validita-ts", "x"],
                      ["--payload", "chiaro", "--versione", "2", "--versione", "2"],
                      ["--payload", "chiaro", "--versione", "3"]):
            with self.assertRaises(SystemExit, msg=extra) as c:
                sx._main(base + extra)
            self.assertEqual(c.exception.code, 2, extra)
            self.assertFalse(os.path.exists(u), extra)
            self.assertFalse(os.path.exists(s), extra)
        self.assertEqual(sx._main(base + ["--payload", "chiaro"]), 0)               # positive control
        import io
        from contextlib import redirect_stdout
        for payload, avviso in (("riservato", True), ("chiaro", False)):
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(sx._main([self.reg, os.path.join(self.d, "v1" + payload), "--nome", "r", "--effimere",
                                           "--versione", "1", "--payload", payload]), 0)
            self.assertEqual("WARNING format 1" in out.getvalue(), avviso, payload)
        self.assertEqual(json_manifest(u)["profilo"], "omega-scitt/2")

    def test_chiavi_persistenti_vogliono_validita(self):
        k = []
        for n in "itp":
            p = os.path.join(self.d, n)
            fd = os.open(p, os.O_WRONLY | os.O_CREAT, 0o600)
            os.write(fd, ed25519.Ed25519PrivateKey.generate().private_bytes_raw().hex().encode())
            os.close(fd)
            k.append("file:" + p)
        chiavi = ["--chiave-issuer", k[0], "--chiave-ts", k[1], "--chiave-politica", k[2]]
        u = os.path.join(self.d, "u")
        with self.assertRaises(SystemExit) as c:
            sx._main([self.reg, u, "--nome", "r", "--payload", "chiaro"] + chiavi + ["--validita-ts", "x"])
        self.assertEqual(c.exception.code, 2)
        import datetime as dt
        oggi = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        f = "%Y-%m-%dT%H:%M:%SZ"
        buona = (oggi - dt.timedelta(days=1)).strftime(f) + "/" + (oggi + dt.timedelta(days=300)).strftime(f)
        val = ["--validita-issuer", buona, "--validita-ts", buona, "--validita-politica", buona]
        self.assertEqual(sx._main([self.reg, u, "--nome", "r", "--payload", "chiaro"] + chiavi + val), 0)
        self.assertEqual(sv._main([u, "--alg", "-19"] + self._pub(u)), 0)
        scaduta = (oggi - dt.timedelta(days=300)).strftime(f) + "/" + (oggi - dt.timedelta(days=1)).strftime(f)
        lunga = (oggi - dt.timedelta(days=1)).strftime(f) + "/" + (oggi + dt.timedelta(days=366)).strftime(f)
        senza_zeri = (oggi - dt.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ").replace("-0", "-").replace("T0", "T")
        for v in (scaduta, lunga, buona.replace("Z", ""), buona + "/x", "2026-02-30T00:00:00Z/2026-03-01T00:00:00Z",
                  buona.replace("T", " "), buona + "/" + buona.split("/")[1], senza_zeri + "/" + buona.split("/")[1]):
            self.assertEqual(sx._main([self.reg, os.path.join(self.d, "u%d" % hash(v)), "--nome", "r", "--payload",
                                       "chiaro"] + chiavi + ["--validita-issuer", v, "--validita-ts", buona,
                                                             "--validita-politica", buona]), 1, v)
        kid_t = sx.kid_di(bytes.fromhex(json_manifest(u)["chiavi_pubbliche_da_confrontare_fuori_banda"]["ts"][1])).hex()
        self.assertEqual(sx._main([self.reg, os.path.join(self.d, "ur"), "--nome", "r", "--payload", "chiaro",
                                   "--revocata", kid_t] + chiavi + val), 1)
        self.assertEqual(sx._main([self.reg, os.path.join(self.d, "ur2"), "--nome", "r", "--payload", "chiaro",
                                   "--revocata", "0" * 32, "--revocata", "f" * 32] + chiavi + val), 0)
        self.assertEqual(json_manifest(os.path.join(self.d, "ur2"))["politica"]["revocate"], ["0" * 32, "f" * 32])


def _proof_di_riferimento(foglie_h, m):
    """PROOF(m, D_n) written from the definition of RFC 9162 §2.1.4.1 with lists (independent of AlberoMerkle)."""
    def mth(h):
        if len(h) == 1:
            return h[0]
        k = sx._k(len(h))
        return sx.hash_nodo(mth(h[:k]), mth(h[k:]))

    def sub(m_, d, b):
        if m_ == len(d):
            return [] if b else [mth(d)]
        k = sx._k(len(d))
        if m_ <= k:
            return sub(m_, d[:k], b) + [mth(d[k:])]
        return sub(m_ - k, d[k:], False) + [mth(d[:k])]
    return sub(m, foglie_h, True), mth(foglie_h)


class TestConsistenza(unittest.TestCase):
    """Amendment 11 (item C): extension of an export and consistency proof RFC 9162 §2.1.4."""

    def test_prova_contro_definizione_e_alterazioni(self):
        foglie = [b"foglia %d" % i for i in range(40)]
        for n in range(2, 41):
            a = sx.AlberoMerkle(foglie[:n])
            for m in range(1, n):
                pr = a.consistenza(m)
                rif, rad_n = _proof_di_riferimento([sx.hash_foglia(f) for f in foglie[:n]], m)
                self.assertEqual(pr, rif, (m, n))
                rad_m = sx.AlberoMerkle(foglie[:m]).radice()
                self.assertEqual(rad_n, a.radice())
                self.assertTrue(sv.consistenza_regge(m, n, rad_m, rad_n, pr), (m, n))
                self.assertFalse(sv.consistenza_regge(m, n, rad_m, rad_n, pr[:-1]), (m, n, "truncated"))
                self.assertFalse(sv.consistenza_regge(m, n, rad_m, rad_n, pr + [rad_m]), (m, n, "lengthened"))
                for j in range(len(pr)):
                    alt = list(pr)
                    alt[j] = bytes([alt[j][0] ^ 1]) + alt[j][1:]
                    self.assertFalse(sv.consistenza_regge(m, n, rad_m, rad_n, alt), (m, n, j))
                self.assertFalse(sv.consistenza_regge(m, n, rad_n, rad_n, pr) and rad_m != rad_n)
                self.assertFalse(sv.consistenza_regge(m, n, rad_m, rad_m, pr) and rad_m != rad_n)
                if m + 1 < n:
                    self.assertFalse(sv.consistenza_regge(m + 1, n, rad_m, rad_n, pr), (m, n, "wrong m"))
                # tree_size does not enter the hashes: n+1 with the root of n can close (m=1, n=3 measured). That is why
                # tree_size is signed separately (-65538) and verifica_consistenza takes it from the signed heads.
                if n < 40:
                    a1 = sx.AlberoMerkle(foglie[:n + 1])
                    self.assertFalse(sv.consistenza_regge(m, n + 1, rad_m, a1.radice(), pr) and len(pr) > 0
                                     and a1.consistenza(m) != pr, (m, n, "wrong n"))
                # past rewritten: leaf 0 changed, same proof and same old root
                b = sx.AlberoMerkle([b"altra"] + foglie[1:n])
                self.assertFalse(sv.consistenza_regge(m, n, rad_m, b.radice(), b.consistenza(m)), (m, n, "rewritten"))
        for m, n in ((0, 3), (3, 3), (4, 3), (-1, 2)):
            self.assertFalse(sv.consistenza_regge(m, n, b"\x00" * 32, b"\x00" * 32, [b"\x00" * 32]))
        self.assertFalse(sv.consistenza_regge(1, 2, b"\x00" * 32, b"\x00" * 32, []))
        with self.assertRaises(sx.ExportError):
            sx.AlberoMerkle(foglie[:3]).consistenza(3)
        with self.assertRaises(sx.ExportError):
            sx.AlberoMerkle(foglie[:3]).consistenza(0)

    def _serie(self, versione=1, payload="chiaro", m=3, n=6, alg=sx.ALG_ED25519):
        F = {r: _firmatario(alg) for r in sx.RUOLI}
        righe = _righe_ops(n)
        opz = {} if versione == 1 else dict(versione=2, validita={r: ANNO for r in sx.RUOLI}, adesso=ADESSO)
        v = sx.esporta(righe[:m], nome="prova", formato="ops", issuer=F["issuer"], ts=F["ts"], politica=F["politica"],
                       iss_issuer="omega.issuer", iss_ts="omega.ts", payload=payload, **opz)
        dv = _cartella_di(self, v)
        kw = dict(nome="prova", formato="ops", payload=payload, issuer=F["issuer"], ts=F["ts"], politica=F["politica"],
                  iss_issuer="omega.issuer", iss_ts="omega.ts")
        if versione == 2:
            kw["adesso"] = ADESSO + 3600
        if versione == 2 and payload == "riservato":
            kw["sali_precedenti"] = v["sali"]
        e = sx.estendi(dv, righe, **kw)
        de = _cartella_di(self, e)
        arg = dict(alg_statement=alg, alg_receipt=alg, chiave_ts=(alg, F["ts"].pub),
                   chiave_politica=(alg, F["politica"].pub))
        return F, righe, v, dv, e, de, kw, arg

    def test_estensione_ok_in_ogni_modo(self):
        for versione, payload, alg in ((1, "chiaro", -19), (1, "riservato", -19), (2, "chiaro", -19),
                                       (2, "riservato", -19), (2, "riservato", -49)):
            F, righe, v, dv, e, de, kw, arg = self._serie(versione, payload, alg=alg)
            r = sv.verifica_consistenza(dv, de, **arg)
            self.assertTrue(r.ok, (versione, payload, r))
            self.assertEqual((r.campi["precedente"], r.campi["attuale"]), (4, 7))
            self.assertEqual(e["statements"][:4], [sx._foglia_da_file(t) for t in v["transparent"]])
            self.assertTrue(sv.verifica_cartella(de, **arg).ok)
            if e["sali"] is not None:
                self.assertEqual(e["sali"][:3], v["sali"])
                self.assertTrue(sv.verifica_cartella(de, righe=righe, sali=e["sali"], **arg).ok)
            # positive control of the verifier: old and new export swapped
            self.assertFalse(sv.verifica_consistenza(de, dv, **arg).ok)

    def _riscrivi(self, d, **campi):
        import json
        p = os.path.join(d, "consistenza.json")
        with open(p) as f:
            doc = json.load(f)
        doc.update(campi)
        with open(p, "wb") as f:
            f.write(sx.json_canonico(doc))
        return doc

    def _copia(self, d):
        c = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, c, True)
        shutil.rmtree(c)
        shutil.copytree(d, c)
        return c

    def test_prova_alterata_nel_file(self):
        F, righe, v, dv, e, de, kw, arg = self._serie(m=4, n=7)          # 5 -> 8 leaves: 4-node proof
        pr = e["consistenza"]["percorso"]
        self.assertEqual(len(pr), 4)
        for nome, campi, motivo in (
                ("truncated", dict(percorso=pr[:-1]), "consistenza_non_valida"),
                ("lengthened", dict(percorso=pr + ["0" * 64]), "consistenza_non_valida"),
                ("node changed", dict(percorso=["f" * 64] + pr[1:]), "consistenza_non_valida"),
                ("empty", dict(percorso=[]), "consistenza_fuori_forma"),
                ("65 nodes", dict(percorso=["0" * 64] * 65), "consistenza_fuori_forma"),
                ("uppercase", dict(percorso=[h.upper() for h in pr]), "consistenza_fuori_forma"),
                ("short node", dict(percorso=[pr[0][:-1]]), "consistenza_fuori_forma"),
                ("extra key", dict(nota=1), "consistenza_fuori_forma"),
                ("head extra", dict(precedente=dict(e["consistenza"]["precedente"], x=1)), "consistenza_fuori_forma"),
                ("tree_size zero", dict(precedente={"tree_size": 0, "radice": "0" * 64}), "consistenza_fuori_forma"),
                ("tree_size bool", dict(precedente={"tree_size": True, "radice": "0" * 64}), "consistenza_fuori_forma"),
                ("unknown profilo", dict(profilo="omega-scitt/9"), "consistenza_fuori_forma"),
                ("profilo of the other version", dict(profilo="omega-scitt/2"), "testa_non_firmata"),
                ("old root not signed", dict(precedente={"tree_size": 5, "radice": "0" * 64}),
                 "testa_non_firmata"),
                ("new root not signed", dict(attuale={"tree_size": 8, "radice": "0" * 64}), "testa_non_firmata"),
                ("old tree_size different", dict(precedente=dict(e["consistenza"]["precedente"], tree_size=4)),
                 "testa_non_firmata"),
                ("sub different", dict(sub="omega-ledger:altro"), "testa_non_firmata"),
                ("tree_size 1 (good shape, head not signed)", dict(precedente={"tree_size": 1, "radice": "0" * 64}),
                 "testa_non_firmata"),
                ("root with newline", dict(precedente=dict(e["consistenza"]["precedente"],
                                                           radice=e["consistenza"]["precedente"]["radice"] + "\n")),
                 "consistenza_fuori_forma"),
                ("percorso object", dict(percorso={h: 1 for h in pr}), "consistenza_fuori_forma"),
                ("percorso string", dict(percorso=pr[0]), "consistenza_fuori_forma"),
                ("64 nodes (good shape)", dict(percorso=["0" * 64] * 64), "consistenza_non_valida"),
                ("one node not hex", dict(percorso=pr[:-1] + ["zz"]), "consistenza_fuori_forma"),
                ("one node with newline", dict(percorso=pr[:-1] + [pr[-1] + "\n"]), "consistenza_fuori_forma")):
            c = self._copia(de)
            self._riscrivi(c, **campi)
            r = sv.verifica_consistenza(dv, c, **arg)
            self.assertEqual((r.ok, r.motivo), (False, motivo), nome)
        for contenuto in (b"", b"[1]", b'{"a":NaN}', b"\xff"):
            c = self._copia(de)
            with open(os.path.join(c, "consistenza.json"), "wb") as f:
                f.write(contenuto)
            r = sv.verifica_consistenza(dv, c, **arg)
            self.assertEqual((r.ok, r.motivo), (False, "consistenza_fuori_forma"), contenuto)
        c = self._copia(de)
        os.remove(os.path.join(c, "consistenza.json"))
        r = sv.verifica_consistenza(dv, c, **arg)
        self.assertEqual((r.ok, r.motivo), (False, "consistenza_fuori_forma"))

    def test_tree_size_che_non_cresce(self):
        F, righe, v, dv, e, de, kw, arg = self._serie(m=3, n=6)
        corta = sx.estendi(dv, righe[:5], **kw)                       # 4 -> 6 leaves
        dc = _cartella_di(self, corta)
        self.assertTrue(sv.verifica_consistenza(dv, dc, **arg).ok)
        # "the new" is shorter than "the old": file with the signed heads of the two exports
        c = self._copia(dc)
        self._riscrivi(c, precedente={"tree_size": e["tree_size"], "radice": e["radice"].hex()})
        r = sv.verifica_consistenza(de, c, **arg)
        self.assertEqual((r.ok, r.motivo), (False, "tree_size_non_cresce"))
        c = self._copia(de)
        self._riscrivi(c, precedente={"tree_size": e["tree_size"], "radice": e["radice"].hex()})
        r = sv.verifica_consistenza(de, c, **arg)
        self.assertEqual((r.ok, r.motivo), (False, "tree_size_non_cresce"))

    def test_passato_riscritto(self):
        F, righe, v, dv, e, de, kw, arg = self._serie(m=3, n=6)
        for quale in (0, 1, 2):                                       # every old line, the last one too (m-2)
            cambiate = _righe_ops(6)
            cambiate[quale]["data"]["n"] = 999                        # old line changed, chain recomputed
            prev = sx.GENESIS if quale == 0 else cambiate[quale - 1]["self_hash"]
            for r in cambiate[quale:]:
                r["prev_hash"] = prev
                r["self_hash"] = sx.hash_riga_ops(r)
                prev = r["self_hash"]
            self.assertIsNone(sx.verifica_catena(cambiate, "ops"))
            with self.assertRaises(sx.ExportError, msg=quale) as c:
                sx.estendi(dv, cambiate, **kw)
            self.assertIn("rewrites the past: line %d " % quale, str(c.exception))
        # "extension" built by skipping the check: export from scratch with the same keys (Ed25519: leaf 0 is
        # identical) and proof computed on its tree
        falso = sx.esporta(cambiate, nome="prova", formato="ops", issuer=F["issuer"], ts=F["ts"], politica=F["politica"],
                           iss_issuer="omega.issuer", iss_ts="omega.ts")
        falso["consistenza"] = {"profilo": "omega-scitt/1", "sub": falso["sub"],
                                "precedente": {"tree_size": 4, "radice": v["radice"].hex()},
                                "attuale": {"tree_size": 7, "radice": falso["radice"].hex()},
                                "percorso": [h.hex() for h in falso["albero"].consistenza(4)]}
        df = _cartella_di(self, falso)
        r = sv.verifica_consistenza(dv, df, **arg)
        self.assertEqual((r.ok, r.motivo), (False, "consistenza_non_valida"))
        # a real proof but of another ledger does not pass; the proof of the real extension does (positive control)
        self.assertTrue(sv.verifica_consistenza(dv, de, **arg).ok)

    def test_politica_diversa(self):
        F, righe, v, dv, e, de, kw, arg = self._serie(versione=2)
        # same ledger, same keys, export from scratch one hour later: leaf 0 (iat) changes
        altro = sx.esporta(righe, nome="prova", formato="ops", issuer=F["issuer"], ts=F["ts"], politica=F["politica"],
                           iss_issuer="omega.issuer", iss_ts="omega.ts", versione=2,
                           validita={r: ANNO for r in sx.RUOLI}, adesso=ADESSO + 3600)
        altro["consistenza"] = dict(e["consistenza"], attuale={"tree_size": 7, "radice": altro["radice"].hex()},
                                    percorso=[h.hex() for h in altro["albero"].consistenza(4)])
        r = sv.verifica_consistenza(dv, _cartella_di(self, altro), **arg)
        self.assertEqual((r.ok, r.motivo), (False, "politica_diversa"))

    def test_export_non_validi(self):
        F, righe, v, dv, e, de, kw, arg = self._serie()
        altra_ts = (-19, _firmatario(-19).pub)
        r = sv.verifica_consistenza(dv, de, **dict(arg, chiave_ts=altra_ts))
        self.assertEqual((r.ok, r.dettaglio[:7]), (False, "vecchia"))
        c = self._copia(de)
        os.remove(os.path.join(c, "ts_000005.cose"))
        r = sv.verifica_consistenza(dv, c, **arg)
        self.assertEqual((r.ok, r.dettaglio[:5]), (False, "nuova"))
        r = sv.verifica_consistenza(dv, de, **dict(arg, revocate_esterne=[F["issuer"].kid.hex()]))
        self.assertEqual((r.ok, r.motivo), (False, "chiave_revocata"))

    def test_guardie_di_estendi(self):
        F, righe, v, dv, e, de, kw, arg = self._serie(versione=2, payload="riservato")
        casi = (("no new lines", dict(), righe[:3]),
                ("shorter ledger", dict(), righe[:2]),
                ("payload different", dict(payload="chiaro", sali_precedenti=None), righe),
                ("formato different", dict(formato="ops_sha3"), righe),
                ("nome different", dict(nome="altro"), righe),
                ("nome out of shape", dict(nome="A"), righe),
                ("nome not a string", dict(nome=1), righe),
                ("unknown payload", dict(payload="misto"), righe),
                ("iss different", dict(iss_issuer="altro"), righe),
                ("iss ts different", dict(iss_ts="altro"), righe),
                ("issuer different", dict(issuer=_firmatario(-19)), righe),
                ("ts different", dict(ts=_firmatario(-19)), righe),
                ("politica different", dict(politica=_firmatario(-19)), righe),
                ("salts missing", dict(sali_precedenti=None), righe),
                ("fewer salts", dict(sali_precedenti=v["sali"][:2]), righe),
                ("wrong salt", dict(sali_precedenti=[bytes(32)] + v["sali"][1:]), righe),
                ("out of validity", dict(adesso=ANNO[1] + 1), righe),
                ("before validity", dict(adesso=ANNO[0] - 1), righe),
                ("adesso negative", dict(adesso=-1), righe),
                ("adesso not an integer", dict(adesso="1"), righe),
                ("adesso float", dict(adesso=float(ADESSO)), righe),
                ("broken chain", dict(), righe[:3] + [dict(righe[3], prev_hash="0" * 64)] + righe[4:]))
        for nome, cambi, rr in casi:
            with self.assertRaises(sx.ExportError, msg=nome):
                sx.estendi(dv, rr, **dict(kw, **cambi))
        self.assertTrue(sx.estendi(dv, righe, **kw)["consistenza"])                  # positive control
        # edges of validity: adesso = fino passes
        self.assertTrue(sx.estendi(dv, righe, **dict(kw, adesso=ANNO[1]))["consistenza"])
        self.assertTrue(sx.estendi(dv, righe, **dict(kw, adesso=ANNO[0]))["consistenza"])
        # a single new line is enough (m-1 old + 1)
        una = sx.estendi(dv, righe[:4], **kw)
        self.assertEqual((una["consistenza"]["precedente"]["tree_size"], una["tree_size"]), (4, 5))
        self.assertTrue(sv.verifica_consistenza(dv, _cartella_di(self, una), **arg).ok)
        # key among the revoked of the previous policy
        G = {r: _firmatario(-19) for r in sx.RUOLI}
        for ruolo in ("issuer", "ts"):
            pv = sx.esporta(righe[:2], nome="prova", formato="ops", issuer=G["issuer"], ts=G["ts"],
                            politica=G["politica"], iss_issuer="i", iss_ts="t", versione=2,
                            validita={r: ANNO for r in sx.RUOLI}, revocate=["0" * 32], adesso=ADESSO)
            from unittest import mock
            with mock.patch.object(sx, "_controlla_chiavi_v2", lambda *a: (ADESSO, [G[ruolo].kid.hex()])):
                pv = sx.esporta(righe[:2], nome="prova", formato="ops", issuer=G["issuer"], ts=G["ts"],
                                politica=G["politica"], iss_issuer="i", iss_ts="t", versione=2,
                                validita={r: ANNO for r in sx.RUOLI}, adesso=ADESSO)
            with self.assertRaises(sx.ExportError, msg=ruolo):
                sx.estendi(_cartella_di(self, pv), righe, nome="prova", formato="ops", payload="chiaro",
                           issuer=G["issuer"], ts=G["ts"], politica=G["politica"], iss_issuer="i", iss_ts="t",
                           adesso=ADESSO)
        # v1: sali and adesso do not exist
        F1, r1, v1, dv1, e1, de1, kw1, arg1 = self._serie()
        for cambi in (dict(sali_precedenti=[bytes(32)] * 3), dict(adesso=ADESSO)):
            with self.assertRaises(sx.ExportError, msg=cambi):
                sx.estendi(dv1, r1, **dict(kw1, **cambi))
        # previous folder not valid or missing
        with self.assertRaises(sx.ExportError):
            sx.estendi(os.path.join(dv1, "manca"), r1, **kw1)
        c = self._copia(dv1)
        os.remove(os.path.join(c, "ts_000001.cose"))
        with self.assertRaises(sx.ExportError):
            sx.estendi(c, r1, **kw1)

    def test_cli(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        righe = _righe_ops(6)
        reg3, reg6 = os.path.join(d, "r3.jsonl"), os.path.join(d, "r6.jsonl")
        for p, rr in ((reg3, righe[:3]), (reg6, righe)):
            with open(p, "wb") as f:
                for r in rr:
                    f.write(sx.json_canonico(r) + b"\n")
        k = []
        for n in "itp":
            p = os.path.join(d, n)
            fd = os.open(p, os.O_WRONLY | os.O_CREAT, 0o600)
            os.write(fd, ed25519.Ed25519PrivateKey.generate().private_bytes_raw().hex().encode())
            os.close(fd)
            k.append("file:" + p)
        chiavi = ["--chiave-issuer", k[0], "--chiave-ts", k[1], "--chiave-politica", k[2]]
        import datetime as dt
        oggi = dt.datetime.now(dt.timezone.utc)
        f = "%Y-%m-%dT%H:%M:%SZ"
        buona = (oggi - dt.timedelta(days=1)).strftime(f) + "/" + (oggi + dt.timedelta(days=300)).strftime(f)
        val = ["--validita-issuer", buona, "--validita-ts", buona, "--validita-politica", buona]
        v, e, s1, s2 = (os.path.join(d, x) for x in ("v", "e", "s1", "s2"))
        self.assertEqual(sx._main([reg3, v, "--nome", "r", "--payload", "riservato", "--sali", s1] + chiavi + val), 0)
        for extra in (["--versione", "2"], ["--effimere"], ["--revocata", "0" * 32], ["--validita-ts", buona],
                      ["--sali", os.path.join(e, "s")]):
            with self.assertRaises(SystemExit, msg=extra) as c:
                sx._main([reg6, e, "--nome", "r", "--payload", "riservato", "--estendi", v, "--sali-precedenti", s1]
                         + chiavi + extra)
            self.assertEqual(c.exception.code, 2)
        with self.assertRaises(SystemExit):
            sx._main([reg6, e, "--nome", "r", "--payload", "chiaro", "--effimere", "--sali-precedenti", s1])
        with self.assertRaises(SystemExit):
            sx._main([reg6, e, "--nome", "r", "--payload", "chiaro", "--estendi", v, "--chiave-ts", k[1]])
        # without --sali (needed): refusal and no folder
        self.assertEqual(sx._main([reg6, e, "--nome", "r", "--payload", "riservato", "--estendi", v,
                                   "--sali-precedenti", s1] + chiavi), 1)
        self.assertFalse(os.path.exists(e))
        self.assertEqual(sx._main([reg6, e, "--nome", "r", "--payload", "riservato", "--estendi", v,
                                   "--sali-precedenti", s1, "--sali", s2] + chiavi), 0)
        self.assertEqual(sx.leggi_sali(s2)[:3], sx.leggi_sali(s1))
        m = json_manifest(e)["chiavi_pubbliche_da_confrontare_fuori_banda"]
        pub = ["--ts-pub", m["ts"][1], "--politica-pub", m["politica"][1]]
        self.assertEqual(sv._main([e, "--alg", "-19", "--consistenza", v] + pub), 0)
        self.assertEqual(sv._main([e, "--alg", "-19", "--registro", reg6, "--sali", s2] + pub), 0)
        self.assertEqual(sv._main([v, "--alg", "-19", "--consistenza", e] + pub), 1)
        with self.assertRaises(SystemExit):
            sv._main([e, "--alg", "-19", "--consistenza", v, "--registro", reg6, "--sali", s2] + pub)
        # ledger not readable and previous salts out of shape: readable refusal
        self.assertEqual(sx._main([os.path.join(d, "manca"), os.path.join(d, "e2"), "--nome", "r", "--payload",
                                   "riservato", "--estendi", v, "--sali-precedenti", s1, "--sali",
                                   os.path.join(d, "s3")] + chiavi), 1)
        self.assertEqual(sx._main([reg6, os.path.join(d, "e3"), "--nome", "r", "--payload", "riservato", "--estendi",
                                   v, "--sali-precedenti", reg6, "--sali", os.path.join(d, "s4")] + chiavi), 1)
        # salts given for an export without commitments
        vc = os.path.join(d, "vc")
        self.assertEqual(sx._main([reg3, vc, "--nome", "r", "--payload", "chiaro"] + chiavi + val), 0)
        self.assertEqual(sx._main([reg6, os.path.join(d, "ec"), "--nome", "r", "--payload", "chiaro", "--estendi", vc,
                                   "--sali", os.path.join(d, "s5")] + chiavi), 1)
        self.assertEqual(sx._main([reg6, os.path.join(d, "ec2"), "--nome", "r", "--payload", "chiaro", "--estendi", vc]
                                  + chiavi), 0)


def _riforgia(b, doc, firm_righe=None):
    """review SCITT2: redoes the export /2 of b with the policy document doc (REALLY signed by b.P) and the lines
    signed by firm_righe; real TS receipts. So the refusal comes from the rule under test, not from the signatures."""
    f = firm_righe or b.ISS
    cwt = lambda iss: {1: iss, 2: b.es["sub"], 6: ADESSO}
    st = [sx._sign1(b.P, {1: b.alg, 3: sx.CTY_POLITICA, 4: b.P.kid, 15: cwt("omega.ts")}, sx.json_canonico(doc), True, {})]
    for s in b.es["statements"][1:]:
        st.append(sx._sign1(f, {1: b.alg, 3: sx.CTY_RIGA_OPS, 4: f.kid, 15: cwt("omega.issuer")},
                            cbor.loads(s).value[2], True, {}))
    alb = sx.AlberoMerkle(st)
    rad = alb.radice()
    tr = [sx.aggiungi_receipt(s, sx.receipt(b.T, "omega.ts", b.es["sub"], rad, alb.n, i, alb.percorso(i), ADESSO))
          for i, s in enumerate(st)]
    return dict(b.es, statements=st, transparent=tr, radice=rad, tree_size=alb.n, politica=doc)


class TestRevisioneScitt2(unittest.TestCase):
    """review SCITT2 (08/11 evening): P1 one key per role in policy /2; P2 new CLI output; P3 repeated salts."""

    def test_p1_stessa_chiave_in_due_ruoli(self):
        import copy
        b = _v2()
        d = copy.deepcopy(b.es["politica"])
        d["ts"]["valida_fino"] = d["ts"]["valida_dal"] + 10                 # TS: 10 seconds, iat outside
        e = sv.verifica_cartella(_cartella_di(self, _riforgia(b, d)), **_arg_cartella(b))
        self.assertEqual((e.ok, e.motivo), (False, "chiave_fuori_validita"))  # control: the TS window bites
        d["ancore"][0].update(kid=b.T.kid.hex(), pub=b.T.pub.hex())          # anchor = TS key, one-year window
        e = sv.verifica_cartella(_cartella_di(self, _riforgia(b, d, firm_righe=b.T)), **_arg_cartella(b))
        self.assertEqual((e.ok, e.motivo), (False, "politica_fuori_profilo"))
        d = copy.deepcopy(b.es["politica"])
        d["ancore"][0].update(kid=b.P.kid.hex(), pub=b.P.pub.hex())          # anchor = policy key
        e = sv.verifica_cartella(_cartella_di(self, _riforgia(b, d, firm_righe=b.P)), **_arg_cartella(b))
        self.assertEqual((e.ok, e.motivo), (False, "politica_fuori_profilo"))
        d = copy.deepcopy(b.es["politica"])
        d["ancore"].append(dict(d["ancore"][0]))                              # two anchors with the same kid
        e = sv.verifica_cartella(_cartella_di(self, _riforgia(b, d)), **_arg_cartella(b))
        self.assertEqual((e.ok, e.motivo), (False, "politica_fuori_profilo"))
        e = sv.verifica_cartella(_cartella_di(self, _riforgia(b, copy.deepcopy(b.es["politica"]))), **_arg_cartella(b))
        self.assertTrue(e.ok, e)                                              # positive control of the forger
        d = copy.deepcopy(b.es["politica"])                                   # TS key = policy key
        d["ts"]["kid"] = b.P.kid.hex()
        b.T = b.P
        e = sv.verifica_cartella(_cartella_di(self, _riforgia(b, d)), **_arg_cartella(b))
        self.assertEqual((e.ok, e.motivo), (False, "politica_fuori_profilo"))

    def test_p2_uscita_esistente_rifiutata(self):
        import io
        from contextlib import redirect_stdout
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        reg, reg5 = os.path.join(d, "r.jsonl"), os.path.join(d, "r5.jsonl")
        for p, n in ((reg, 8), (reg5, 5)):
            with open(p, "w") as f:
                for r in _righe_ops(n):
                    f.write(sx.json_canonico(r).decode() + "\n")
        def cli(argv):
            with redirect_stdout(io.StringIO()):
                return sx._main(argv)

        def leggi(c):
            out = {}
            for n in os.listdir(c):
                with open(os.path.join(c, n), "rb") as f:
                    out[n] = f.read()
            return out
        u = os.path.join(d, "u")
        self.assertEqual(cli([reg, u, "--nome", "r", "--payload", "chiaro", "--effimere"]), 0)
        prima = leggi(u)
        self.assertEqual(cli([reg5, u, "--nome", "r", "--payload", "chiaro", "--effimere"]), 1)
        s = os.path.join(d, "sali")
        self.assertEqual(cli([reg5, u, "--nome", "r", "--payload", "riservato", "--effimere", "--sali", s]), 1)
        self.assertFalse(os.path.exists(s))                                   # no salts written for a refused export
        self.assertEqual(leggi(u), prima)
        k = []
        for n in "itp":
            p = os.path.join(d, n)
            fd = os.open(p, os.O_WRONLY | os.O_CREAT, 0o600)
            os.write(fd, ed25519.Ed25519PrivateKey.generate().private_bytes_raw().hex().encode())
            os.close(fd)
            k.append("file:" + p)
        ch = ["--chiave-issuer", k[0], "--chiave-ts", k[1], "--chiave-politica", k[2]]
        import datetime as dt
        oggi = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        f_ = "%Y-%m-%dT%H:%M:%SZ"
        buona = (oggi - dt.timedelta(days=1)).strftime(f_) + "/" + (oggi + dt.timedelta(days=300)).strftime(f_)
        v = os.path.join(d, "v")
        self.assertEqual(cli([reg5, v, "--nome", "r", "--payload", "chiaro"] + ch + ["--validita-issuer", buona,
                              "--validita-ts", buona, "--validita-politica", buona]), 0)
        pv = leggi(v)
        self.assertEqual(cli([reg, v, "--nome", "r", "--payload", "chiaro", "--estendi", v] + ch), 1)   # in place
        self.assertEqual(leggi(v), pv)
        self.assertEqual(cli([reg, os.path.join(d, "e"), "--nome", "r", "--payload", "chiaro", "--estendi", v] + ch), 0)
        self.assertEqual(cli([reg5, os.path.join(reg5, "sotto"), "--nome", "r", "--payload", "chiaro", "--effimere"]), 1)

    def test_p2_due_estensioni_concorrenti_stessa_uscita(self):
        import subprocess
        b = Banco(n=1)
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        es = sx.esporta(_righe_ops(3), nome="r", formato="ops", issuer=b.ISS, ts=b.T, politica=b.P, iss_issuer="i",
                        iss_ts="t", payload="chiaro")
        u = os.path.join(d, "u")
        codice = ("import sys,threading; sys.path[:0]=[%r,%r]; from pq_scitt.scitt import export as sx\n"
                  "b=threading.Barrier(2); r=[]\n"
                  "def f():\n b.wait()\n try:\n  sx._crea_uscita(%r); r.append(0)\n except sx.ExportError: r.append(1)\n"
                  "t=[threading.Thread(target=f) for _ in range(2)]; [x.start() for x in t]; [x.join() for x in t]\n"
                  "print(sorted(r))") % (RADICE, os.path.join(RADICE, "chain"), u)
        out = subprocess.run([sys.executable, "-c", codice], capture_output=True, text=True, timeout=60).stdout.strip()
        self.assertEqual(out, "[0, 1]")                                       # only one creates the output
        self.assertTrue(es["tree_size"] == 4)

    def test_p4_file_dei_sali_regolare(self):
        import subprocess
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        fifo = os.path.join(d, "fifo")
        os.mkfifo(fifo)
        codice = ("import sys; sys.path[:0]=[%r,%r]; from pq_scitt.scitt import export as sx\n"
                  "try:\n sx.leggi_sali(%r)\nexcept sx.ExportError as e: print('REFUSED', e)") % (
                      RADICE, os.path.join(RADICE, "chain"), fifo)
        r = subprocess.run([sys.executable, "-c", codice], capture_output=True, text=True, timeout=60)
        self.assertIn("not a regular file", r.stdout)
        aperti = len(os.listdir("/proc/self/fd")) if os.path.isdir("/proc/self/fd") else None
        for cattivo in (d, os.path.join(d, "manca")):
            with self.assertRaises(sx.ExportError):
                sx.leggi_sali(cattivo)
        if aperti is not None:
            self.assertEqual(len(os.listdir("/proc/self/fd")), aperti)      # no descriptor left open
        buono = os.path.join(d, "s")
        sx.scrivi_sali([bytes(range(32)), bytes(32)], buono)
        self.assertEqual(sx.leggi_sali(buono), [bytes(range(32)), bytes(32)])     # positive control

    def test_cli_dice_sali_solo_se_usati(self):
        import io
        from contextlib import redirect_stdout
        righe = _righe_ops(3)
        b = _v2(righe=righe, payload="riservato")
        d = _cartella_di(self, b.es)
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        reg, sali = os.path.join(t, "r.jsonl"), os.path.join(t, "s")
        with open(reg, "w") as f:
            for r in righe:
                f.write(sx.json_canonico(r).decode() + "\n")
        sx.scrivi_sali(b.es["sali"], sali)
        base = [d, "--alg", "-19", "--ts-pub", b.T.pub.hex(), "--politica-pub", b.P.pub.hex()]
        for extra, atteso in (([], False), (["--registro", reg, "--sali", sali], True)):
            o = io.StringIO()
            with redirect_stdout(o):
                self.assertEqual(sv._main(base + extra), 0)
            self.assertEqual("verified with the salts" in o.getvalue(), atteso, extra)

    def test_uri_awskms_mldsa65_chiuso_prima_del_backend(self):
        """bacb08a7: unknown/duplicate/empty key and mu outside the list = refused BEFORE building the backend (no network)."""
        import types
        vero = sx._cryptovalid_kms()
        costruiti = []

        def backend(**kw):
            costruiti.append(kw)
            raise RuntimeError("backend built")
        finto = types.SimpleNamespace(_parse_kv=vero._parse_kv, _ALLOWED_KEYS=vero._ALLOWED_KEYS,
                                      AwsKmsMlDsaBackend=backend)
        for resto in ("key_id=x;mu=boh", "key_id=x;mu=External", "key_id=x;pim=1", "key_id=x;key_id=y", "key_id=",
                      "key_id=x;", "region=eu-central-1", "key_id=x;endpoint=http://h"):
            with self.assertRaises((sx.ExportError, ValueError), msg=resto):
                sx._firmatario_kms(finto, "awskms-mldsa65", resto, "awskms-mldsa65:" + resto, sx.ALG_MLDSA65)
        self.assertEqual(costruiti, [])
        for resto, mu in (("key_id=x", False), ("key_id=x;mu=raw", False), ("key_id=x;mu=external", True)):
            with self.assertRaises(RuntimeError):                                  # positive control: backend reached
                sx._firmatario_kms(finto, "awskms-mldsa65", resto, "awskms-mldsa65:" + resto, sx.ALG_MLDSA65)
            self.assertEqual(costruiti[-1]["external_mu"], mu)

    def test_estendi_su_export_con_nomi_diversi(self):
        """The verifier accepts .cose files with any names; estendi reads by name: readable refusal, no crash."""
        b = _v2(righe=_righe_ops(3))
        d = _cartella_di(self, b.es)
        for n in sorted(os.listdir(d)):
            if n.endswith(".cose"):
                os.rename(os.path.join(d, n), os.path.join(d, "x" + n))
        self.assertTrue(sv.verifica_cartella(d, **_arg_cartella(b)).ok)
        with self.assertRaises(sx.ExportError):
            sx.estendi(d, _righe_ops(5), nome="prova", formato="ops", payload="chiaro", issuer=b.ISS, ts=b.T,
                       politica=b.P, iss_issuer="omega.issuer", iss_ts="omega.ts", adesso=ADESSO)

    def test_consistenza_con_nomi_diversi(self):
        """verifica_consistenza rereads leaf 0 by name: renamed files = refusal with a reason, never an exception."""
        righe = _righe_ops(5)
        b = _v2(righe=righe[:3])
        dv = _cartella_di(self, b.es)
        e = sx.estendi(dv, righe, nome="prova", formato="ops", payload="chiaro", issuer=b.ISS, ts=b.T, politica=b.P,
                       iss_issuer="omega.issuer", iss_ts="omega.ts", adesso=ADESSO)
        de = _cartella_di(self, e)
        self.assertTrue(sv.verifica_consistenza(dv, de, **_arg_cartella(b)).ok)        # positive control
        for c in (dv, de):
            for n in os.listdir(c):
                if n.endswith(".cose"):
                    os.rename(os.path.join(c, n), os.path.join(c, "x" + n))
        r = sv.verifica_consistenza(dv, de, **_arg_cartella(b))
        self.assertFalse(r.ok)
        self.assertIn(r.motivo, sv.MOTIVI)

    def test_effimere_valgono_365_giorni(self):
        import io
        from contextlib import redirect_stdout
        t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, t, True)
        reg, u = os.path.join(t, "r.jsonl"), os.path.join(t, "u")
        with open(reg, "w") as f:
            for r in _righe_ops(2):
                f.write(sx.json_canonico(r).decode() + "\n")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(sx._main([reg, u, "--nome", "r", "--payload", "chiaro", "--effimere"]), 0)
        with open(os.path.join(u, "manifest.json"), "rb") as f:
            pol = strict_json.loads_object(f.read())["politica"]
        for v in (pol["ancore"][0], pol["ts"], pol["politica"]):
            self.assertEqual(v["valida_fino"] - v["valida_dal"], 365 * 86400)

    def test_consistenza_regge_accetta_tuple(self):
        """Public function: the path may arrive as a tuple (m power of 2 = radice_m at the head)."""
        foglie = [bytes([i]) for i in range(7)]
        a = sx.AlberoMerkle(foglie)
        for m in (1, 2, 3, 4):
            rm = sx.AlberoMerkle(foglie[:m]).radice()
            self.assertTrue(sv.consistenza_regge(m, 7, rm, a.radice(), tuple(a.consistenza(m))), m)

    def test_p3_sali_ripetuti(self):
        from unittest import mock
        righe = _righe_ops(4)
        with mock.patch.object(sx.secrets, "token_bytes", lambda n: b"\x07" * n):
            b = _v2(righe=righe, payload="riservato")
        d = _cartella_di(self, b.es)
        self.assertTrue(sv.verifica_cartella(d, **_arg_cartella(b)).ok)       # not seen without salts
        e = sv.verifica_cartella(d, righe=righe, sali=b.es["sali"], **_arg_cartella(b))
        self.assertEqual((e.ok, e.motivo, e.dettaglio), (False, "impegno_non_valido", "repeated salts"))
        for r_, s_ in ((righe, iter(b.es["sali"])), (iter(righe), b.es["sali"]), (righe, {x: 1 for x in b.es["sali"]})):
            e = sv.verifica_cartella(d, righe=r_, sali=s_, **_arg_cartella(b))   # only lists/tuples, one per type
            self.assertEqual((e.ok, e.motivo), (False, "impegno_non_valido"))
        b2 = _v2(righe=righe, payload="riservato")
        self.assertTrue(sv.verifica_cartella(_cartella_di(self, b2.es), righe=righe, sali=b2.es["sali"],
                                             **_arg_cartella(b2)).ok)         # positive control


if __name__ == "__main__":
    unittest.main()
