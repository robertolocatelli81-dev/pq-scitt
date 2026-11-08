"""Regression O3 (08/11/2026): SLH-DSA anchors of pq_scitt/anchors/slh_dsa.py conform to FIPS 205 "pure".

Defects measured on the original code a92c7ecd:
  1. backend 'slhdsa' signed with the Bare interface of the slh-dsa library (= slh_sign_internal, initial
     draft): it passes the ACVP "internal" group and fails "external/pure" → new anchors are v2 = pure;
  2. 'auto' chose 'oqs' if `import oqs` succeeded, even with the PyPI package of the same name (Open Quick Script)
     or with the mechanism not enabled in the liboqs build → AttributeError at keygen.
Already signed v1 anchors stay verifiable (legacy). The tests with signatures need `slh-dsa`; those on backend
selection run everywhere. To skip nothing, `slh-dsa` and `liboqs-python` are needed.
"""
import importlib.util
import json
import os
import sys
import types
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load():
    spec = importlib.util.spec_from_file_location("anchor_slhdsa_t", importlib.util.find_spec("pq_scitt.anchors.slh_dsa").origin)
    m = importlib.util.module_from_spec(spec)
    sys.modules["anchor_slhdsa_t"] = m
    spec.loader.exec_module(m)
    return m


A = _load()
try:
    import slhdsa
    import slhdsa.parameters as P
    HAVE_SLH = True
except Exception:
    HAVE_SLH = False
try:
    import oqs as _oqs
    HAVE_OQS_128F = callable(getattr(_oqs, "get_enabled_sig_mechanisms", None)) and \
        "SLH_DSA_PURE_SHA2_128F" in _oqs.get_enabled_sig_mechanisms()
except Exception:
    HAVE_OQS_128F = False

FIX = json.load(open(os.path.join(ROOT, "tests", "data", "acvp_slhdsa_sha2_128f.json"), encoding="utf-8"))["casi"]


class TestSceltaBackend(unittest.TestCase):
    def test_oqs_omonimo_non_scelto(self):
        finto = types.ModuleType("oqs")            # like PyPI `oqs` 0.10.2: no Signature
        with mock.patch.dict(sys.modules, {"oqs": finto}):
            self.assertFalse(A._oqs_available())
            self.assertEqual(A._resolve_backend("auto"), "slhdsa")
            with self.assertRaises(RuntimeError):
                A._resolve_backend("oqs")

    def test_meccanismo_non_abilitato_non_scelto(self):
        finto = types.ModuleType("oqs")
        finto.Signature = object
        finto.get_enabled_sig_mechanisms = lambda: ["SLH_DSA_PURE_SHA2_128F"]
        with mock.patch.dict(sys.modules, {"oqs": finto}):
            self.assertEqual(A._resolve_backend("auto", "sha2_128f"), "oqs")       # positive control
            self.assertEqual(A._resolve_backend("auto", "sha2_256f"), "slhdsa")
            with self.assertRaises(RuntimeError):
                A._resolve_backend("oqs", "sha2_256f")

    def test_parametro_ignoto_rifiutato(self):
        with self.assertRaises(ValueError):
            A.AnchorKey.generate("sha2_999f", "slhdsa")


@unittest.skipUnless(HAVE_SLH, "slh-dsa not installed")
class TestFips205Pure(unittest.TestCase):
    def _ak(self, c):
        return A.AnchorKey.from_secret({"backend": "slhdsa", "param": "sha2_128f",
                                        "keypair_digest_hex": c["pk"] + c["sk"], "pub_hex": c["pk"]})

    def test_firma_identica_al_vettore_acvp_pure(self):
        c = FIX["1/7"]                               # external/pure, empty ctx, deterministic
        self.assertEqual(c["context"], "")
        self.assertEqual(self._ak(c).sign(bytes.fromhex(c["message"])), bytes.fromhex(c["signature"]))

    def test_verifica_pure_acvp_e_bare_rifiutata(self):
        c = FIX["1/7"]
        msg, sig = bytes.fromhex(c["message"]), bytes.fromhex(c["signature"])
        self.assertTrue(A._verify_raw("slhdsa", "sha2_128f", c["pk"], msg, sig))
        self.assertFalse(A._verify_raw("slhdsa", "sha2_128f", c["pk"], msg, sig, legacy_bare=True))
        self.assertFalse(A._verify_raw("slhdsa", "sha2_128f", c["pk"], msg + b"\x00", sig))

    def test_interna_solo_come_legacy(self):
        c = FIX["13/115"]                            # internal (= Bare interface of the library)
        msg, sig = bytes.fromhex(c["message"]), bytes.fromhex(c["signature"])
        self.assertTrue(A._verify_raw("slhdsa", "sha2_128f", c["pk"], msg, sig, legacy_bare=True))
        self.assertFalse(A._verify_raw("slhdsa", "sha2_128f", c["pk"], msg, sig))
        self.assertFalse(A._verify_raw("oqs", "sha2_128f", c["pk"], msg, sig, legacy_bare=True))

    def _v1(self, kp, with_backend, bare=True):
        root, ts = "ab" * 32, 1762600000.25
        body = A._canonical_body(A.SCHEMA_V1, "sha2_128f", root, ts)
        sig = kp.sign(body) if bare else kp.sign_pure(body)
        d = {"schema": A.SCHEMA_V1, "param": "sha2_128f", "root": root, "ts": ts, "sig": sig.hex(),
             "pub": kp.pub.digest().hex()}
        if with_backend:
            d["backend"] = "slhdsa"
        return d

    def test_ancore_v1_gia_firmate_restano_valide(self):
        kp = slhdsa.KeyPair.gen(P.sha2_128f)
        self.assertTrue(A.verify_anchor(self._v1(kp, True)))
        self.assertTrue(A.verify_anchor(self._v1(kp, False)))        # v1 without backend field
        self.assertFalse(A.verify_anchor(self._v1(kp, True, bare=False)))
        self.assertFalse(A.verify_anchor({**self._v1(kp, True), "x": 1}))

    def test_nuove_ancore_v2_pure_e_formato_chiuso(self):
        ak = A.AnchorKey.generate("sha2_128f", "slhdsa")
        an = A.create_anchor("cd" * 32, ak)
        self.assertEqual(an["schema"], A.SCHEMA)
        self.assertEqual(set(an), set(A._KEYS_V2))
        body = A._canonical_body(A.SCHEMA, an["param"], an["root"], an["ts"])
        pub = slhdsa.PublicKey.from_digest(bytes.fromhex(an["pub"]), P.sha2_128f)
        self.assertTrue(pub.verify_pure(body, bytes.fromhex(an["sig"])))      # FIPS 205 pure, empty ctx
        self.assertFalse(pub.verify(body, bytes.fromhex(an["sig"])))          # no longer Bare
        self.assertTrue(A.verify_anchor(an))                                  # positive control
        for bad in ({**an, "extra": 0}, {k: v for k, v in an.items() if k != "backend"},
                    {**an, "schema": "omega-slhdsa-anchor-v3"}, {**an, "param": "sha2_999f"},
                    {**an, "ts": True}, {**an, "ts": float("nan")}, {**an, "backend": "altro"},
                    {**an, "schema": A.SCHEMA_V1}, {**an, "root": ""}):
            self.assertFalse(A.verify_anchor(bad), sorted(set(bad) ^ set(an)) or bad.get("schema"))


@unittest.skipUnless(HAVE_SLH and HAVE_OQS_128F, "needs slh-dsa and liboqs-python with SLH_DSA_PURE_SHA2_128F")
class TestInteroperabilitaV2(unittest.TestCase):
    def test_ancora_di_un_backend_verifica_con_l_altro(self):
        for be, other in (("slhdsa", "oqs"), ("oqs", "slhdsa")):
            an = A.create_anchor("ef" * 32, A.AnchorKey.generate("sha2_128f", be))
            body = A._canonical_body(A.SCHEMA, an["param"], an["root"], an["ts"])
            self.assertTrue(A._verify_raw(other, "sha2_128f", an["pub"], body, bytes.fromhex(an["sig"])), be)


class _ImportOqsEsce:
    """Finder that simulates liboqs-python without liboqs: `import oqs` ends with SystemExit (measured 08/11)."""
    def find_spec(self, name, path=None, target=None):
        if name == "oqs":
            raise SystemExit("Could not load liboqs shared library")
        return None


class TestRevisioneO3(unittest.TestCase):
    """Cases added by the 08/11/2026 review: each one kills a surviving mutant or covers a finding."""

    def test_oqs_finti_parziali(self):
        def finto(**attr):
            m = types.ModuleType("oqs")
            for k, v in attr.items():
                setattr(m, k, v)
            return m

        def esplode():
            raise RuntimeError("x")
        solo_enabled = finto(get_enabled_sig_mechanisms=lambda: ["SLH_DSA_PURE_SHA2_128F"])
        solo_sig = finto(Signature=object)
        rotto = finto(Signature=object, get_enabled_sig_mechanisms=esplode)
        completo = finto(Signature=object, get_enabled_sig_mechanisms=lambda: [])
        for mod, param, atteso in ((solo_enabled, "sha2_128f", False), (solo_sig, None, False),
                                   (rotto, "sha2_128f", False), (completo, None, True)):
            with mock.patch.dict(sys.modules, {"oqs": mod}):
                self.assertIs(A._oqs_available(param), atteso, (sorted(vars(mod)), param))

    def test_import_oqs_che_esce_non_uccide_il_verificatore(self):
        sys.modules.pop("oqs", None)
        finder = _ImportOqsEsce()
        sys.meta_path.insert(0, finder)
        try:
            with mock.patch.dict(sys.modules):
                sys.modules.pop("oqs", None)
                self.assertFalse(A._oqs_available("sha2_128f"))
                if HAVE_SLH:
                    an = A.create_anchor("ab" * 32, A.AnchorKey.generate("sha2_128f", "slhdsa"))
                    self.assertTrue(A.verify_anchor(an))
                    self.assertTrue(A.verify_anchor({**an, "backend": "oqs"}))   # fallback to slhdsa (v2: same sigs)
        finally:
            sys.meta_path.remove(finder)

    @unittest.skipUnless(HAVE_SLH, "slh-dsa not installed")
    def test_verifica_slhdsa_non_tocca_oqs(self):
        an = A.create_anchor("ab" * 32, A.AnchorKey.generate("sha2_128f", "slhdsa"))
        with mock.patch.object(A, "_oqs_available", side_effect=AssertionError("oqs touched")):
            self.assertTrue(A.verify_anchor(an))

    @unittest.skipUnless(HAVE_SLH, "slh-dsa not installed")
    def test_v1_oqs_e_pure_non_bare(self):
        kp = slhdsa.KeyPair.gen(P.sha2_128f)
        root, ts = "ab" * 32, 1762600000.25
        body = A._canonical_body(A.SCHEMA_V1, "sha2_128f", root, ts)
        base = {"schema": A.SCHEMA_V1, "backend": "oqs", "param": "sha2_128f", "root": root, "ts": ts,
                "pub": kp.pub.digest().hex()}
        self.assertTrue(A.verify_anchor({**base, "sig": kp.sign_pure(body).hex()}))
        self.assertFalse(A.verify_anchor({**base, "sig": kp.sign(body).hex()}))

    @unittest.skipUnless(HAVE_SLH, "slh-dsa not installed")
    def test_valori_strani_firmati_davvero_rifiutati(self):
        kp = slhdsa.KeyPair.gen(P.sha2_128f)
        for root, ts in ((5, 1.5), ("", 1.5), ("ab", True), ("ab", None), ("ab", "1"),
                         ("ab", float("nan")), ("ab", float("inf"))):
            body = A._canonical_body(A.SCHEMA, "sha2_128f", root, ts)
            an = {"schema": A.SCHEMA, "backend": "slhdsa", "param": "sha2_128f", "root": root, "ts": ts,
                  "sig": kp.sign_pure(body).hex(), "pub": kp.pub.digest().hex()}
            self.assertFalse(A.verify_anchor(an), (root, ts))
        body = A._canonical_body(A.SCHEMA, "sha2_128f", "ab", 1.5)                # positive control
        self.assertTrue(A.verify_anchor({"schema": A.SCHEMA, "backend": "slhdsa", "param": "sha2_128f", "root": "ab",
                                         "ts": 1.5, "sig": kp.sign_pure(body).hex(), "pub": kp.pub.digest().hex()}))

    @unittest.skipUnless(HAVE_SLH, "slh-dsa not installed")
    def test_pin_codifica_e_pub_incastonata(self):
        ak = A.AnchorKey.generate("sha2_128f", "slhdsa")
        an = A.create_anchor("ab" * 32, ak)
        altra = A.AnchorKey.generate("sha2_128f", "slhdsa").pub_bytes().hex()
        self.assertTrue(A.verify_anchor(an, ak.pub_bytes()))
        self.assertTrue(A.verify_anchor(an, ak.pub_bytes().hex().upper()))       # the pin is normalised
        self.assertTrue(A.verify_anchor(an, ak))
        self.assertFalse(A.verify_anchor({**an, "pub": altra}, ak.pub_bytes()))   # pin != embedded pub
        self.assertFalse(A.verify_anchor({**an, "pub": "zz"}, ak.pub_bytes()))
        self.assertFalse(A.verify_anchor({**an, "pub": 5}, ak.pub_bytes()))
        self.assertFalse(A.verify_anchor(an, memoryview(ak.pub_bytes())))         # pin of unknown type
        self.assertFalse(A.verify_anchor(an, slhdsa.PublicKey.from_digest(ak.pub_bytes(), P.sha2_128f)))
        for k in ("sig", "pub"):
            self.assertFalse(A.verify_anchor({**an, k: an[k].upper()}), k)
            self.assertFalse(A.verify_anchor({**an, k: " " + an[k]}), k)
            self.assertFalse(A.verify_anchor({**an, k: an[k][:4] + "\n" + an[k][4:]}), k)

    @unittest.skipUnless(HAVE_SLH, "slh-dsa not installed")
    def test_create_anchor_parametro_ignoto_o_diverso(self):
        kp = slhdsa.KeyPair.gen(P.sha2_128f)
        with self.assertRaises(ValueError):
            A.create_anchor("ab" * 32, kp, param_name="sha2_999f")
        ak = A.AnchorKey.generate("sha2_128f", "slhdsa")
        with self.assertRaises(ValueError):
            A.create_anchor("ab" * 32, ak, param_name="sha2_128s")
        self.assertTrue(A.verify_anchor(A.create_anchor("ab" * 32, ak, param_name="sha2_128f")))


if __name__ == "__main__":
    unittest.main()
