"""Ed25519 against Wycheproof (C2SP/wycheproof, testvectors_v1/ed25519_test.json, Apache-2.0, see NOTICE).

Accepted = pq_scitt.ed25519_keys.signature_problem() finds nothing AND the `cryptography` library verifies the signature.
Expected: every «valid» case accepted, every «invalid» case refused. The 29 «acceptable» cases (keys of small or mixed
order) are refused here by design; the positive control shows that the library alone accepts them, so it is the key
check that refuses them, not the library.
"""
import hashlib
import json
import os
import unittest
from collections import Counter

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from pq_scitt import ed25519_keys

DATI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "wycheproof_ed25519_test.json")
SHA256 = "ea80ffebac085e21cb9d3e903e7fa2b448d96702da5b31f061d0b83b430b74b3"


def _libreria(pk, sig, msg):
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


def _casi():
    with open(DATI, "rb") as f:
        grezzo = f.read()
    d = json.loads(grezzo)
    for g in d["testGroups"]:
        pk = bytes.fromhex(g["publicKey"]["pk"])
        for t in g["tests"]:
            yield t, pk, bytes.fromhex(t["sig"]), bytes.fromhex(t["msg"])


class TestWycheproofEd25519(unittest.TestCase):
    def test_file(self):
        with open(DATI, "rb") as f:
            grezzo = f.read()
        self.assertEqual(hashlib.sha256(grezzo).hexdigest(), SHA256)
        d = json.loads(grezzo)
        self.assertEqual(d["algorithm"], "EDDSA")
        self.assertEqual(d["numberOfTests"], 210)
        self.assertEqual(sum(1 for _ in _casi()), 210)

    def test_esiti(self):
        esiti = Counter()
        for t, pk, sig, msg in _casi():
            accettato = ed25519_keys.signature_problem(pk, sig) is None and _libreria(pk, sig, msg)
            esiti[(t["result"], accettato)] += 1
            if t["result"] == "valid":
                self.assertTrue(accettato, "tcId %d" % t["tcId"])
            else:
                self.assertFalse(accettato, "tcId %d %s" % (t["tcId"], t["result"]))
        self.assertEqual(esiti, Counter({("valid", True): 117, ("invalid", False): 64, ("acceptable", False): 29}))

    def test_controllo_positivo_la_libreria_da_sola_accetta_gli_acceptable(self):
        n = sum(1 for t, pk, sig, msg in _casi() if t["result"] == "acceptable" and _libreria(pk, sig, msg))
        self.assertEqual(n, 29)


if __name__ == "__main__":
    unittest.main()
