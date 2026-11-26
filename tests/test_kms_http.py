#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pq-scitt — tests for the stdlib-only AWS KMS backend (awskms-http).

SPDX-License-Identifier: Apache-2.0
Copyright (C) 2026 Roberto Locatelli

Self-contained (no external deps, no credentials): validates the SigV4 signing-key
against AWS's official test vector and the URI/honesty behaviour. The live round-trip
against real AWS KMS is exercised separately (needs an account + credentials).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pq_scitt import kms as k  # noqa: E402


class TestSigV4Vector(unittest.TestCase):
    def test_signing_key_matches_official_aws_vector(self):
        got = k._sigv4_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830", "us-east-1", "iam").hex()
        self.assertEqual(
            got, "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9")


class TestUriAndHonesty(unittest.TestCase):
    def test_requires_key_id_and_region(self):
        with self.assertRaises(ValueError):
            k.backend_from_uri("awskms-http:key_id=abc")            # region missing
        with self.assertRaises(ValueError):
            k.backend_from_uri("awskms-http:region=eu-north-1")     # key_id missing

    def test_honest_without_credentials(self):
        saved = {kk: os.environ.pop(kk, None)
                 for kk in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")}
        try:
            with self.assertRaises(RuntimeError):
                k.backend_from_uri("awskms-http:key_id=abc;region=eu-north-1")
        finally:
            for kk, v in saved.items():
                if v is not None:
                    os.environ[kk] = v

    def test_legacy_awskms_backend_untouched(self):
        # the pre-existing boto3 backend stays available (nothing removed)
        self.assertTrue(hasattr(k, "AwsKmsBackend"))
        self.assertTrue(hasattr(k, "AwsKmsHttpBackend"))


class TestNetHsmRispostaMalformata(unittest.TestCase):
    def test_risposta_senza_chiave_o_firma(self):
        """A NetHSM answer without public.data / signature was a KeyError traceback: now a RuntimeError, like Vault."""
        import io
        from unittest import mock
        os.environ["NETHSM_PASS_T"] = "x"
        self.addCleanup(os.environ.pop, "NETHSM_PASS_T", None)
        b = k.NetHsmBackend(url="https://127.0.0.1:1", key="k", user="u", pass_env="NETHSM_PASS_T")
        for corpo in (b"{}", b'{"public": 5}', b'{"signature": 7}', b"[]"):
            risposta = mock.MagicMock()
            risposta.__enter__.return_value = io.BytesIO(corpo)
            with mock.patch("pq_scitt.kms._apri", return_value=risposta):
                for f in (b.public_key_hex, lambda: b.sign(b"m")):
                    with self.assertRaises(RuntimeError, msg=corpo):
                        f()

class TestEcPointEd25519(unittest.TestCase):
    def test_due_codifiche_e_rifiuti(self):
        """CKA_EC_POINT of an Ed25519 key: DER OCTET STRING (PKCS#11 2.40/3.0, SoftHSM2 2.6.1) or 32 raw bytes
        (PKCS#11 3.1); the parameters must name Ed25519 (OID or "edwards25519"). Anything else is refused."""
        pub = bytes(range(32))
        oid, nome = bytes.fromhex("06032b6570"), b"\x13\x0cedwards25519"
        for p in (oid, nome):
            self.assertEqual(k._ed25519_da_ec_point(b"\x04\x20" + pub, p), pub)
            self.assertEqual(k._ed25519_da_ec_point(pub, p), pub)
        for punto, p in ((b"\x04\x20" + pub, bytes.fromhex("06032b6571")),          # Ed448 OID
                         (b"\x04\x21" + pub + b"\x00", oid), (pub[:31], oid), (b"\x04\x20" + pub[:31], oid),
                         (b"\x05\x20" + pub, oid), (pub, b""), (pub + b"\x00", oid)):
            with self.assertRaises(ValueError, msg=(punto.hex(), p.hex())):
                k._ed25519_da_ec_point(punto, p)


class TestLimiteDiTempoPkcs11(unittest.TestCase):
    def test_chiamata_bloccata_fermata(self):
        """0.1.1: the PKCS#11 calls run in a child process; at the time limit the child is killed, on every system.
        Here the child hangs on purpose (it sleeps instead of answering); before, the call ran in a thread of this
        process that the time limit could not stop."""
        import time
        f = k._Pkcs11Figlio(1.0)
        f.comando = [sys.executable, "-c", "import time; time.sleep(600)"]
        t0 = time.monotonic()
        with self.assertRaises(RuntimeError) as c:
            f.chiama({"op": "pub"}, "read public key")
        self.assertIn("timeout after 1.0 s", str(c.exception))
        self.assertLess(time.monotonic() - t0, 15)
        self.assertIsNone(f._proc)                               # killed and dropped
        # positive control: a child that answers is read, and a child that ends without answering is an error
        f = k._Pkcs11Figlio(30.0)
        f.comando = [sys.executable, "-c", "import sys; sys.stdin.readline(); print('{\"ok\": \"00ff\"}', flush=True)"]
        self.assertEqual(f.chiama({"op": "pub"}, "x"), b"\x00\xff")
        f.comando = [sys.executable, "-c", "import sys; sys.stdin.readline(); sys.exit(3)"]
        with self.assertRaises(RuntimeError) as c:
            f.chiama({"op": "pub"}, "x")
        self.assertIn("ended", str(c.exception))


class TestFiglioPkcs11Chiuso(unittest.TestCase):
    """NEMESIS 24/11/2026: the child process of the PKCS#11 calls."""

    def test_non_importa_dalla_cartella_corrente(self):
        """`python -c` puts the current directory first in sys.path: a json.py found there ran in the child, which
        holds the PIN. The child answers from any folder, and the planted module is not run."""
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "json.py"), "w") as f:
                f.write("open(%r, 'w').close()\nraise SystemExit(3)\n" % os.path.join(d, "ESEGUITO"))
            r = subprocess.run(k._Pkcs11Figlio(5.0).comando, cwd=d, input=b'{"op": "x"}\n', capture_output=True,
                               timeout=120)
            self.assertFalse(os.path.exists(os.path.join(d, "ESEGUITO")), "the child ran json.py of the current folder")
            self.assertEqual((r.returncode, r.stdout.strip()), (0, b'{"err": "unknown request"}'), r.stderr[-300:])

    def test_stdout_del_modulo_non_entra_nel_protocollo(self):
        """A module that prints on descriptor 1 during a call: the child's answer is still the only line."""
        import subprocess
        codice = ("import os, sys; sys.path[:] = [p for p in sys.path if p != '']; sys.path.append(sys.argv[1]); "
                  "import pq_scitt.kms as k; "
                  "k._p11_public_key = lambda *a: (os.write(1, b'vendor debug line\\n'), b'\\x01' * 32)[1]; "
                  "k._p11_lavoratore()")
        r = subprocess.run([sys.executable, "-B", "-c", codice, k._Pkcs11Figlio(5.0).comando[-1]],
                           input=b'{"op": "pub", "module": "m", "token": "t", "key": "k"}\n', capture_output=True,
                           timeout=120)
        self.assertEqual(r.stdout.splitlines(), [('{"ok": "%s"}' % ("01" * 32)).encode()], r.stderr[-300:])

    def test_risposta_fuori_forma_ferma_il_figlio(self):
        """Any answer that is not {"ok": hex} or {"err": text} = RuntimeError and the child is stopped: before, a
        stray line was a JSONDecodeError/TypeError/KeyError and the next call read the answer of this one."""
        for riga in ("vendor debug", "1", "[]", "{}", '{"ok": "zz"}', '{"ok": 5}', '{"err": 5}', '{"altro": "00"}',
                     '{"ok": "00", "err": "x"}', '{"ok": "00", "altro": "x"}'):
            f = k._Pkcs11Figlio(30.0)
            f.comando = [sys.executable, "-c", "import sys, time; sys.stdin.readline(); print(sys.argv[1], flush=True); "
                                               "print('{\"ok\": \"aa\"}', flush=True); time.sleep(600)", riga]
            with self.assertRaises(RuntimeError, msg=riga) as c:
                f.chiama({"op": "pub"}, "x")
            self.assertIn("out of form", str(c.exception), riga)
            self.assertIsNone(f._proc, riga)
        # positive control: the two forms allowed
        f = k._Pkcs11Figlio(30.0)
        f.comando = [sys.executable, "-c", "import sys; sys.stdin.readline(); print('{\"err\": \"no\"}', flush=True); "
                                           "sys.stdin.readline(); print('{\"ok\": \"aa\"}', flush=True)"]
        with self.assertRaises(RuntimeError) as c:
            f.chiama({"op": "pub"}, "x")
        self.assertIn("pkcs11 x: no", str(c.exception))
        self.assertEqual(f.chiama({"op": "pub"}, "x"), b"\xaa")

    def test_figlio_che_non_legge_fermato_al_limite(self):
        """A request larger than the pipe buffer to a child that does not read: the time limit holds (before, the
        caller stayed in the write until the child ended)."""
        import time
        f = k._Pkcs11Figlio(1.0)
        f.comando = [sys.executable, "-c", "import time; time.sleep(60)"]
        t0 = time.monotonic()
        with self.assertRaises(RuntimeError) as c:
            f.chiama({"op": "sign", "msg": "00" * (1 << 20)}, "sign")
        self.assertIn("timeout after 1.0 s", str(c.exception))
        self.assertLess(time.monotonic() - t0, 15)


class TestLayoutPkcs11(unittest.TestCase):
    def test_strutture_come_pkcs11_h(self):
        """CK_ATTRIBUTE and CK_MECHANISM as pkcs11.h lays them out: packed to 1 byte on Windows (CK_ULONG 4 bytes +
        pointer 8 + CK_ULONG 4 = 16 on Win64), natural alignment elsewhere (24 on LP64). Checked against the sizes
        ctypes gives for the same fields, so a change of packing is seen on every system."""
        import ctypes
        a, m = k._p11_strutture()
        u, p = ctypes.sizeof(ctypes.c_ulong), ctypes.sizeof(ctypes.c_void_p)
        atteso = 2 * u + p if os.name == "nt" else ctypes.sizeof(
            type("N", (ctypes.Structure,), {"_fields_": [("a", ctypes.c_ulong), ("b", ctypes.c_void_p),
                                                         ("c", ctypes.c_ulong)]}))
        self.assertEqual((ctypes.sizeof(a), ctypes.sizeof(m)), (atteso, atteso))
        self.assertEqual((a.pValue.offset, a.ulValueLen.offset), (u, u + p) if os.name == "nt" else
                         (a.pValue.offset, a.ulValueLen.offset))
        if os.name == "nt":
            self.assertEqual((u, ctypes.sizeof(a)), (4, 16))    # Win64: CK_ULONG is 4 bytes, the attribute 16


if __name__ == "__main__":
    unittest.main(verbosity=2)
