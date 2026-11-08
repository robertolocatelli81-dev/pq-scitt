#!/usr/bin/env python3
"""Backends of pq_scitt/kms.py against REAL local services:
SoftHSM2 through pkcs11-tool (token in a temporary folder, never the system one) and HashiCorp Vault Transit in a
throwaway podman container (`vault server -dev`, port only on 127.0.0.1, removed at the end). No external network.
Skipped with a reason if SoftHSM2/pkcs11-tool or podman/the image are missing: a skip is not a green.
PIN and token are random, passed through the environment, never on argv and never printed."""
import base64
import json
import os
import random
import secrets
import shutil
import socket
import string
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from datetime import datetime, timedelta, timezone
from unittest import mock

RADICE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RADICE)
sys.path.insert(1, os.path.join(RADICE, "chain"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

from pq_scitt.scitt import cbor as cbor  # noqa: E402
from pq_scitt.scitt import export as sx  # noqa: E402

kms = sx._cryptovalid_kms()

MODULO = "/usr/lib/softhsm/libsofthsm2.so"
IMMAGINE = "docker.io/hashicorp/vault:1.20"
HSM_C_E = bool(shutil.which("pkcs11-tool")) and os.path.exists(MODULO)


def _podman_c_e():
    if not shutil.which("podman"):
        return False
    return subprocess.run(["podman", "image", "exists", IMMAGINE], capture_output=True).returncode == 0


PODMAN_C_E = _podman_c_e()


def _righe(n):
    righe, prev = [], sx.GENESIS
    for i in range(n):
        r = {"idx": i, "ts": "2026-11-08T12:00:%02dZ" % i, "data": {"evento": "prova kms reale", "n": i},
             "prev_hash": prev}
        r["self_hash"] = sx.hash_riga_ops(r)
        prev = r["self_hash"]
        righe.append(r)
    return righe


def _validita():
    f = "%Y-%m-%dT%H:%M:%SZ"
    ora = datetime.now(timezone.utc)
    return (ora - timedelta(days=1)).strftime(f) + "/" + (ora + timedelta(days=300)).strftime(f)


def _cli(argv, env, timeout=300):
    r = subprocess.run([sys.executable, "-B"] + argv, cwd=RADICE, env=env, capture_output=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def _porta_libera():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _Comune(unittest.TestCase):
    SEGRETI = ()

    def env(self, **extra):
        e = dict(os.environ)
        e.update(self.ENV)
        e.update(extra)
        return e

    def assert_rifiuto_pulito(self, rc, out, err, cartella=None):
        tutto = out + err
        self.assertNotEqual(rc, 0, tutto[-400:])
        self.assertNotIn(b"Traceback", tutto, tutto[-800:])
        for s in self.SEGRETI:
            self.assertNotIn(s.encode(), tutto)
        if cartella is not None:
            self.assertFalse(os.path.exists(cartella), "output folder created despite the refusal")

    def export(self, uri, cartella, payload="chiaro", n=5, env=None):
        reg = os.path.join(self.tmp, "registro_%s.jsonl" % secrets.token_hex(4))
        with open(reg, "w", encoding="utf-8") as f:
            for r in _righe(n):
                f.write(json.dumps(r, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
        v = _validita()
        argv = ["-m", "pq_scitt.scitt.export", reg, cartella, "--nome", "kms-reali", "--payload", payload,
                "--chiave-issuer", uri[0], "--chiave-ts", uri[1], "--chiave-politica", uri[2],
                "--validita-issuer", v, "--validita-ts", v, "--validita-politica", v]
        sali = None
        if payload == "riservato":
            sali = os.path.join(self.tmp, "sali_%s" % secrets.token_hex(4))
            argv += ["--sali", sali]
        rc, out, err = _cli(argv, env or self.env())
        return rc, out, err, reg, sali

    def verifica(self, cartella, pub_ts, pub_pol, reg=None, sali=None):
        argv = ["-m", "pq_scitt.scitt.verify", cartella, "--alg", "-19", "--ts-pub", pub_ts, "--politica-pub", pub_pol]
        if reg:
            argv += ["--registro", reg, "--sali", sali]
        return _cli(argv, self.env())

    def controllo_positivo(self, cartella, pub_ts, pub_pol, firma_altra):
        """M3: altered signature and signature by another key = REFUSED; the same structure re-encoded = OK."""
        nome = "ts_000001.cose"
        with open(os.path.join(cartella, nome), "rb") as f:
            dati = f.read()
        t = cbor.loads(dati)
        prot, nonprot, payload, firma = t.value
        casi = {"intatto_ricodificato": (cbor.dumps(cbor.Tag(cbor.TAG_COSE_SIGN1, [prot, nonprot, payload, firma])), 0),
                "byte_alterato": (dati[:-1] + bytes([dati[-1] ^ 1]), 1),
                "altra_chiave": (cbor.dumps(cbor.Tag(cbor.TAG_COSE_SIGN1, [prot, nonprot, payload,
                                                     firma_altra(sx.sig_structure(prot, payload))])), 1)}
        esiti = {}
        for caso, (nuovi, atteso) in casi.items():
            c2 = os.path.join(self.tmp, "cp_%s_%s" % (caso, secrets.token_hex(3)))
            shutil.copytree(cartella, c2)
            with open(os.path.join(c2, nome), "wb") as f:
                f.write(nuovi)
            rc, out, err = self.verifica(c2, pub_ts, pub_pol)
            esiti[caso] = (rc, out.decode(errors="replace").strip())
            self.assertEqual(rc, atteso, (caso, out, err[-300:]))
        return esiti

    def controllo_firma_issuer(self, uri_ts, uri_pol, pub_issuer, firma_altra, attesa=b"firma_statement_non_valida"):
        """M3 (bis): the altered signature above already fails on the receipt (the leaf is the whole statement,
        signature included). Here the receipts are VALID and only the issuer signature is by another key: the
        export self-check (_firma_regge) is bypassed to build the case; the verifier must refuse for the signature."""
        ts, pol = sx.carica_firmatario(uri_ts, -19), sx.carica_firmatario(uri_pol, -19)
        falso = sx.Firmatario(-19, bytes.fromhex(pub_issuer), firma_altra)
        with mock.patch.object(sx, "_firma_regge", lambda *a: True):
            es = sx.esporta(_righe(3), nome="kms-reali", formato="ops", issuer=falso, ts=ts, politica=pol,
                            iss_issuer="omega.issuer", iss_ts="omega.ts")
        cart = os.path.join(self.tmp, "issuer_falso_" + secrets.token_hex(3))
        sx.scrivi_cartella(es, cart)
        rc, out, err = self.verifica(cart, ts.pub.hex(), pol.pub.hex())
        self.assertEqual(rc, 1, out + err[-300:])
        self.assertIn(attesa, out)
        return out


# ------------------------------------------------------------------------------------------------ SoftHSM2

@unittest.skipUnless(HSM_C_E, "SoftHSM2 or pkcs11-tool missing (%s)" % MODULO)
class TestSoftHsmReale(_Comune):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="kmsreali_hsm_")
        os.chmod(cls.tmp, 0o700)
        os.makedirs(os.path.join(cls.tmp, "tokens"))
        conf = os.path.join(cls.tmp, "softhsm2.conf")
        with open(conf, "w") as f:
            f.write("directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n" % cls.tmp)
        cls.PIN, so = secrets.token_hex(8), secrets.token_hex(8)
        cls.SEGRETI = (cls.PIN, so)
        cls.ENV = {"SOFTHSM2_CONF": conf, "KR_PIN": cls.PIN, "KR_SO": so}
        e = dict(os.environ, **cls.ENV)
        for argv in (["--init-token", "--label", "kmsreali", "--so-pin", "env:KR_SO", "--slot-index", "0"],
                     ["--token-label", "kmsreali", "--init-pin", "--login", "--login-type", "so", "--so-pin",
                      "env:KR_SO", "--pin", "env:KR_PIN"]):
            r = subprocess.run(["pkcs11-tool", "--module", MODULO] + argv, env=e, capture_output=True, timeout=60)
            if r.returncode:
                raise RuntimeError("token initialisation failed: %s" % r.stderr[-200:])
        cls._env_patch = mock.patch.dict(os.environ, cls.ENV)
        cls._env_patch.start()
        cls.pub = {}
        for nome in ("issuer", "ts", "politica", "altra"):
            cls.pub[nome] = cls.backend(nome).keygen()

    @classmethod
    def tearDownClass(cls):
        cls._env_patch.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def uri(cls, nome, **extra):
        u = "pkcs11:module=%s;token=kmsreali;key=%s;pin=env:KR_PIN" % (MODULO, nome)
        return u + "".join(";%s=%s" % kv for kv in extra.items())

    @classmethod
    def backend(cls, nome, **extra):
        return kms.backend_from_uri(cls.uri(nome, **extra))

    def _oggetti(self):
        r = subprocess.run(["pkcs11-tool", "--module", MODULO, "--token-label", "kmsreali", "--login", "--pin",
                            "env:KR_PIN", "--list-objects"], env=self.env(), capture_output=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        blocchi, cur = [], None
        for riga in r.stdout.decode().splitlines():
            if riga and not riga.startswith(" "):
                cur = {"tipo": riga.split(";")[0].strip()}
                blocchi.append(cur)
            elif cur is not None and ":" in riga:
                k, _, v = riga.strip().partition(":")
                cur[k.strip()] = v.strip()
        return blocchi

    def test_m1_privata_generata_nel_token_non_estraibile(self):
        priv = [b for b in self._oggetti() if b["tipo"] == "Private Key Object"]
        self.assertEqual(sorted(b["label"] for b in priv), ["altra", "issuer", "politica", "ts"])
        for b in priv:
            accesso = {x.strip() for x in b["Access"].split(",")}
            self.assertTrue({"sensitive", "always sensitive", "never extractable", "local"} <= accesso, b)
            self.assertNotIn("extractable", accesso, b)
            uso = {x.strip() for x in b["Usage"].split(",")}
            self.assertIn("sign", uso, b)
            self.assertNotIn("derive", uso, b)

    def test_m1_etichetta_gia_presente_rifiutata(self):
        with self.assertRaises(RuntimeError):
            self.backend("issuer").keygen()
        priv = [b for b in self._oggetti() if b["tipo"] == "Private Key Object" and b["label"] == "issuer"]
        self.assertEqual(len(priv), 1, "second key created with the same label")

    def test_m1_export_e_verifica_chiaro_e_riservato(self):
        uri = (self.uri("issuer"), self.uri("ts"), self.uri("politica"))
        for payload in ("chiaro", "riservato"):
            cart = os.path.join(self.tmp, "export_" + payload)
            rc, out, err, reg, sali = self.export(uri, cart, payload)
            self.assertEqual(rc, 0, out + err[-500:])
            with open(os.path.join(cart, "manifest.json")) as f:
                man = json.load(f)
            self.assertEqual(man["politica"]["ancore"][0]["pub"], self.pub["issuer"])
            rc, out, err = self.verifica(cart, self.pub["ts"], self.pub["politica"],
                                         reg if payload == "riservato" else None, sali)
            self.assertEqual(rc, 0, out + err[-500:])
            self.assertTrue(out.startswith(b"OK 6 leaves"), out)

    def test_m3_controllo_positivo(self):
        uri = (self.uri("issuer"), self.uri("ts"), self.uri("politica"))
        cart = os.path.join(self.tmp, "export_cp")
        rc, out, err, _, _ = self.export(uri, cart)
        self.assertEqual(rc, 0, out + err[-500:])
        self.controllo_positivo(cart, self.pub["ts"], self.pub["politica"], self.backend("altra").sign)
        self.controllo_firma_issuer(self.uri("ts"), self.uri("politica"), self.pub["issuer"], self.backend("altra").sign)

    def _tre_livelli(self, uri, attesa_backend):
        with self.assertRaises((RuntimeError, ValueError)) as c:
            b = kms.backend_from_uri(uri)
            b.public_key_hex()
            b.sign(b"x")
        self.assertIn(attesa_backend, str(c.exception))
        for s in self.SEGRETI:
            self.assertNotIn(s, str(c.exception))
        cart = os.path.join(self.tmp, "no_" + secrets.token_hex(4))
        rc, out, err, _, _ = self.export((uri, self.uri("ts"), self.uri("politica")), cart)
        self.assert_rifiuto_pulito(rc, out, err, cart)
        self.assertIn(b"REFUSED", out)
        rc, out, err = _cli(["-m", "pq_scitt.kms", "selftest", "--backend", uri], self.env())
        self.assert_rifiuto_pulito(rc, out, err)
        return str(c.exception)

    def test_m4_pin_sbagliato(self):
        with mock.patch.dict(os.environ, {"KR_ALTRO": "0000" + secrets.token_hex(4)}):
            self.ENV = dict(self.ENV, KR_ALTRO=os.environ["KR_ALTRO"])
            self._tre_livelli(self.uri("issuer").replace("env:KR_PIN", "env:KR_ALTRO"), "PIN_INCORRECT")

    def test_m4_chiave_inesistente(self):
        self._tre_livelli(self.uri("nessuna"), "nessuna")

    def test_m4_token_inesistente(self):
        self._tre_livelli(self.uri("issuer").replace("token=kmsreali", "token=spento"), "spento")

    def test_m4_modulo_inesistente(self):
        self._tre_livelli(self.uri("issuer").replace(MODULO, "/nessun/modulo.so"), "pkcs11-tool")

    def test_m4_timeout(self):
        self._tre_livelli(self.uri("issuer", timeout="0.001"), "timeout")

    # review 08/11 (P1): concurrency and timeout in the same process. In a subprocess: a SIGSEGV of the module
    # becomes rc -11 here instead of killing the suite. Before the patch: 5/5 crashes with 8 threads, 9/12 with short
    # timeouts.
    _SCRIPT_N1 = r"""
import os, sys, threading, secrets
sys.path.insert(0, "opencore")
from pq_scitt import kms as k
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
uri, pub = sys.argv[1], Ed25519PublicKey.from_public_bytes(bytes.fromhex(sys.argv[2]))
be = k.backend_from_uri(uri)
cattivi = []
def w(i):
    for j in range(5):
        m = b"n1-%d-%d" % (i, j)
        try:
            pub.verify(be.sign(m), m)
        except Exception as e:
            cattivi.append(type(e).__name__)
ts = [threading.Thread(target=w, args=(i,)) for i in range(8)]
[t.start() for t in ts]; [t.join() for t in ts]
corto = k.backend_from_uri(uri + ";timeout=0.003")
for i in range(30):
    m = secrets.token_bytes(1 << 18)
    try:
        pub.verify(corto.sign(m), m)
    except RuntimeError as e:
        if "timeout" not in str(e) and "still running" not in str(e):
            cattivi.append(str(e)[:80])
k.backend_from_uri(uri + ";timeout=120").sign(b"dopo")
print("OK" if not cattivi else "BAD %r" % cattivi[:5])
"""

    def test_n1_concorrenza_e_timeout_senza_crash(self):
        for giro in range(3):
            r = subprocess.run([sys.executable, "-B", "-c", self._SCRIPT_N1, self.uri("altra"), self.pub["altra"]],
                               cwd=RADICE, env=self.env(), capture_output=True, timeout=600)
            self.assertEqual(r.returncode, 0, (giro, r.returncode, r.stdout[-300:], r.stderr[-300:]))
            self.assertEqual(r.stdout.strip(), b"OK", r.stdout[-300:])

    def _genera_con_pkcs11_tool(self, etichetta, *opzioni):
        r = subprocess.run(["pkcs11-tool", "--module", MODULO, "--token-label", "kmsreali", "--login", "--pin",
                            "env:KR_PIN", "--keypairgen", "--label", etichetta] + list(opzioni),
                           env=self.env(), capture_output=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr[-300:])

    def test_n2_firma_rifiuta_chiavi_fuori_forma(self):
        """Checks of _p11_sign_direct on keys made on purpose (outside keygen): extractable, P-256, duplicate label."""
        self._genera_con_pkcs11_tool("n2_estr", "--key-type", "EC:edwards25519", "--usage-sign", "--sensitive",
                                     "--extractable")
        self._genera_con_pkcs11_tool("n2_p256", "--key-type", "EC:prime256v1", "--usage-sign", "--sensitive")
        for _ in range(2):
            self._genera_con_pkcs11_tool("n2_doppia", "--key-type", "EC:edwards25519", "--usage-sign", "--sensitive")
        for etichetta, motivo in (("n2_estr", "CKA_EXTRACTABLE=1"), ("n2_p256", "not an EC_EDWARDS key"),
                                  ("n2_doppia", "2 private keys labelled")):
            with self.assertRaises(RuntimeError, msg=etichetta) as c:
                self.backend(etichetta).sign(b"x")
            self.assertIn(motivo, str(c.exception))
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.pub["altra"])).verify(
            self.backend("altra").sign(b"x"), b"x")   # positive control: the well-formed key signs

    def _genera_ctypes(self, etichetta, sensibile, firma):
        """Ed25519 pair in the token with chosen CKA_SENSITIVE/CKA_SIGN (pkcs11-tool 0.23 cannot clear them)."""
        import ctypes
        ul, lib = ctypes.c_ulong, ctypes.CDLL(MODULO)

        class A(ctypes.Structure):
            _fields_ = [("t", ul), ("p", ctypes.c_void_p), ("n", ul)]

        class M(ctypes.Structure):
            _fields_ = [("m", ul), ("p", ctypes.c_void_p), ("n", ul)]
        for f in ("C_Initialize", "C_GetSlotList", "C_GetTokenInfo", "C_OpenSession", "C_Login", "C_GenerateKeyPair",
                  "C_CloseSession", "C_Finalize"):
            getattr(lib, f).restype = ul
        keep = []

        def a(t, v):
            b = ctypes.create_string_buffer(v, len(v)) if isinstance(v, bytes) else ctypes.c_ubyte(v)
            keep.append(b)
            return A(t, ctypes.cast(ctypes.byref(b), ctypes.c_void_p), len(v) if isinstance(v, bytes) else 1)
        with mock.patch.dict(os.environ, self.ENV):
            self.assertIn(lib.C_Initialize(None), (0, 0x191))
            try:
                n = ul(0)
                lib.C_GetSlotList(ctypes.c_ubyte(1), None, ctypes.byref(n))
                slots = (ul * n.value)()
                lib.C_GetSlotList(ctypes.c_ubyte(1), slots, ctypes.byref(n))
                slot = [x for x in slots if (lambda b: (lib.C_GetTokenInfo(ul(x), b), b.raw[:32])[1])(
                    ctypes.create_string_buffer(1024)).rstrip(b" ") == b"kmsreali"][0]
                h = ul(0)
                self.assertEqual(lib.C_OpenSession(ul(slot), ul(6), None, None, ctypes.byref(h)), 0)
                pin = self.PIN.encode()
                self.assertEqual(lib.C_Login(h, ul(1), pin, ul(len(pin))), 0)
                lab = etichetta.encode()
                pub = (A * 3)(a(0x1, 1), a(0x3, lab), a(0x180, bytes.fromhex("06032b6570")))   # TOKEN, LABEL, EC_PARAMS
                prv = (A * 6)(a(0x1, 1), a(0x2, 1), a(0x3, lab), a(0x103, int(sensibile)), a(0x108, int(firma)),
                              a(0x162, 0))                     # TOKEN, PRIVATE, LABEL, SENSITIVE, SIGN, EXTRACTABLE
                hp, hk = ul(0), ul(0)
                mech = M(0x1055, None, 0)                      # CKM_EC_EDWARDS_KEY_PAIR_GEN
                rv = lib.C_GenerateKeyPair(h, ctypes.byref(mech), pub, ul(3), prv, ul(6), ctypes.byref(hp),
                                           ctypes.byref(hk))
                self.assertEqual(rv, 0, hex(rv))
                lib.C_CloseSession(h)
            finally:
                lib.C_Finalize(None)

    def test_n5_firma_rifiuta_non_sensibile_e_senza_sign(self):
        self._genera_ctypes("n5_nosens", sensibile=False, firma=True)
        self._genera_ctypes("n5_nosign", sensibile=True, firma=False)
        self._genera_ctypes("n5_ok", sensibile=True, firma=True)   # positive control of the same generator
        for etichetta, motivo in (("n5_nosens", "CKA_SENSITIVE=0"), ("n5_nosign", "CKA_SIGN=0")):
            with self.assertRaises(RuntimeError, msg=etichetta) as c:
                self.backend(etichetta).sign(b"x")
            self.assertIn(motivo, str(c.exception))
        self.assertEqual(len(self.backend("n5_ok").sign(b"x")), 64)

    def test_n6_due_token_con_la_stessa_etichetta(self):
        """In its own token-dir: two tokens "doppio" = signing refuses (before any login)."""
        d = tempfile.mkdtemp(prefix="kmsreali_n6_", dir=self.tmp)
        os.makedirs(os.path.join(d, "tokens"))
        conf = os.path.join(d, "softhsm2.conf")
        with open(conf, "w") as f:
            f.write("directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n" % d)
        e = dict(self.env(), SOFTHSM2_CONF=conf)
        for i in range(2):
            r = subprocess.run(["pkcs11-tool", "--module", MODULO, "--init-token", "--label", "doppio", "--so-pin",
                                "env:KR_SO", "--slot-index", str(i)], env=e, capture_output=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr[-200:])
        with mock.patch.dict(os.environ, {"SOFTHSM2_CONF": conf}):
            with self.assertRaises(RuntimeError) as c:
                kms.backend_from_uri("pkcs11:module=%s;token=doppio;key=k;pin=env:KR_PIN" % MODULO).sign(b"x")
        self.assertIn("2 tokens labelled 'doppio'", str(c.exception))


# ------------------------------------------------------------------------------------------------ Vault

@unittest.skipUnless(PODMAN_C_E, "podman or image %s missing" % IMMAGINE)
class TestVaultReale(_Comune):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="kmsreali_vault_")
        cls.TOKEN = "kr-" + secrets.token_hex(12)
        cls.SEGRETI = (cls.TOKEN,)
        cls.ENV = {"VAULT_TOKEN": cls.TOKEN, "VAULT_DEV_ROOT_TOKEN_ID": cls.TOKEN}
        cls.porta = _porta_libera()
        cls.nome = "kmsreali-vault-" + secrets.token_hex(4)
        cls.url = "http://127.0.0.1:%d" % cls.porta
        r = subprocess.run(["podman", "run", "-d", "--rm", "--name", cls.nome, "-p", "127.0.0.1:%d:8200" % cls.porta,
                            "-e", "VAULT_DEV_ROOT_TOKEN_ID", "-e", "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
                            "-e", "SKIP_SETCAP=1", IMMAGINE, "server", "-dev"],
                           env=dict(os.environ, **cls.ENV), capture_output=True, timeout=120)
        if r.returncode:
            raise RuntimeError("podman run failed: %s" % r.stderr[-300:])
        fine = time.time() + 90
        while True:
            try:
                with urllib.request.urlopen(cls.url + "/v1/sys/health", timeout=2) as h:
                    if h.status == 200:
                        break
            except Exception:  # noqa: BLE001 — the service is starting
                pass
            if time.time() > fine:
                cls.tearDownClass()
                raise RuntimeError("Vault not ready in 90 s")
            time.sleep(1)
        cls.api("POST", "sys/mounts/transit", {"type": "transit"})
        for nome in ("issuer", "ts", "politica", "altra", "rot"):
            cls.api("POST", "transit/keys/" + nome, {"type": "ed25519"})
        cls._env_patch = mock.patch.dict(os.environ, {"VAULT_TOKEN": cls.TOKEN})
        cls._env_patch.start()
        cls.pub = {n: cls.backend(n).public_key_hex() for n in ("issuer", "ts", "politica", "altra")}

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "_env_patch", None):
            cls._env_patch.stop()
        subprocess.run(["podman", "stop", "-t", "2", cls.nome], capture_output=True, timeout=120)
        subprocess.run(["podman", "rm", "-f", "--ignore", cls.nome], capture_output=True, timeout=120)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def api(cls, metodo, percorso, corpo=None):
        req = urllib.request.Request("%s/v1/%s" % (cls.url, percorso), method=metodo,
                                     data=json.dumps(corpo).encode() if corpo is not None else None,
                                     headers={"X-Vault-Token": cls.TOKEN, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            dati = r.read()
        return json.loads(dati) if dati else {}

    @classmethod
    def uri(cls, nome, url=None, **extra):
        u = "vault:url=%s;key=%s" % (url or cls.url, nome)
        return u + "".join(";%s=%s" % kv for kv in extra.items())

    @classmethod
    def backend(cls, nome, **kw):
        return kms.backend_from_uri(cls.uri(nome, **kw))

    def test_m2_export_e_verifica(self):
        cart = os.path.join(self.tmp, "export")
        rc, out, err, _, _ = self.export((self.uri("issuer"), self.uri("ts"), self.uri("politica")), cart)
        self.assertEqual(rc, 0, out + err[-500:])
        rc, out, err = self.verifica(cart, self.pub["ts"], self.pub["politica"])
        self.assertEqual(rc, 0, out + err[-500:])

    def test_m2_rotazione_vecchie_firme_restano_verificabili(self):
        uri = (self.uri("rot"), self.uri("ts"), self.uri("politica"))
        v1 = self.backend("rot").public_key_hex()
        prima = os.path.join(self.tmp, "rot_prima")
        rc, out, err, _, _ = self.export(uri, prima)
        self.assertEqual(rc, 0, out + err[-500:])
        self.api("POST", "transit/keys/rot/rotate")
        self.assertEqual(self.api("GET", "transit/keys/rot")["data"]["latest_version"], 2)
        v2 = self.backend("rot").public_key_hex()
        self.assertNotEqual(v1, v2)
        rc, out, err = self.verifica(prima, self.pub["ts"], self.pub["politica"])
        self.assertEqual(rc, 0, out + err[-500:])
        with open(os.path.join(prima, "manifest.json")) as f:
            self.assertEqual(json.load(f)["politica"]["ancore"][0]["pub"], v1)
        dopo = os.path.join(self.tmp, "rot_dopo")
        rc, out, err, _, _ = self.export(uri, dopo)
        self.assertEqual(rc, 0, out + err[-500:])
        with open(os.path.join(dopo, "manifest.json")) as f:
            anc = json.load(f)["politica"]["ancore"][0]
        self.assertEqual(anc["pub"], v2)
        self.assertNotEqual(anc["kid"], sx.kid_di(bytes.fromhex(v1)).hex())
        rc, out, err = self.verifica(dopo, self.pub["ts"], self.pub["politica"])
        self.assertEqual(rc, 0, out + err[-500:])

    def test_m2_rotazione_a_meta_firma_con_la_versione_letta(self):
        self.api("POST", "transit/keys/meta", {"type": "ed25519"})
        b = self.backend("meta")
        pub = b.public_key_hex()
        self.api("POST", "transit/keys/meta/rotate")
        msg = b"riga firmata dopo la rotazione"
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(b.sign(msg), msg)

    def test_m3_controllo_positivo(self):
        cart = os.path.join(self.tmp, "export_cp")
        rc, out, err, _, _ = self.export((self.uri("issuer"), self.uri("ts"), self.uri("politica")), cart)
        self.assertEqual(rc, 0, out + err[-500:])
        self.controllo_positivo(cart, self.pub["ts"], self.pub["politica"], self.backend("altra").sign)
        self.controllo_firma_issuer(self.uri("ts"), self.uri("politica"), self.pub["issuer"], self.backend("altra").sign)

    def _tre_livelli(self, uri, attesa_backend, env=None):
        with mock.patch.dict(os.environ, env or {}):
            with self.assertRaises((RuntimeError, ValueError)) as c:
                b = kms.backend_from_uri(uri)
                b.public_key_hex()
                b.sign(b"x")
        self.assertIn(attesa_backend, str(c.exception))
        for s in self.SEGRETI:
            self.assertNotIn(s, str(c.exception))
        e = self.env(**(env or {}))
        cart = os.path.join(self.tmp, "no_" + secrets.token_hex(4))
        rc, out, err, _, _ = self.export((uri, self.uri("ts"), self.uri("politica")), cart, env=e)
        self.assert_rifiuto_pulito(rc, out, err, cart)
        self.assertIn(b"REFUSED", out)
        rc, out, err = _cli(["-m", "pq_scitt.kms", "selftest", "--backend", uri], e)
        self.assert_rifiuto_pulito(rc, out, err)

    def test_m4_servizio_spento(self):
        self._tre_livelli(self.uri("issuer", url="http://127.0.0.1:%d" % _porta_libera()), "unreachable")

    def test_m4_token_sbagliato(self):
        self._tre_livelli(self.uri("issuer"), "403", env={"VAULT_TOKEN": "kr-sbagliato-" + secrets.token_hex(6)})

    def test_m4_chiave_inesistente(self):
        self._tre_livelli(self.uri("nessuna"), "nessuna")

    def test_m4_timeout(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        aperte = []

        def accetta():
            try:
                while True:
                    aperte.append(srv.accept()[0])   # accepts and never answers
            except OSError:
                pass
        threading.Thread(target=accetta, daemon=True).start()
        try:
            self._tre_livelli(self.uri("issuer", url="http://127.0.0.1:%d" % srv.getsockname()[1], timeout="1"),
                              "timed out")
        finally:
            srv.close()
            for s in aperte:
                s.close()


# ------------------------------------------------------------------------------------------------ URI chiuso

class TestUriChiuso(unittest.TestCase):
    """M5: unknown, duplicate or empty key, or segment without "=" = refused with reason (before: silently accepted)."""
    BASE = {
        "pkcs11": [("module", MODULO), ("token", "t"), ("key", "k"), ("pin", "env:KR_FINTO")],
        "vault": [("url", "http://127.0.0.1:8200"), ("key", "k"), ("mount", "transit")],
        "awskms-http": [("key_id", "k"), ("region", "eu-central-1")],
        "nethsm": [("url", "https://127.0.0.1"), ("key", "k"), ("user", "u")],
    }
    ENV = {"KR_FINTO": "x", "VAULT_TOKEN": "x", "AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "x",
           "NETHSM_PASS": "x"}

    def _uri(self, schema, coppie):
        return schema + ":" + ";".join("%s=%s" % kv if kv[1] is not None else kv[0] for kv in coppie)

    def test_valido_si_costruisce(self):   # positive control: the bench does not refuse everything
        with mock.patch.dict(os.environ, self.ENV):
            for schema, coppie in self.BASE.items():
                if schema == "pkcs11" and not shutil.which("pkcs11-tool"):
                    continue
                kms.backend_from_uri(self._uri(schema, coppie))

    def test_generativo(self):
        rnd = random.Random(20261108)
        rifiuti = 0
        with mock.patch.dict(os.environ, self.ENV):
            # without pkcs11-tool the pkcs11 scheme is not among the choices (before: "continue", and 299 refusals out
            # of 400 did not reach the threshold); with pkcs11-tool the sequence is identical to before
            schemi = sorted(s for s in self.BASE if s != "pkcs11" or shutil.which("pkcs11-tool"))
            for _ in range(400):
                schema = rnd.choice(schemi)
                coppie = list(self.BASE[schema])
                caso = rnd.choice(("ignota", "doppia", "vuota", "senza_uguale", "segmento_vuoto"))
                pos = rnd.randrange(len(coppie) + 1)
                if caso == "ignota":
                    k = "".join(rnd.choice(string.ascii_lowercase + "_") for _ in range(rnd.randint(1, 9)))
                    if k in ("module", "token", "key", "pin", "url", "mount", "token_env", "key_id", "region",
                             "profile", "endpoint", "user", "pass_env", "timeout"):
                        continue
                    coppie.insert(pos, (k, "v"))
                elif caso == "doppia":
                    k, v = rnd.choice(coppie)
                    coppie.insert(pos, (k, v))
                elif caso == "vuota":
                    i = rnd.randrange(len(coppie))
                    coppie[i] = (coppie[i][0], "")
                elif caso == "senza_uguale":
                    coppie.insert(pos, ("pim", None))
                else:
                    coppie.insert(pos, ("", None))
                uri = self._uri(schema, coppie)
                with self.assertRaises(ValueError, msg=uri):
                    kms.backend_from_uri(uri)
                rifiuti += 1
        self.assertGreater(rifiuti, 300)

    def test_regione_aws_chiusa(self):
        with mock.patch.dict(os.environ, self.ENV):
            for r in ("eu-central-1/x", "evil.com#", "eu-central-1.evil.com", "EU-CENTRAL-1", "eu central 1", ""):
                with self.assertRaises(ValueError, msg=r):
                    kms.backend_from_uri("awskms-http:key_id=k;region=" + r)

    def test_timeout_fuori_intervallo(self):
        with mock.patch.dict(os.environ, self.ENV):
            for t in ("0", "-1", "nan", "inf", "601", "abc", "1e9"):
                with self.assertRaises(ValueError, msg=t):
                    kms.backend_from_uri("vault:url=http://127.0.0.1:8200;key=k;timeout=" + t)


    def test_n3_regione_chiusa_anche_nei_costruttori(self):   # review 08/11 (P2)
        with mock.patch.dict(os.environ, self.ENV):
            for r in ("x.evil.com#", "eu-central-1.evil.com", "eu-central-١", "eu-central-१"):
                with self.assertRaises(ValueError, msg=r):
                    kms.AwsKmsHttpBackend("k", r)
                with self.assertRaises(ValueError, msg=r):
                    kms.AwsKmsBackend("k", region=r, client=object())
                with self.assertRaises(ValueError, msg=r):
                    kms.backend_from_uri("awskms-http:key_id=k;region=" + r)
            self.assertEqual(kms.AwsKmsHttpBackend("k", "eu-central-1")._host, "kms.eu-central-1.amazonaws.com")
            kms.AwsKmsBackend("k", region="us-gov-west-1", client=object())   # positive control

    def test_n4_timeout_solo_decimale_ascii(self):   # review 08/11 (P2)
        with mock.patch.dict(os.environ, self.ENV):
            for t in ("1_0", "١٠", "0x10", "5.", ".5", "1e1", "+5"):
                with self.assertRaises(ValueError, msg=t):
                    kms.backend_from_uri("vault:url=http://127.0.0.1:8200;key=k;timeout=" + t)
            for t, atteso in (("5", 5.0), ("0.5", 0.5), ("600", 600.0)):
                b = kms.backend_from_uri("vault:url=http://127.0.0.1:8200;key=k;timeout=" + t)
                self.assertEqual(b._timeout, atteso)

    def test_n7_vault_risposta_di_altra_versione_rifiutata(self):   # review 08/11: Vault that ignores key_version
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization as ser
        sk = Ed25519PrivateKey.generate()
        spki = base64.b64encode(sk.public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo))
        chiave = {"data": {"latest_version": 1, "keys": {"1": {"public_key": spki.decode()}}}}
        with mock.patch.dict(os.environ, self.ENV):
            for ver, rifiuto in (("2", True), ("1", False)):
                b = kms.backend_from_uri("vault:url=http://127.0.0.1:8200;key=k")
                firma = {"data": {"signature": "vault:v%s:%s" % (ver, base64.b64encode(sk.sign(b"m")).decode())}}
                with mock.patch.object(b, "_req", side_effect=[chiave, firma]):
                    if rifiuto:
                        with self.assertRaises(RuntimeError) as c:
                            b.sign(b"m")
                        self.assertIn("key version 2", str(c.exception))
                    else:
                        self.assertEqual(b.sign(b"m"), sk.sign(b"m"))

if __name__ == "__main__":
    unittest.main(verbosity=2)
