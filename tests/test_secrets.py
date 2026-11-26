"""0.1.2: a secret given to pq-scitt does not come out of it. A canary — an Ed25519 seed, a password in a URL, a token
or PIN in the environment, an HMAC key, a value put where a name goes — goes into every input that takes a key, a URL or
a token (`kms --backend` vault:, nethsm:, awskms-http:, pkcs11:, file:; `verify-ledger --hmac-key*`; the strict JSON
reader), and is searched in everything that comes out: standard output and error, the receipt, the exception, the
environment of a child process. It is searched raw and in hex, base64, base64url (at each of the three offsets) and
decimal. With it the platform rules of the same release: no program found in the current folder, reads in pieces,
integers of more than 4300 digits refused on every Python.

Positive control: a producer that leaks is found in each of those forms; and on 0.1.1 (34606f7) the tests that state
the new behaviour fail (CHANGELOG 0.1.2 counts them)."""
import base64
import contextlib
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

from pq_scitt import cli, kms, strict_json
from pq_scitt.ledger import standalone

SEED = hashlib.sha256(b"pq-scitt test_secrets canary seed").digest()      # a test key, not anyone's
PASSWORD = "Pw" + base64.urlsafe_b64encode(SEED).decode()[:30]
KEYNAME = base64.urlsafe_b64encode(SEED).decode().rstrip("=")             # 43 characters: a secret where a name goes
CANARIES = (SEED, SEED.hex().encode(), PASSWORD.encode(), KEYNAME.encode())


def forms(secret):
    out = {"raw": secret, "hex": secret.hex().encode(), "HEX": secret.hex().upper().encode(),
           "decimal": str(int.from_bytes(secret, "big")).encode()}
    for k in range(3):
        whole = base64.b64encode(b"\0" * k + secret + b"\0" * ((3 - (k + len(secret)) % 3) % 3))
        part = whole[(k * 8 + 5) // 6:(k + len(secret)) * 8 // 6]
        out["base64+%d" % k], out["base64url+%d" % k] = part, part.replace(b"+", b"-").replace(b"/", b"_")
    return out


def found(secret, *outputs):
    blob = b"\n".join(o if isinstance(o, bytes) else str(o).encode("utf-8", "surrogatepass") for o in outputs)
    blob += b"\n" + blob.replace(b"\\/", b"/")
    return sorted(n for n, f in forms(secret).items() if f in blob)


def run(argv, env=None):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.dict(os.environ, env or {}), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli.main(argv)
        except SystemExit as e:
            rc = e.code
    return rc, out.getvalue(), err.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory(prefix="pqsec-")
        self.addCleanup(self.td.cleanup)
        self.d = self.td.name

    def file(self, name, data):
        p = os.path.join(self.d, name)
        with open(p, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())
        return p

    def none(self, what, *outputs):
        for c in CANARIES:
            self.assertEqual(found(c, *outputs), [], what)

    def refused(self, f, *a, **kw):
        """the texts of the exception f raises (with its causes), or a failure if it returns"""
        try:
            f(*a, **kw)
        except Exception as e:  # noqa: BLE001
            texts = []
            while e is not None:
                texts += [type(e).__name__, str(e), repr(e.args)]
                e = e.__cause__ or (None if e.__suppress_context__ else e.__context__)   # what a traceback shows
            return texts
        self.fail("accepted: %r" % (a,))


class TheSearchFinds(Base):
    def test_every_form(self):
        s = SEED
        for name, text in (("raw", b"x" + s), ("hex", s.hex().encode()), ("HEX", s.hex().upper().encode()),
                           ("decimal", str(int.from_bytes(s, "big")).encode()), ("base64+0", base64.b64encode(s)),
                           ("base64+1", base64.b64encode(b"{" + s)), ("base64+2", base64.b64encode(b"{{" + s)),
                           ("base64url+0", base64.urlsafe_b64encode(s)), ("base64url+1", base64.urlsafe_b64encode(b"a" + s)),
                           ("base64url+2", base64.urlsafe_b64encode(b"ab" + s))):
            self.assertIn(name, found(s, text), name)
        self.assertEqual(found(s, hashlib.sha256(s).hexdigest()), [])

    def test_a_producer_that_leaks_is_found(self):
        url = "https://u:%s@192.0.2.2/" % PASSWORD
        with mock.patch.object(kms, "_backend_url", lambda u, w, h=True: u), mock.patch.dict(os.environ, {"VAULT_TOKEN": "t"}):
            be = kms.backend_from_uri("vault:url=%s;key=k" % url)
        self.assertIn("raw", found(PASSWORD.encode(), json.dumps(be.describe())))
        with self.assertRaises(AssertionError):
            self.none("leak", json.dumps(be.describe()))
        with mock.patch.object(kms, "_net_reason", lambda e: str(e)), \
                mock.patch.object(kms, "_apri", side_effect=urllib.error.URLError("at " + url)):
            texts = self.refused(be._req, "GET", "x")
        with self.assertRaises(AssertionError):
            self.none("leak", *texts)


class BackendURLs(Base):
    URLS = ("https://u:%s@192.0.2.1/" % PASSWORD, "https://%s@192.0.2.1/" % PASSWORD, "HTTPS://u:%s@192.0.2.1" % PASSWORD,
            "https://%s:@192.0.2.1" % PASSWORD, "https://u:%s@[::1]:8200" % PASSWORD, "https://192.0.2.1/\\@" + PASSWORD,
            "https://192.0.2.1/ " + PASSWORD, "https://192.0.2.1/\x00" + PASSWORD, "https://192.0.2.1/é" + PASSWORD,
            "ftp://" + PASSWORD, PASSWORD, "https://192.0.2.1:99999/" + PASSWORD, "HTTP://192.0.2.1/" + PASSWORD)

    def test_every_backend_refuses_without_repeating(self):
        env = {"VAULT_TOKEN": "t", "NETHSM_PASS": "p", "AWS_ACCESS_KEY_ID": "a", "AWS_SECRET_ACCESS_KEY": "s"}
        for url in self.URLS:
            for uri in ("vault:url=%s;key=k" % url, "nethsm:url=%s;key=k;user=u" % url,
                        "awskms-http:key_id=k;region=eu-central-1;endpoint=%s" % url):
                with mock.patch.dict(os.environ, env), mock.patch.object(kms, "_apri") as net:
                    texts = self.refused(kms.backend_from_uri, uri)
                self.assertEqual(net.call_count, 0)
                self.none(uri, *texts)
                rc, out, err = run(["kms", "pubkey", "--backend", uri], env)
                self.assertEqual(rc, 1, uri)
                self.none(uri, out, err)

    def test_a_url_longer_than_2048_is_refused(self):
        with mock.patch.dict(os.environ, {"VAULT_TOKEN": "t"}):
            base = "https://192.0.2.1/"
            kms.backend_from_uri("vault:url=%s%s;key=k" % (base, "a" * (2048 - len(base))))
            texts = self.refused(kms.backend_from_uri, "vault:url=%s%s;key=k" % (base, "a" * (2049 - len(base))))
        self.assertIn("not repeated here", " ".join(texts))

    def test_plain_http_only_to_loopback(self):
        with mock.patch.dict(os.environ, {"VAULT_TOKEN": "t"}):
            self.assertEqual(kms.backend_from_uri("vault:url=http://127.0.0.1:8200;key=k").describe()["url"],
                             "http://127.0.0.1:8200")
            texts = self.refused(kms.backend_from_uri, "vault:url=HTTP://192.0.2.2;key=k")
        self.assertIn("plain http:// only to a loopback host", " ".join(texts))

    def test_a_network_error_says_its_kind(self):
        for e in (urllib.error.URLError(OSError(111, "refused " + PASSWORD)), urllib.error.URLError("x " + PASSWORD),
                  OSError(5, PASSWORD), ValueError(PASSWORD), TimeoutError(PASSWORD)):
            self.none(repr(e), kms._net_reason(e))
        self.assertEqual(kms._net_reason(urllib.error.URLError(ConnectionRefusedError(111, "x"))),
                         "URLError: ConnectionRefusedError [Errno 111]")
        with mock.patch.dict(os.environ, {"VAULT_TOKEN": "t", "NETHSM_PASS": "p", "AWS_ACCESS_KEY_ID": "a",
                                          "AWS_SECRET_ACCESS_KEY": "s"}):
            for be in (kms.backend_from_uri("awskms-http:key_id=k;region=eu-central-1;endpoint=http://127.0.0.1:1/" + PASSWORD),
                       kms.backend_from_uri("vault:url=http://127.0.0.1:1/%s;key=k;timeout=5" % PASSWORD),
                       kms.backend_from_uri("nethsm:url=http://127.0.0.1:1/%s;key=k;user=u" % PASSWORD)):
                with mock.patch.object(kms, "_apri", side_effect=urllib.error.URLError(
                        OSError(111, "http://127.0.0.1:1/" + PASSWORD))):
                    texts = self.refused(be.public_key_hex)
                self.none(be.name, *texts)
                self.assertIn("unreachable: URLError: ConnectionRefusedError [Errno 111]", " ".join(texts))

    def test_a_uri_segment_or_name_is_not_repeated(self):
        from pq_scitt.strict_json import nominabile     # the bound: 32 characters repeated, 33 named by their length
        for f in (kms._nameable, nominabile):
            self.assertEqual(f("a" * 32), repr("a" * 32))
            self.assertEqual(f("a" * 33), "(a name of 33 characters, not repeated)")
        for uri in ("vault:" + PASSWORD, "vault:url=https://192.0.2.1;" + PASSWORD, "vault:%s=1;url=https://192.0.2.1" % KEYNAME,
                    "vault:url=https://192.0.2.1;key=k;%s=1;%s=2" % (KEYNAME, KEYNAME), "vault:%s=" % KEYNAME,
                    # the secret itself where the NAME of its environment variable goes, or where the scheme, the
                    # timeout or the region go
                    "vault:url=https://192.0.2.1;key=k;token_env=" + PASSWORD, "nethsm:url=https://192.0.2.1;key=k;user=u;pass_env=" + PASSWORD,
                    "pkcs11:module=/m.so;token=t;key=k;pin=env:" + PASSWORD, "pkcs11:module=/m.so;token=t;key=k;pin=" + PASSWORD,
                    KEYNAME, KEYNAME + ":x", "vault:url=https://192.0.2.1;key=k;timeout=" + PASSWORD[:20],
                    "awskms-http:key_id=k;region=" + PASSWORD):
            with mock.patch.dict(os.environ, {"VAULT_TOKEN": "t", "AWS_ACCESS_KEY_ID": "a", "AWS_SECRET_ACCESS_KEY": "s"}), \
                    mock.patch.object(kms, "which_absolute", return_value="/usr/bin/pkcs11-tool"):
                texts = self.refused(kms.backend_from_uri, uri)
                self.none(uri, *texts)
                self.assertEqual(found(PASSWORD.encode()[:16], *texts), [], uri)     # nor a part of it
            rc, out, err = run(["kms", "pubkey", "--backend", uri], {"VAULT_TOKEN": "t"})
            self.assertEqual(rc, 1, uri)
            self.none(uri, out, err)
        self.assertIn("unknown backend scheme 'nope'", " ".join(self.refused(kms.backend_from_uri, "nope:x")))
        from pq_scitt.scitt import export as sx
        self.none("export scheme", *self.refused(sx.carica_firmatario, KEYNAME + ":x", -19))
        self.assertIn("key scheme not allowed: nope", self.refused(sx.carica_firmatario, "nope:x", -19))

    def test_a_name_given_twice_is_not_repeated(self):
        texts = self.refused(kms._parse_kv, "%s=1;%s=2" % (KEYNAME, KEYNAME))
        self.assertIn("backend URI: key (a name of 43 characters, not repeated) given twice", texts)
        self.assertIn("backend URI: key 'ab' given twice", self.refused(kms._parse_kv, "ab=1;ab=2"))

    def test_an_answer_is_read_up_to_a_bound(self):
        with mock.patch.dict(os.environ, {"VAULT_TOKEN": "t"}):
            be = kms.backend_from_uri("vault:url=http://127.0.0.1:1;key=k")

        class Big(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        with mock.patch.object(kms, "_apri", return_value=Big(b" " * (kms.MAX_RISPOSTA + 1))):
            self.assertIn("ValueError", " ".join(self.refused(be.public_key_hex)))
        self.a_redirect_to_another_origin_is_not_followed()

    def a_redirect_to_another_origin_is_not_followed(self):
        """urllib copies the headers of a request to the address a redirect names: the credential must not follow it to
        another scheme, host or port (a real server on loopback; the second one must see no request)."""
        import http.server
        import threading
        import time
        seen = []

        class H(http.server.BaseHTTPRequestHandler):
            def answer(self):
                self.rfile.read(int(self.headers.get("content-length") or 0))
                seen.append((self.server.server_address[1], self.path, " ".join(self.headers.values())))
                if self.path.endswith("/slow"):
                    time.sleep(3)
                if self.path.endswith("/same"):
                    body = b'{"data": {}}'
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:%d/same" % (
                    one.server_address[1] if self.path.endswith("/to-same") else two.server_address[1]))
                self.send_header("Content-Length", "0")
                self.end_headers()
            do_GET = do_POST = do_PUT = answer

            def log_message(self, *a):
                pass
        one, two = (http.server.HTTPServer(("127.0.0.1", 0), H) for _ in range(2))
        for s in (one, two):
            threading.Thread(target=s.serve_forever, daemon=True).start()
            self.addCleanup(s.server_close)
            self.addCleanup(s.shutdown)
        url = "http://127.0.0.1:%d" % one.server_address[1]
        env = {"VAULT_TOKEN": PASSWORD, "NETHSM_PASS": PASSWORD, "AWS_ACCESS_KEY_ID": "a", "AWS_SECRET_ACCESS_KEY": "s",
               "AWS_SESSION_TOKEN": PASSWORD}
        with mock.patch.dict(os.environ, env):
            for be in (kms.backend_from_uri("vault:url=%s;key=k;timeout=5" % url),
                       kms.backend_from_uri("nethsm:url=%s;key=k;user=u" % url),
                       kms.backend_from_uri("awskms-http:key_id=k;region=eu-central-1;endpoint=%s" % url)):
                del seen[:]
                texts = self.refused(be.public_key_hex)
                self.assertTrue(seen, be.name)
                self.assertEqual([s for s in seen if s[0] == two.server_address[1]], [], be.name)
                self.assertIn("HTTP 302", " ".join(texts), be.name)
            be = kms.backend_from_uri("vault:url=%s;key=k;timeout=5" % url)
            del seen[:]
            self.assertEqual(be._req("GET", "x/to-same"), {"data": {}})        # the same origin is still followed
            self.assertEqual([s[1] for s in seen], ["/v1/x/to-same", "/same"])
            be = kms.backend_from_uri("vault:url=%s;key=k;timeout=0.5" % url)       # the time limit of the URI still holds
            t0 = time.monotonic()
            self.assertIn("Vault unreachable: ", " ".join(self.refused(be._req, "GET", "x/slow")))
            self.assertLess(time.monotonic() - t0, 2.5)
        # the scheme counts too: https to http on the same host and port is a downgrade (NEMESIS 26/11/2026: a check of
        # host and port only passed the whole suite)
        import urllib.request
        handler, hdrs = kms._SameOrigin(), {}
        for old, new, followed in (("https://h.example/v1/x", "http://h.example/v1/x", False),
                                   ("https://h.example:8200/v1/x", "http://h.example:8200/v1/x", False),
                                   ("https://h.example/v1/x", "https://h.example/v1/y", True)):
            req = urllib.request.Request(old, headers={"X-Vault-Token": PASSWORD})
            self.assertEqual(handler.redirect_request(req, None, 302, "Found", hdrs, new) is not None, followed, new)


try:
    import cryptography  # noqa: F401
    CRYPTOGRAPHY = True
except ImportError:
    CRYPTOGRAPHY = False


class Keys(Base):
    @unittest.skipUnless(CRYPTOGRAPHY, "the file: backend needs cryptography")
    def test_a_file_key_is_never_repeated(self):
        for bad in (SEED.hex() + "0", b"\xff" + SEED, SEED, SEED.hex()[:-1] + "\xe9"):
            p = self.file("k", bad)
            be = kms.backend_from_uri("file:" + p)
            texts = self.refused(be.public_key_hex)
            self.assertIn("file: the key file is not one 32-byte hex line", texts)
            self.none("file key", *[t for t in texts])
            rc, out, err = run(["kms", "pubkey", "--backend", "file:" + p])
            self.assertEqual(rc, 1)
            self.none("file key cli", out, err)

    def test_strict_json_names_and_integers(self):
        for t in ('{"%s": 1, "%s": 2}' % (KEYNAME, KEYNAME),):
            e = self.refused(strict_json.loads, t)
            self.assertIn("membro_ripetuto: (a name of 43 characters, not repeated)", e)
            self.none("dup", *e)
        self.assertIn("membro_ripetuto: 'ab'", self.refused(strict_json.loads, '{"ab": 1, "ab": 2}'))
        self.assertEqual(strict_json.loads("[%s]" % ("9" * 4300)), [int("9" * 4300)])
        self.assertEqual(strict_json.loads("[-%s]" % ("9" * 4300)), [-int("9" * 4300)])
        for t in ("[%s]" % ("1" * 4301), "[-%s]" % ("1" * 4301), '{"a": %s}' % ("2" * 100000)):
            self.assertIn("non_json: an integer of more than 4300 digits", self.refused(strict_json.loads, t))
        e = self.refused(standalone._bounded_int, "1" * 5000)
        self.assertIn("an integer outside the portable range +/-(2**53-1)", e)
        self.assertNotIn("1" * 20, " ".join(e))


class HmacKey(Base):
    def ledger(self):
        p, prev = os.path.join(self.d, "ledger.jsonl"), "0" * 64
        with open(p, "w", encoding="utf-8") as f:
            for i in range(3):
                e = {"idx": i, "ts": "2026-11-08T12:00:0%dZ" % i, "data": {"n": i}, "prev_hash": prev}
                e["self_hash"] = prev = hashlib.sha256(json.dumps(e, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                f.write(json.dumps(e) + "\n")
        from pq_scitt.ledger import verify as lv
        return p, lv._tip_hmac(PASSWORD, 3, prev)

    def test_env_and_file_give_the_same_verdict(self):
        p, want = self.ledger()
        for argv, env in ((["--hmac-key-env", "PQ_TEST_HMAC"], {"PQ_TEST_HMAC": PASSWORD}),
                          (["--hmac-key-file", self.file("k", PASSWORD + "\n")], {}),
                          (["--hmac-key-file", self.file("k2", PASSWORD + "\r\n")], {}),
                          (["--hmac-key-file", self.file("k3", PASSWORD)], {})):
            out = self.file("r.json", "")
            rc, so, se = run(["verify-ledger", p, "--expect-hmac", want, "--out", out] + argv, env)
            self.assertEqual(rc, 0, se)
            self.assertEqual(json.loads(so)["verdict"], "PASS")
            with open(out, "rb") as f:
                self.none(argv[0], so, se, f.read())
            self.assertNotIn("deprecated", se)
        rc, so, se = run(["verify-ledger", p, "--expect-hmac", want, "--hmac-key-env", "PQ_TEST_HMAC"],
                         {"PQ_TEST_HMAC": "other"})
        self.assertEqual((rc, json.loads(so)["verdict"]), (1, "FAIL"))

    def test_argv_still_works_with_a_warning(self):
        p, want = self.ledger()
        rc, so, se = run(["verify-ledger", p, "--expect-hmac", want, "--hmac-key", PASSWORD])
        self.assertEqual(rc, 0)
        self.assertIn("--hmac-key is deprecated", se)
        self.none("argv", so, se)

    def test_usage_errors_name_the_option_not_the_key(self):
        p, want = self.ledger()
        k = self.file("k", PASSWORD)
        empty = self.file("e", "")
        named = "K" + SEED.hex()[:40]          # a key that is also a possible variable name
        for argv, env in ((["--hmac-key", PASSWORD, "--hmac-key-file", k], {}), (["--hmac-key-env", "PQ_ABSENT_X"], {}), (["--hmac-key-env", "PQ_EMPTY_X"], {"PQ_EMPTY_X": ""}),
                          (["--hmac-key-env", named], {}), (["--hmac-key-file", k, "--hmac-key-file", k], {}),
                          (["--hmac-key", PASSWORD, "--hmac-key", PASSWORD], {}),
                          (["--hmac-key-env", "PQ_TWICE_X", "--hmac-key-env", "PQ_TWICE_X"], {"PQ_TWICE_X": PASSWORD}),
                          (["--hmac-key-env", PASSWORD + "-"], {}), (["--hmac-key-file", os.path.join(self.d, "no")], {}),
                          (["--hmac-key-file", empty], {}), (["--hmac-key-file", self.d], {})):
            rc, so, se = run(["verify-ledger", p, "--expect-hmac", want] + argv, env)
            self.assertEqual(rc, 2, argv)
            self.none(argv, so, se)
            self.assertNotIn(named, so + se, argv)


class Programs(Base):
    def test_pkcs11_tool_by_absolute_path_and_the_pin_only_where_it_logs_in(self):
        tool = os.path.join(self.d, "pkcs11-tool")
        seen = []
        with mock.patch.object(kms, "which_absolute", return_value=tool), \
                mock.patch.dict(os.environ, {"PQ_TEST_PIN": PASSWORD}):
            be = kms.Pkcs11Backend("/m.so", "t", "k", pin="env:PQ_TEST_PIN")
            with mock.patch.object(kms.subprocess, "run",
                                   lambda cmd, **kw: seen.append((cmd, kw.get("env"))) or
                                   subprocess.CompletedProcess(cmd, 0, b"", b"")):
                be._run(["--list-objects"], login=True)
                be._run(["--list-token-slots"], login=False)
            self.assertEqual(kms._env_without("PQ_TEST_PIN").get("PQ_TEST_PIN"), None)
        self.assertEqual([c[0][0] for c in seen], [tool, tool])
        self.assertEqual(seen[0][1].get("PQ_TEST_PIN"), PASSWORD)
        self.assertNotIn("PQ_TEST_PIN", seen[1][1])
        self.none("argv", *[" ".join(c[0]) for c in seen])
        named = "K" + SEED.hex()[:40]          # the variable is unset at the time of the signature: its name is not repeated
        with mock.patch.object(kms, "which_absolute", return_value=tool):
            with mock.patch.dict(os.environ, {named: "1234"}):
                be = kms.Pkcs11Backend("/m.so", "t", "k", pin="env:" + named)
            self.assertNotIn(named, " ".join(self.refused(be.sign, b"m")))

    def test_the_pkcs11_child_has_no_pin_in_its_environment(self):
        started = []

        class P:
            def __init__(self, cmd, **kw):
                started.append(kw.get("env"))
                raise OSError("stop")
        f = kms._Pkcs11Figlio(5, "PQ_TEST_PIN")
        with mock.patch.dict(os.environ, {"PQ_TEST_PIN": PASSWORD}), mock.patch.object(kms.subprocess, "Popen", P):
            self.refused(f._avvia)
        self.assertEqual(len(started), 1)
        self.assertIsNotNone(started[0])
        self.assertNotIn("PQ_TEST_PIN", started[0])
        self.none("child env", json.dumps(started[0]))
        if os.name != "nt":     # POSIX: a variable whose bytes are not UTF-8 (Windows' environment is UTF-16)
            self.the_pin_goes_as_the_bytes_of_the_environment()

    def the_pin_goes_as_the_bytes_of_the_environment(self):
        """A PIN that is not UTF-8 reached the child as text and str.encode() named one of its characters and where it
        stands; it goes as the bytes pkcs11-tool reads, and the child answers about the module, not about the PIN."""
        pin = b"Pi\xe9" + PASSWORD.encode()
        sent = []

        class F:
            def chiama(self, richiesta, cosa):
                sent.append(richiesta)
                return b"s" * 64
        with mock.patch.object(kms, "which_absolute", return_value="/usr/bin/pkcs11-tool"), \
                mock.patch.dict(os.environb, {b"PQ_TEST_PIN": pin}):
            be = kms.Pkcs11Backend("/no/such/module.so", "t", "k", pin="env:PQ_TEST_PIN")
            real, be._figlio = be._figlio, F()
            be.sign(b"m")
            self.assertEqual(bytes.fromhex(sent[0]["pin"]), pin)
            be._figlio = real
            texts = self.refused(be.sign, b"m")
        self.assertNotIn("Unicode", " ".join(texts))
        self.assertNotIn("position", " ".join(texts))
        self.assertIn("cannot be loaded", " ".join(texts))
        # the child gives the module those same bytes (a module replaced by one that answers with the PIN it got)
        code = ("from pq_scitt import kms\nkms._p11_sign_direct = lambda module, token, key, pin, msg: pin\n"
                "kms._p11_lavoratore()\n")
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=120,
                           input=json.dumps(dict(sent[0], op="sign")).encode() + b"\n")
        self.assertEqual(bytes.fromhex(json.loads(r.stdout)["ok"]), pin, r.stderr[-300:])

    def test_no_program_by_bare_name_no_tempfile(self):
        bad = re.compile(r"shutil\.which\(|tempfile\.mk[sd]temp|NamedTemporaryFile\(|TemporaryDirectory\(|"
                         r"\[\s*\"pkcs11-tool\"")
        root = os.path.dirname(os.path.abspath(kms.__file__))
        hits = []
        for base, dirs, files in os.walk(root):
            dirs[:] = [x for x in dirs if x not in ("_nucleo", "__pycache__")]
            for n in files:
                if n.endswith(".py"):
                    with open(os.path.join(base, n), encoding="utf-8") as fh:
                        hits += ["%s:%d" % (n, i) for i, line in enumerate(fh, 1) if bad.search(line.split("#")[0])]
        self.assertEqual(hits, [])

    def test_reads_in_pieces(self):
        asked = []

        class F(io.BytesIO):
            def read(self, n=-1):
                asked.append(n)
                return super().read(min(n, 3) if n > 0 else n)
        self.assertEqual(strict_json.leggi_a_pezzi(F(b"y" * 10), 4), b"yyyyy")
        self.assertEqual(strict_json.leggi_a_pezzi(F(b"y" * 4), 4), b"yyyy")
        self.assertEqual(strict_json.leggi_a_pezzi(F(b"x"), 1 << 28), b"x")
        self.assertTrue(max(asked) <= 1 << 20, asked)

    @unittest.skipUnless(sys.platform.startswith("linux"), "RLIMIT_DATA is enforced by Linux (macOS ignores it; Windows "
                         "has none): the reads in pieces are proved everywhere by test_reads_in_pieces")
    def test_a_one_byte_ledger_under_a_data_limit(self):
        p = self.file("l.jsonl", "\n")
        code = ("import resource;resource.setrlimit(resource.RLIMIT_DATA,(80000*1024,80000*1024));"
                "from pq_scitt import strict_json;print(strict_json.leggi_file(%r))" % p)
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=120)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, b"b'\\n'"), r.stderr[-400:])


if __name__ == "__main__":
    unittest.main()
