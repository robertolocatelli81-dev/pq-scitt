"""pq-scitt command line (pq_scitt/cli.py): dispatch, usage errors, version, and the installed entry points."""
import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import sysconfig
import tempfile
import unittest
from importlib import metadata
from unittest import mock

import pq_scitt
from pq_scitt import cli, kms
from pq_scitt.anchors import slh_dsa
from pq_scitt.ledger import standalone
from pq_scitt.ledger import verify as ledger_verify
from pq_scitt.scitt import export, verify


def _esegui(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = cli.main(argv)
    return rc, out.getvalue(), err.getvalue()


def _registro(d, n=3, altera=False):
    p, prev = os.path.join(d, "ledger.jsonl"), "0" * 64
    with open(p, "w", encoding="utf-8") as f:
        for i in range(n):
            e = {"idx": i, "ts": "2026-11-08T12:00:0%dZ" % i, "data": {"n": i}, "prev_hash": prev}
            e["self_hash"] = prev = hashlib.sha256(json.dumps(e, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if altera and i == 1:
                e["data"] = {"n": 7}
            f.write(json.dumps(e) + "\n")
    return p


class TestSmistamento(unittest.TestCase):
    CASI = [("export", export, "_main"), ("verify", verify, "_main"), ("verify-ledger", ledger_verify, "main"),
            ("verify-ledger-standalone", standalone, "main"), ("kms", kms, "main")]

    def test_ogni_sottocomando_chiama_la_sua_funzione_con_il_resto(self):
        for nome, modulo, funzione in self.CASI:
            with self.subTest(nome), mock.patch.object(modulo, funzione, return_value=37) as f:
                self.assertEqual(cli.main([nome, "a", "--b", "c"]), 37)
                f.assert_called_once_with(["a", "--b", "c"])

    def test_elenco_chiuso(self):
        self.assertEqual(sorted(cli.COMANDI), sorted([c[0] for c in self.CASI] + ["anchor-selftest"]))

    def test_anchor_selftest(self):
        with mock.patch.object(slh_dsa, "self_test", return_value=True) as f:
            self.assertEqual(cli.main(["anchor-selftest"]), 0)
            f.assert_called_once_with()
        with mock.patch.object(slh_dsa, "self_test", return_value=False):
            self.assertEqual(cli.main(["anchor-selftest"]), 1)
        with mock.patch.object(slh_dsa, "self_test", return_value=True) as f:
            rc, out, err = _esegui(["anchor-selftest", "x"])
            self.assertEqual(rc, 2)
            self.assertIn("no arguments", err)
            f.assert_not_called()

    def test_argv_none_legge_sys_argv(self):
        with mock.patch.object(sys, "argv", ["pq-scitt", "verify-ledger", "x.jsonl"]), \
                mock.patch.object(ledger_verify, "main", return_value=5) as f:
            self.assertEqual(cli.main(), 5)
            f.assert_called_once_with(["x.jsonl"])


class TestUso(unittest.TestCase):
    def test_senza_argomenti(self):
        rc, out, err = _esegui([])
        self.assertEqual((rc, out), (2, ""))
        self.assertTrue(err.startswith("usage: pq-scitt {export,verify,"))

    def test_help(self):
        for a in ("--help", "-h"):
            rc, out, err = _esegui([a])
            self.assertEqual((rc, err), (0, ""))
            self.assertIn("verify-ledger-standalone", out)
            self.assertIn("unknown subcommand is an", out)

    def test_versione(self):
        rc, out, err = _esegui(["--version"])
        self.assertEqual((rc, out, err), (0, "pq-scitt %s\n" % pq_scitt.__version__, ""))
        self.assertEqual(metadata.version("pq-scitt"), pq_scitt.__version__)

    def test_sconosciuto(self):
        for argv in (["verifica"], ["--help", "x"], ["--version", "x"], ["-v"], [""], ["EXPORT"], ["Verify"], ["--export"],
                     ["-kms"], ["export-"], [" export"]):
            with self.subTest(argv):
                rc, out, err = _esegui(argv)
                self.assertEqual((rc, out), (2, ""))
                self.assertIn("unknown subcommand %r" % argv[0], err)


class TestDacapoAFondo(unittest.TestCase):
    def test_verify_ledger_e_standalone(self):
        with tempfile.TemporaryDirectory() as d:
            buono = _registro(d)
            for sub in ("verify-ledger", "verify-ledger-standalone"):
                with self.subTest(sub):
                    rc, out, _ = _esegui([sub, buono, "--quiet"])
                    self.assertEqual((rc, out.strip()), (0, "PASS"))
            os.unlink(buono)
            cattivo = _registro(d, altera=True)
            for sub in ("verify-ledger", "verify-ledger-standalone"):
                with self.subTest(sub):
                    rc, out, _ = _esegui([sub, cattivo, "--quiet"])
                    self.assertEqual((rc, out.strip()), (1, "FAIL"))

    def test_kms_senza_comando(self):
        rc, out, _ = _esegui(["kms"])
        self.assertEqual(rc, 2)
        self.assertIn("pq-scitt kms", out)

    def test_usage_nomina_il_sottocomando(self):
        """The usage of every argparse subcommand can be copied and rerun: it starts with "pq-scitt <subcommand>"."""
        for sub in ("export", "verify", "verify-ledger", "verify-ledger-standalone", "kms"):
            with self.subTest(sub):
                out = io.StringIO()
                with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as uscita:
                    cli.main([sub, "--help"])
                self.assertEqual(uscita.exception.code, 0)
                self.assertTrue(out.getvalue().startswith("usage: pq-scitt %s " % sub), out.getvalue()[:80])


class TestPuntiDiIngresso(unittest.TestCase):
    def _env(self):
        return {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}

    def test_script_installato(self):
        exe = os.path.join(sysconfig.get_path("scripts"), "pq-scitt")
        self.assertTrue(os.path.isfile(exe), exe)
        r = subprocess.run([exe, "--version"], capture_output=True, text=True, env=self._env(), timeout=60)
        self.assertEqual((r.returncode, r.stdout), (0, "pq-scitt %s\n" % pq_scitt.__version__))
        r = subprocess.run([exe, "nessuno"], capture_output=True, text=True, env=self._env(), timeout=60)
        self.assertEqual(r.returncode, 2)

    def test_python_m(self):
        r = subprocess.run([sys.executable, "-B", "-m", "pq_scitt", "--version"], capture_output=True, text=True,
                           env=self._env(), timeout=60)
        self.assertEqual((r.returncode, r.stdout), (0, "pq-scitt %s\n" % pq_scitt.__version__))
        r = subprocess.run([sys.executable, "-B", "-m", "pq_scitt"], capture_output=True, text=True, env=self._env(),
                           timeout=60)
        self.assertEqual(r.returncode, 2)


class TestCacciaInputSpeciali(unittest.TestCase):
    """caccia 24/11/2026: a FIFO blocked every reader of a ledger, /dev/zero exhausted the memory, a directory or a
    non-UTF-8 name was a traceback. Each command must answer with a refusal, in bounded time and memory."""

    def _cli(self, *argv, env=None):
        import resource
        def limite():   # 1 GiB of address space: /dev/zero read whole fails fast instead of taking the machine
            resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
        e = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
        e.update(env or {})
        try:
            r = subprocess.run([sys.executable, "-B", "-m", "pq_scitt"] + list(argv), capture_output=True, timeout=30,
                               env=e, preexec_fn=limite)
        except subprocess.TimeoutExpired:
            self.fail("%s blocked (30 s)" % (argv,))
        self.assertNotIn(b"Traceback", r.stderr, (argv, r.stderr[-300:]))
        return r

    def test_fifo_zero_cartella(self):
        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d, True)
        fifo, buono = os.path.join(d, "fifo"), _registro(d)
        os.mkfifo(fifo)
        for p in (fifo, "/dev/zero", d):
            with self.subTest(p):
                for sub in ("verify-ledger", "verify-ledger-standalone"):
                    r = self._cli(sub, p)
                    self.assertEqual(r.returncode, 1)
                    self.assertIn(b'"verdict": "FAIL"', r.stdout)
                r = self._cli("verify-ledger", buono, "--checkpoint", p, "--checkpoint-pubkey", "00" * 32)
                self.assertEqual(r.returncode, 1)
                self.assertIn(b"checkpoint unreadable", r.stdout)
                r = self._cli("export", p, os.path.join(d, "u"), "--nome", "x", "--payload", "chiaro", "--effimere")
                self.assertEqual(r.returncode, 1)
                self.assertIn(b"REFUSED ledger not readable", r.stdout)
                r = self._cli("verify", d, "--alg", "-19", "--ts-pub", "00", "--politica-pub", "00",
                              "--registro", p, "--sali", buono)
                self.assertEqual(r.returncode, 1)
                self.assertIn(b"REFUSED impegno_non_valido", r.stdout)
                r = self._cli("kms", "pubkey", "--backend", "file:" + p)
                self.assertEqual(r.returncode, 1)
                self.assertIn(b"REFUSED", r.stderr)
        r = self._cli("verify-ledger", buono)               # positive control: the same commands still read a ledger
        self.assertEqual(r.returncode, 0)

    def test_nome_non_utf8_nel_rifiuto(self):
        """A refusal that names a non-UTF-8 file or argument (surrogateescape) is written, not a UnicodeEncodeError."""
        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d, True)
        os.mkdir(os.path.join(os.fsencode(d), b"ts_\xff.cose"))   # first leaf, not a regular file: named in the refusal
        uscita = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")   # errors="strict", as in a UTF-8 locale
        with contextlib.redirect_stdout(uscita):
            rc1 = verify._main([d, "--alg", "-19", "--ts-pub", "00" * 32, "--politica-pub", "11" * 32])
            rc2 = export._main([_registro(d), os.path.join(d, "u"), "--nome", "x", "--payload", "chiaro",
                                "--versione", "1", "--chiave-issuer", "\udcff:x", "--chiave-ts", "file:a",
                                "--chiave-politica", "file:b"])
        uscita.flush()
        testo = uscita.buffer.getvalue().decode("utf-8")
        self.assertEqual((rc1, rc2), (1, 1))
        self.assertIn("REFUSED forma_cose ts_\\udcff.cose: not a regular file", testo)
        self.assertIn("key scheme not allowed: \\udcff", testo)

    def test_ancora_hmac_e_out(self):
        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d, True)
        p = _registro(d)
        for argv in (["--expect-hmac", "é", "--hmac-key", "k"], ["--expect-hmac", "aa", "--hmac-key", "\udcff"]):
            rc, out, err = _esegui(["verify-ledger", p] + argv)
            self.assertEqual(rc, 1, argv)
            self.assertIn("tip HMAC does not match", out)
        rc, out, err = _esegui(["verify-ledger", p, "--out", d])         # --out is a directory
        self.assertEqual(rc, 1)
        self.assertIn("receipt not written to --out: IsADirectoryError", err)
        rc, out, err = _esegui(["verify-ledger", p, "--out", os.path.join(d, "r.json")])   # positive control
        self.assertEqual(rc, 0)

if __name__ == "__main__":
    unittest.main()
