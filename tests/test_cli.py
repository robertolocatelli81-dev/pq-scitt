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


if __name__ == "__main__":
    unittest.main()
