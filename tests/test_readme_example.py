"""Package tests: the README example really runs, and the out-of-band anchors of verify_ledger do what the README
says (a re-wired chain passes the chain-only check and fails with --expect-tip, --expect-count or HMAC)."""
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

RADICE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _esempio():
    with open(os.path.join(RADICE, "README.md"), encoding="utf-8") as f:
        testo = f.read()
    m = re.search(r"<!-- esempio:inizio -->\n```sh\n(.*?)```\n<!-- esempio:fine -->", testo, re.S)
    if not m:
        raise AssertionError("example block not found in the README")
    return m.group(1)


def _ambiente():
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
    env["PATH"] = os.path.dirname(sys.executable) + os.pathsep + env.get("PATH", "")
    return env


def _catena(n, prev="0" * 64, inizio=0):
    righe = []
    for i in range(inizio, inizio + n):
        e = {"idx": i, "ts": "2026-11-08T12:00:%02dZ" % i, "data": {"n": i}, "prev_hash": prev}
        e["self_hash"] = prev = hashlib.sha256(json.dumps(e, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        righe.append(e)
    return righe


def _scrivi(d, nome, righe):
    p = os.path.join(d, nome)
    with open(p, "w", encoding="utf-8") as f:
        for r in righe:
            f.write(json.dumps(r) + "\n")
    return p


def _verifica(*argv):
    r = subprocess.run([sys.executable, "-B", "-m", "pq_scitt", "verify-ledger", *argv], capture_output=True, text=True,
                       env=_ambiente(), cwd=RADICE, timeout=120)
    return r.returncode, r.stdout


class TestEsempioReadme(unittest.TestCase):
    def test_righe(self):
        self.assertLessEqual(len(_esempio().strip().splitlines()), 10)

    def test_file_esempio_generato(self):
        """examples/ledger.jsonl is byte for byte the 3-entry ledger that _catena() generates, and it verifies."""
        with open(os.path.join(RADICE, "examples", "ledger.jsonl"), encoding="utf-8") as f:
            self.assertEqual(f.read(), "".join(json.dumps(r) + "\n" for r in _catena(3)))
        self.assertEqual(_verifica(os.path.join("examples", "ledger.jsonl"))[0], 0)

    def _esegui(self, blocco, altera=None):
        """Runs the block with POSIX sh -e in a fresh folder holding a copy of examples/ledger.jsonl."""
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, "examples"))
            with open(os.path.join(RADICE, "examples", "ledger.jsonl"), encoding="utf-8") as f:
                righe = f.read()
            if altera:
                righe = altera(righe)
            with open(os.path.join(d, "examples", "ledger.jsonl"), "w", encoding="utf-8") as f:
                f.write(righe)
            return subprocess.run(["sh", "-e", "-c", blocco], cwd=d, env=_ambiente(), capture_output=True, text=True,
                                  timeout=300)

    def test_esempio_gira(self):
        r = self._esegui(_esempio())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('"verdict": "PASS"', r.stdout)
        self.assertRegex(r.stdout, r"exported 4 Transparent Statements, root [0-9a-f]{64}")
        self.assertRegex(r.stdout, r"\nOK 4 leaves, root [0-9a-f]{64}")

    def test_esempio_con_riga_alterata_fallisce(self):
        """Positive control: the same block on the ledger with one entry changed must fail at verify-ledger."""
        alterata = lambda t: t.replace('"n": 1}', '"n": 7}', 1)  # noqa: E731
        self.assertNotEqual(alterata("x" + '"n": 1}'), "x" + '"n": 1}')
        r = self._esegui(_esempio(), alterata)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('"verdict": "FAIL"', r.stdout)

    def test_esempio_con_chiave_sbagliata_fallisce(self):
        """Positive control: the same block with the policy key passed as the TS key must fail at verify."""
        alterato = _esempio().replace('--ts-pub "$TS"', '--ts-pub "$POL"', 1)
        self.assertNotEqual(alterato, _esempio())
        r = self._esegui(alterato)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('"verdict": "PASS"', r.stdout)
        self.assertNotRegex(r.stdout, r"\nOK 4 leaves")


class TestAncoreFuoriBanda(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.vera = _catena(5)
        self.p = _scrivi(self.d, "vera.jsonl", self.vera)
        self.tip = self.vera[-1]["self_hash"]
        # forgery: line 2 changed and chain recomputed from there on
        prev, ricablata = self.vera[1]["self_hash"], list(self.vera[:2])
        for i in range(2, 5):
            r = {"idx": i, "ts": self.vera[i]["ts"], "data": {"n": 999 if i == 2 else i}, "prev_hash": prev}
            r["self_hash"] = prev = hashlib.sha256(json.dumps(r, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            ricablata.append(r)
        self.ricablata = _scrivi(self.d, "ricablata.jsonl", ricablata)
        self.troncata = _scrivi(self.d, "troncata.jsonl", self.vera[:3])

    def tearDown(self):
        for n in os.listdir(self.d):
            os.unlink(os.path.join(self.d, n))
        os.rmdir(self.d)

    def test_catena_ricablata_passa_la_sola_catena(self):
        self.assertEqual(_verifica(self.ricablata)[0], 0)

    def test_expect_tip(self):
        self.assertEqual(_verifica(self.p, "--expect-tip", self.tip)[0], 0)
        self.assertNotEqual(_verifica(self.ricablata, "--expect-tip", self.tip)[0], 0)

    def test_expect_count(self):
        self.assertEqual(_verifica(self.p, "--expect-count", "5")[0], 0)
        self.assertEqual(_verifica(self.troncata)[0], 0)
        self.assertNotEqual(_verifica(self.troncata, "--expect-count", "5")[0], 0)

    def test_hmac(self):
        chiave = "chiave-di-prova"
        atteso = hmac.new(chiave.encode(), ("5:" + self.tip).encode(), hashlib.sha256).hexdigest()
        self.assertEqual(_verifica(self.p, "--hmac-key", chiave, "--expect-hmac", atteso)[0], 0)
        self.assertNotEqual(_verifica(self.ricablata, "--hmac-key", chiave, "--expect-hmac", atteso)[0], 0)
        self.assertNotEqual(_verifica(self.p, "--hmac-key", "altra", "--expect-hmac", atteso)[0], 0)


if __name__ == "__main__":
    unittest.main()
