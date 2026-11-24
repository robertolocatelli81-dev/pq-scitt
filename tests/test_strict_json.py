"""pq_scitt.strict_json: each refusal listed in the README comes with its named reason, valid JSON is accepted, the
depth limit is exact, and a generative run of random mutations never raises anything but StrictJSONError."""
import errno
import os
import random
import unittest

from pq_scitt import strict_json as sj


class TestStrictJSON(unittest.TestCase):
    def _rifiuta(self, dati, motivo):
        with self.assertRaises(sj.StrictJSONError) as c:
            sj.loads(dati)
        self.assertEqual(c.exception.motivo, motivo, repr(dati)[:60])
        self.assertIn(motivo, sj.MOTIVI)

    def test_valid_json_accepted(self):   # positive control: the refusals below are not a reader that refuses everything
        self.assertEqual(sj.loads(b'{"a": [1, 2.5, "x", null, true], "b": {"c": -3}}'),
                         {"a": [1, 2.5, "x", None, True], "b": {"c": -3}})
        self.assertEqual(sj.loads('"\\ud83d\\ude00"'), "\U0001F600")   # a surrogate PAIR is fine

    def test_readme_refusals(self):
        casi = [
            (b'{"a": 1, "a": 2}', "membro_ripetuto"),
            (b'{"a": NaN}', "costante_non_json"),
            (b'[Infinity]', "costante_non_json"),
            (b'[-Infinity]', "costante_non_json"),
            (b'[1e400]', "numero_non_finito"),
            (b'\xef\xbb\xbf{}', "bom"),
            ('﻿{}', "bom"),
            (b'"\\ud800"', "surrogato_solitario"),
            (b'["\xff"]', "non_utf8"),
            (b'{"a": }', "non_json"),
            (12, "tipo_ingresso"),
        ]
        for dati, motivo in casi:
            with self.subTest(dati=dati):
                self._rifiuta(dati, motivo)

    def test_depth_limit_exact(self):
        self.assertEqual(sj.loads("[" * 128 + "]" * 128), sj.loads("[" * 128 + "]" * 128))
        self._rifiuta("[" * 129 + "]" * 129, "troppo_profondo")
        self._rifiuta('{"a":' * 129 + "1" + "}" * 129, "troppo_profondo")

    def test_generative_only_named_refusals(self):
        rnd = random.Random(20261108)
        base = b'{"idx": 0, "data": {"n": [1, 2.5, "\\u00e8", null]}, "prev_hash": "00"}'
        for _ in range(4000):
            m = bytearray(base)
            for _ in range(rnd.randint(1, 4)):
                op, i = rnd.randrange(3), rnd.randrange(len(m) + 1)
                if op == 0 and i < len(m):
                    m[i] = rnd.randrange(256)
                elif op == 1:
                    m[i:i] = bytes([rnd.randrange(256)])
                elif i < len(m):
                    del m[i]
            try:
                sj.loads(bytes(m))
            except sj.StrictJSONError as e:
                self.assertIn(e.motivo, sj.MOTIVI)


class TestCaccia20261124(unittest.TestCase):
    def test_stringa_non_chiusa_lineare(self):
        """The depth pre-scan restarted at every later quote of an unterminated string: 80 KB of \\" took 48 s."""
        import time
        testo = '"' + '\\"' * 20000 + "[" * 200
        t0 = time.perf_counter()
        with self.assertRaises(sj.StrictJSONError) as c:
            sj.loads(testo)
        self.assertLess(time.perf_counter() - t0, 1.5)
        self.assertEqual(c.exception.motivo, "non_json")        # the brackets are inside the string, not depth
        with self.assertRaises(sj.StrictJSONError) as c:          # positive control: real depth still counted
            sj.loads('["\\"",' + "[" * 200 + "]" * 200 + "]")
        self.assertEqual(c.exception.motivo, "troppo_profondo")

    def test_leggi_file_solo_regolare_e_limitato(self):
        import shutil
        import tempfile
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        fifo, buono = os.path.join(d, "f"), os.path.join(d, "l.jsonl")
        speciali = [d]                                    # a FIFO and /dev/zero only where the platform has them
        if hasattr(os, "mkfifo"):
            os.mkfifo(fifo)
            speciali.append(fifo)
        if os.path.exists("/dev/zero"):
            speciali.append("/dev/zero")
        with open(buono, "wb") as f:
            f.write(b'{"a":1}\n\n{"b":2}\n')
        import subprocess
        import sys
        try:
            import resource
        except ImportError:   # Windows
            resource = None

        def limite():   # 1 GiB: on the old code /dev/zero is read whole; in a child, so a FIFO cannot block the suite
            try:
                resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
            except (ValueError, OSError):   # macOS may refuse it: the fixed code does not need it
                pass
        codice = ("import sys\nfrom pq_scitt import strict_json as sj\ntry:\n sj.load_jsonl(sys.argv[1])\n"
                  "except OSError as e:\n print('OSError', e.errno)")
        for p in speciali:
            try:
                r = subprocess.run([sys.executable, "-B", "-c", codice, p], capture_output=True, text=True, timeout=30,
                                   preexec_fn=limite if resource else None)
            except subprocess.TimeoutExpired:
                self.fail("load_jsonl(%r) blocked" % p)
            # a directory: EINVAL where it can be opened (Linux, macOS), EACCES where it cannot (Windows)
            atteso = {errno.EINVAL} if p != d else {errno.EINVAL, errno.EACCES}
            self.assertEqual(r.returncode, 0, (p, r.stderr[-200:]))
            self.assertIn(r.stdout, {"OSError %d\n" % x for x in atteso}, (p, r.stdout, r.stderr[-200:]))
        with self.assertRaises(OSError) as c:
            sj.leggi_file(buono, 3)
        self.assertEqual(c.exception.errno, errno.EFBIG)
        self.assertEqual(sj.load_jsonl(buono), [{"a": 1}, {"b": 2}])   # positive control

if __name__ == "__main__":
    unittest.main()
