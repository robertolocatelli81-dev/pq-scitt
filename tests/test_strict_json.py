"""pq_scitt.strict_json: each refusal listed in the README comes with its named reason, valid JSON is accepted, the
depth limit is exact, and a generative run of random mutations never raises anything but StrictJSONError."""
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


if __name__ == "__main__":
    unittest.main()
