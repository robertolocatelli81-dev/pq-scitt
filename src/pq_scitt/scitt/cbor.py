#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pq_scitt/scitt/cbor.py — deterministic CBOR (RFC 8949 §4.2.1) for profile omega-scitt/1 (08/11/2026, stdlib only).

Used by pq_scitt/scitt/export.py (writes) and pq_scitt/scitt/verify.py (reads). CLOSED subset of CBOR, written
before the code:
  - allowed types: integers (major 0 and 1), byte string, UTF-8 text string, array, map, tag 18 (COSE_Sign1),
    false / true / null. Nothing else: no floats, undefined, unknown simple values, other tags, indefinite lengths;
  - integers and lengths in the shortest form; map keys int or tstr, unique, in bytewise order of their encoding;
  - no trailing bytes; depth and sizes are limited.
Anything outside these rules = CBORError with a `motivo` from the MOTIVI list. On bytes inputs it raises nothing else.
"""
from __future__ import annotations

from typing import Any, NamedTuple

MAX_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 16
MAX_ITEMS = 1 << 16
TAG_COSE_SIGN1 = 18

MOTIVI = ("cbor_tipo_ingresso", "cbor_troppo_lungo", "cbor_troncato", "cbor_byte_in_coda", "cbor_non_minimo",
          "cbor_indefinito", "cbor_float_o_simple", "cbor_tag_ignoto", "cbor_chiave_tipo", "cbor_chiave_ripetuta",
          "cbor_chiavi_non_ordinate", "cbor_utf8", "cbor_troppo_profondo", "cbor_troppi_elementi",
          "cbor_info_riservata", "cbor_tipo_non_codificabile")


class CBORError(ValueError):
    def __init__(self, motivo: str, dettaglio: str = ""):
        assert motivo in MOTIVI, motivo
        super().__init__(motivo + (": " + dettaglio if dettaglio else ""))
        self.motivo = motivo
        self.dettaglio = dettaglio


class Tag(NamedTuple):
    tag: int
    value: Any


# ------------------------------------------------------------------ writing

def _testa(maggiore: int, n: int) -> bytes:
    if n < 24:
        return bytes([(maggiore << 5) | n])
    for info, larghezza in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < (1 << (8 * larghezza)):
            return bytes([(maggiore << 5) | info]) + n.to_bytes(larghezza, "big")
    raise CBORError("cbor_tipo_non_codificabile", "integer beyond 64 bits")


def dumps(v: Any) -> bytes:
    """Deterministic encoding. Only the types of the subset; anything else = CBORError."""
    if v is False:
        return b"\xf4"
    if v is True:
        return b"\xf5"
    if v is None:
        return b"\xf6"
    if type(v) is int:
        return _testa(0, v) if v >= 0 else _testa(1, -1 - v)
    if isinstance(v, (bytes, bytearray)):
        return _testa(2, len(v)) + bytes(v)
    if type(v) is str:
        b = v.encode("utf-8")
        return _testa(3, len(b)) + b
    if isinstance(v, Tag):
        if v.tag != TAG_COSE_SIGN1:
            raise CBORError("cbor_tag_ignoto", str(v.tag))
        return _testa(6, v.tag) + dumps(v.value)
    if isinstance(v, (list, tuple)):
        return _testa(4, len(v)) + b"".join(dumps(x) for x in v)
    if isinstance(v, dict):
        coppie = []
        for k, x in v.items():
            if type(k) not in (int, str):
                raise CBORError("cbor_chiave_tipo", type(k).__name__)
            coppie.append((dumps(k), dumps(x)))
        coppie.sort(key=lambda c: c[0])
        for a, b in zip(coppie, coppie[1:]):
            if a[0] == b[0]:
                raise CBORError("cbor_chiave_ripetuta")
        return _testa(5, len(coppie)) + b"".join(k + x for k, x in coppie)
    raise CBORError("cbor_tipo_non_codificabile", type(v).__name__)


# ------------------------------------------------------------------ reading

class _Lettore:
    def __init__(self, dati: bytes):
        self.d = dati
        self.i = 0

    def _prendi(self, n: int) -> bytes:
        if n < 0 or self.i + n > len(self.d):
            raise CBORError("cbor_troncato")
        b = self.d[self.i:self.i + n]
        self.i += n
        return b

    def _argomento(self, info: int) -> int:
        if info < 24:
            return info
        if info == 31:
            raise CBORError("cbor_indefinito")
        if info > 27:
            raise CBORError("cbor_info_riservata", str(info))
        larghezza = 1 << (info - 24)
        n = int.from_bytes(self._prendi(larghezza), "big")
        minimo = 24 if larghezza == 1 else 1 << (8 * (larghezza >> 1))
        if n < minimo:
            raise CBORError("cbor_non_minimo")
        return n

    def elemento(self, profondita: int) -> Any:
        if profondita > MAX_DEPTH:
            raise CBORError("cbor_troppo_profondo")
        iniziale = self._prendi(1)[0]
        maggiore, info = iniziale >> 5, iniziale & 31
        if maggiore == 7:
            if iniziale == 0xF4:
                return False
            if iniziale == 0xF5:
                return True
            if iniziale == 0xF6:
                return None
            if info == 31:
                raise CBORError("cbor_indefinito", "misplaced break")
            raise CBORError("cbor_float_o_simple", hex(iniziale))
        n = self._argomento(info)
        if maggiore == 0:
            return n
        if maggiore == 1:
            return -1 - n
        if maggiore == 2:
            return self._prendi(n)
        if maggiore == 3:
            try:
                return self._prendi(n).decode("utf-8")
            except UnicodeDecodeError:
                raise CBORError("cbor_utf8") from None
        if maggiore == 4:
            if n > MAX_ITEMS:
                raise CBORError("cbor_troppi_elementi")
            return [self.elemento(profondita + 1) for _ in range(n)]
        if maggiore == 5:
            if n > MAX_ITEMS:
                raise CBORError("cbor_troppi_elementi")
            out = {}
            ultima = None
            for _ in range(n):
                inizio = self.i
                k = self.elemento(profondita + 1)
                kb = self.d[inizio:self.i]
                if type(k) not in (int, str):
                    raise CBORError("cbor_chiave_tipo", type(k).__name__)
                if ultima is not None and kb <= ultima:
                    raise CBORError("cbor_chiave_ripetuta" if kb == ultima else "cbor_chiavi_non_ordinate")
                ultima = kb
                out[k] = self.elemento(profondita + 1)
            return out
        # maggiore == 6
        if n != TAG_COSE_SIGN1:
            raise CBORError("cbor_tag_ignoto", str(n))
        return Tag(n, self.elemento(profondita + 1))


def loads(dati: Any) -> Any:
    """Bytes → value. The whole message must be ONE CBOR item of the subset, with no trailing bytes."""
    if not isinstance(dati, (bytes, bytearray, memoryview)):
        raise CBORError("cbor_tipo_ingresso", type(dati).__name__)
    dati = bytes(dati)
    if len(dati) > MAX_BYTES:
        raise CBORError("cbor_troppo_lungo", str(len(dati)))
    lettore = _Lettore(dati)
    try:
        v = lettore.elemento(0)
    except RecursionError:
        raise CBORError("cbor_troppo_profondo") from None
    if lettore.i != len(dati):
        raise CBORError("cbor_byte_in_coda", str(len(dati) - lettore.i))
    return v
