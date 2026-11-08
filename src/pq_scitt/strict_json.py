#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pq_scitt/strict_json.py — single strict JSON reader for the pq-scitt verifiers (07/11/2026, stdlib only).

Why: `json.loads` accepts repeated members (the last one wins: whoever reads the first sees another value), NaN,
Infinity, `1e999` (becomes inf), a BOM on bytes, and at depth 200,000 it exits with RecursionError, which is not a
ValueError. Audit 07/11 A7, A8, A9.

Rule, closed: whatever is not RFC 8259 JSON in UTF-8 without BOM, with unique names inside each object (RFC 8259 §4
says SHOULD: here it is our own requirement), finite numbers, strings without lone surrogates and depth <= MAX_DEPTH is
rejected with StrictJSONError and with a `motivo` taken from the MOTIVI list. Raises nothing else on bytes or str input.

StrictJSONError is a ValueError: callers with `except ValueError` stay correct. Large integers: they stay exact in
Python; beyond 4300 digits Python rejects them and here they become `non_json`. It is not a limit at 2^53.
"""
from __future__ import annotations

import base64
import binascii
import json
import math
import re
from typing import Any, Optional, Union

MAX_DEPTH = 128

MOTIVI = ("tipo_ingresso", "non_utf8", "bom", "non_json", "membro_ripetuto", "costante_non_json", "numero_non_finito",
          "troppo_profondo", "surrogato_solitario", "non_oggetto", "base64_non_canonico", "lunghezza_errata",
          "testa_illeggibile")

_TOKEN = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"|[\[\]{}]', re.S)
_ESCAPE_SURROGATO = re.compile(r"\\u[dD][89a-fA-F]")
_SURROGATO = re.compile("[\ud800-\udfff]")


class StrictJSONError(ValueError):
    """Rejection with a reason. `motivo` is an entry of MOTIVI; `dettaglio` never contains the whole data."""

    def __init__(self, motivo: str, dettaglio: str = ""):
        self.motivo = motivo
        self.dettaglio = dettaglio
        super().__init__(motivo + (": " + dettaglio if dettaglio else ""))


def _coppie(coppie):
    d = {}
    for k, v in coppie:
        if k in d:
            raise StrictJSONError("membro_ripetuto", repr(k)[:60])
        d[k] = v
    return d


def _costante(nome):
    raise StrictJSONError("costante_non_json", nome)


def _float(testo):
    v = float(testo)
    if not math.isfinite(v):
        raise StrictJSONError("numero_non_finito", testo[:40])
    return v


def _controlla_profondita(testo: str, limite: int) -> None:
    # Before the parser: with 200,000 brackets the C parser exhausts recursion. Counted only outside strings.
    if testo.count("[") + testo.count("{") <= limite:
        return
    livello = 0
    for m in _TOKEN.finditer(testo):
        c = m.group()
        if c in "[{":
            livello += 1
            if livello > limite:
                raise StrictJSONError("troppo_profondo", "more than %d levels" % limite)
        elif c in "]}":
            livello -= 1


def _surrogati(obj) -> bool:
    pila = [obj]
    while pila:
        o = pila.pop()
        if isinstance(o, str):
            if _SURROGATO.search(o):
                return True
        elif isinstance(o, dict):
            pila.extend(o.keys())
            pila.extend(o.values())
        elif isinstance(o, list):
            pila.extend(o)
    return False


def loads(dati: Union[bytes, bytearray, memoryview, str], *, max_depth: int = MAX_DEPTH) -> Any:
    """UTF-8 bytes or str → JSON value. Rejection with StrictJSONError for everything else."""
    if isinstance(dati, (bytes, bytearray, memoryview)):
        grezzi = bytes(dati)
        if grezzi.startswith(b"\xef\xbb\xbf"):
            raise StrictJSONError("bom")
        try:
            testo = grezzi.decode("utf-8")
        except UnicodeDecodeError as e:
            raise StrictJSONError("non_utf8", "byte %d" % e.start) from None
    elif isinstance(dati, str):
        testo = dati
        if testo.startswith("\ufeff"):
            raise StrictJSONError("bom")
        if _SURROGATO.search(testo):
            raise StrictJSONError("surrogato_solitario")
    else:
        raise StrictJSONError("tipo_ingresso", type(dati).__name__)
    _controlla_profondita(testo, max_depth)
    try:
        obj = json.loads(testo, object_pairs_hook=_coppie, parse_constant=_costante, parse_float=_float)
    except StrictJSONError:
        raise
    except (ValueError, RecursionError, MemoryError) as e:
        raise StrictJSONError("non_json", ("%s" % e)[:80] if isinstance(e, ValueError) else type(e).__name__) from None
    if _ESCAPE_SURROGATO.search(testo) and _surrogati(obj):
        raise StrictJSONError("surrogato_solitario")
    return obj


def loads_object(dati, *, max_depth: int = MAX_DEPTH) -> dict:
    """Like `loads`, but the top-level value must be an object."""
    obj = loads(dati, max_depth=max_depth)
    if not isinstance(obj, dict):
        raise StrictJSONError("non_oggetto", type(obj).__name__)
    return obj


def load_jsonl(percorso) -> list:
    """The non-empty lines of a .jsonl file, all objects. A bad line = StrictJSONError with the line number.
    FileNotFoundError goes to the caller: "missing" is an outcome distinct from "broken"."""
    with open(percorso, "rb") as f:
        dati = f.read()
    righe = []
    for n, riga in enumerate(dati.splitlines(), 1):
        if not riga.strip():
            continue
        try:
            righe.append(loads_object(riga))
        except StrictJSONError as e:
            raise StrictJSONError(e.motivo, ("line %d %s" % (n, e.dettaglio)).strip()) from None
    return righe


def testa_catena(percorso, campo: str, genesi: str) -> str:
    """Head of the chain for whoever WRITES the next record (closure of audit A1, 08/11/2026).

    Missing file or no non-empty lines = `genesi`. Otherwise every line goes through `load_jsonl` (a rejected line =
    StrictJSONError with the line number) and the LAST one must have `campo` as a non-empty string, otherwise
    StrictJSONError `testa_illeggibile`. Never an old head, never the genesis on a file that has lines: before, in the
    writers, a lenient `json.loads` with `except: pass`, or `.get(campo, testa_precedente)`, tied the new record to an
    old head or to the genesis and the chain forked silently. Other I/O errors (permissions, folder) go to the caller
    as OSError."""
    try:
        righe = load_jsonl(percorso)
    except FileNotFoundError:
        return genesi
    if not righe:
        return genesi
    testa = righe[-1].get(campo)
    if not isinstance(testa, str) or not testa:
        raise StrictJSONError("testa_illeggibile", "line %d has no %s string" % (len(righe), campo))
    return testa


def b64_canonical(valore: Any, lunghezza: Optional[int] = None) -> bytes:
    """Standard Base64 with padding (RFC 4648 §4), a single encoding per value: closed alphabet, no line breaks,
    trailing bits zero (§3.5). `lunghezza` = bytes expected after decoding. Rejection with StrictJSONError."""
    if not isinstance(valore, str):
        raise StrictJSONError("base64_non_canonico", "not a string")
    try:
        grezzi = base64.b64decode(valore.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise StrictJSONError("base64_non_canonico") from None
    if base64.b64encode(grezzi).decode("ascii") != valore:
        raise StrictJSONError("base64_non_canonico", "does not re-encode identically")
    if lunghezza is not None and len(grezzi) != lunghezza:
        raise StrictJSONError("lunghezza_errata", "%d bytes, expected %d" % (len(grezzi), lunghezza))
    return grezzi
