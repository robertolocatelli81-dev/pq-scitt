# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Roberto Locatelli
"""json.loads with nesting deeper than a bound refused first, by a linear scan.

From cryptovalid (commit f7883c9, verifier.py: json_nesting_depth, JsonTooDeep, JsonTooDeepToRead,
json_loads_bounded; SPEC §30), with the bound as a parameter (512 by default, the value of cryptovalid's
MAX_JSON_DEPTH). A bare json.loads gave up at 995 levels under Python 3.9 and 3.11, 9 999 under 3.13 and 65 168 under
3.14 on the machine of that measure (cryptovalid f7883c9); under 3.14 the depth is the one the stack of the machine
allows (100 000 levels were read on Linux and macOS in CI run 45583189095). With the scan first, one bound on every
Python and every machine.

Under Python 3.9 to 3.11 the parser's levels count against sys.getrecursionlimit(), so a text within the bound was
still a bare RecursionError when the caller was already deep in its own stack (512 levels from 600 frames down: refused
under 3.9 and 3.11, read under 3.13). _RecursionHeadroom, from cryptovalid f7883c9 (verifier.py, where the callers of
json_loads_bounded held it), is now inside json_loads_bounded."""
import json
import re
import sys
import threading

MAX_JSON_DEPTH = 512

_DEPTH_OUT = re.compile(r'["\[\]{}]')
_DEPTH_IN = re.compile(r'["\\]')


def json_nesting_depth(text: str) -> int:
    """Maximum bracket nesting of a JSON text, by a LINEAR scan (no recursion, no parsing, memory that does not grow
    with the text): brackets inside strings are ignored, escapes honoured."""
    depth = max_depth = 0
    i = 0
    while True:                                  # jumps to the next character that matters (same result as a char loop)
        m = _DEPTH_OUT.search(text, i)
        if m is None:
            break
        ch, i = m.group(), m.end()
        if ch == '"':
            while True:
                m = _DEPTH_IN.search(text, i)
                if m is None:
                    return max_depth             # unterminated string: nothing after it counts
                i = m.end()
                if m.group() == '"':
                    break
                i += 1                           # a backslash escapes the next character, whatever it is
        elif ch in "[{":
            depth += 1
            if depth > max_depth:
                max_depth = depth
        else:
            depth -= 1
    return max_depth


class JsonTooDeep(ValueError):
    pass


class JsonTooDeepToRead(JsonTooDeep, RecursionError):
    """A JSON text nested deeper than the bound, refused before the parser. Both a ValueError and a RecursionError:
    a reader keeps the answer it gave when Python's parser ran out of stack, now at one depth on every Python."""


_HEADROOM_LOCK = threading.Lock()
_HEADROOM = {"users": 0, "saved": None, "set": None}


class _RecursionHeadroom:
    """While a text of `levels` levels is parsed, the interpreter's recursion limit is at least the caller's depth
    + 3 frames a level + 256, so the answer does not depend on how deep the caller's stack already is. The limit is one
    per process: the first parse that raises it saves the caller's value and the last one to finish, in any thread,
    puts it back; if someone else changed the limit meanwhile, their value is kept."""

    def __init__(self, levels: int):
        self.frames = 3 * levels + 256

    def __enter__(self):
        depth = 0
        f = sys._getframe()
        while f is not None:
            depth += 1
            f = f.f_back
        need = depth + self.frames
        with _HEADROOM_LOCK:
            h = _HEADROOM
            if h["users"] == 0:
                h["saved"], h["set"] = sys.getrecursionlimit(), None
            h["users"] += 1
            if sys.getrecursionlimit() < need:
                sys.setrecursionlimit(need)
                h["set"] = need
        return self

    def __exit__(self, *exc):
        with _HEADROOM_LOCK:
            h = _HEADROOM
            h["users"] -= 1
            if h["users"] == 0:
                if h["set"] is not None and sys.getrecursionlimit() == h["set"]:
                    sys.setrecursionlimit(h["saved"])
                h["saved"] = h["set"] = None
        return False


def json_loads_bounded(s, max_depth: int = MAX_JSON_DEPTH, **kw):
    """json.loads, with nesting deeper than `max_depth` refused first (JsonTooDeepToRead). Bytes are decoded first, as
    json.loads decodes them (UTF-8, UTF-16 or UTF-32 by json.detect_encoding, "surrogatepass"): the scan reads
    characters. Scanned as bytes, a UTF-16 text hid its brackets behind a code unit with the byte 0x22 or 0x5C
    (U+2201): 1 100 levels were read under Python 3.13 and a RecursionError under 3.9 (cryptovalid f7883c9).
    The parser is given the stack for the levels of the text, up to MAX_JSON_DEPTH (_RecursionHeadroom): with a
    `max_depth` above 512, a text deeper than 512 is left to the limits of the parser of each Python."""
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) or max_depth < 0:
        raise ValueError("max_depth is an int >= 0")
    if isinstance(s, (bytes, bytearray)):
        s = s.decode(json.detect_encoding(s), "surrogatepass")
    depth = json_nesting_depth(s) if isinstance(s, str) else 0
    if depth > max_depth:
        raise JsonTooDeepToRead("JSON nested deeper than %d levels" % max_depth)
    with _RecursionHeadroom(min(depth, MAX_JSON_DEPTH)):
        return json.loads(s, **kw)
