#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pq-scitt - standalone ledger verifier (auditor-grade)
=====================================================

SPDX-License-Identifier: Apache-2.0
Copyright (C) 2026 Roberto Locatelli

Licensed under the Apache License, Version 2.0 (see LICENSE at the root of this repository). Earlier copies of this
file were published under AGPL-3.0-or-later by the same author; this copy is relicensed by him.

Origin: cryptovalid-opencore (https://github.com/robertolocatelli81-dev/cryptovalid-opencore), same author.
"SPEC §n" and spec/CONFORMANCE.md below are documents of that repository (SPEC = SPEC_EVIDENCE_FORMAT.md);
signer.py, evidence_pack.py, cryptovalid_tip.py and the other verifiers named below are tools of that project,
not part of this package.

Independently verifies a hash-chained ledger (*.jsonl) with NOTHING but the
Python standard library (hashlib, json, sys, argparse).

Verified schema:
  - each line is JSON with at least: {idx, ts, data, prev_hash, self_hash}
  - self_hash = SHA-256( JSON(entry without self_hash, sort_keys, separators (',',':')) )
  - prev_hash of entry i = self_hash of entry i-1 (the first has 64 zeros)

Output: structured JSON receipt with an explicit `scope` (what PASS proves and does not prove).
Exit code 0 = chain intact, 1 = failure (a file with zero entries is a failure: nothing was verified), 74 = the receipt
could not be written whole (stdout or the --out file: full, closed, a reader gone), whatever the verdict.

Example:
    pq-scitt verify-ledger-standalone ledger.jsonl
    pq-scitt verify-ledger-standalone ledger.jsonl --algo sha3_256

Reproducible by any third-party auditor: same file, same schema -> same receipt.
"""

from __future__ import annotations

import sys as _sys_0203
if __name__ == "__main__":   # 0.20.3: run as a command, never write the bytecode cache: CPython 3.9 and 3.11 write
    _sys_0203.dont_write_bytecode = True   # a .pyc with one raw write; cut by a file size limit, every later run died (13/10/2026)
    _L0210 = type(__loader__)   # 0.21.0: a .pyc already cut (CPython 3.9/3.11 installed one) is compiled from the source
    if _L0210.__name__ == "SourceFileLoader":   # instead of failing every later run (EOFError: marshal data too short)
        def _get_code_0210(self, fullname, _get_code=_L0210.get_code):
            try:
                return _get_code(self, fullname)
            except (EOFError, ValueError):
                path = self.get_filename(fullname)
                return self.source_to_code(self.get_data(path), path)
        _L0210.get_code = _get_code_0210
import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional

GENESIS_PREV = "0" * 64
SUPPORTED_ALGOS = ("sha256", "sha3_256")
ENTRY_KEYS = frozenset({"idx", "ts", "data", "prev_hash", "self_hash", "signature", "signer", "tsa_token", "signature_pq", "signer_pq"})   # SPEC §2.1: the closed entry schema

EX_IOERR = 74   # sysexits.h: the receipt could not be written whole (0.20.3); never the verdict's 0/1 in that case

# ── The one writer of every command in this repository (0.20.3) ─────────────────────────────────────────────────────
# A command that has computed an outcome (verdict, receipt, record, key, pack) delivers it WHOLE — to stdout, to the
# file it promises, to the ledger — or exits 74 (EX_IOERR) with one line `receipt not written: <reason>` on stderr.
# The other modules with a `__main__` import these functions from here, so verifier.py stays one stdlib-only file.
# Measured on Linux (13/10/2026); macOS and Windows are not measured.


class ReceiptNotWritten(OSError):
    """stdout refused the outcome (ENOSPC, EPIPE, EBADF, EFBIG, a closed or absent stdout): the exit code becomes 74"""


class OutputNotWritten(OSError):
    """a file the command promises (--out, a sidecar, a pack file, a state file) or a ledger line could not be written
    whole: the exit code becomes 74, and nothing half-written is left at the promised path"""


class CheckNotRun(OutputNotWritten):
    """a check the input asks for that cannot be RUN here (openssl cannot be started: fork refused, no descriptor left;
    no temporary file for the bytes openssl reads): exit 74, never a verdict on the input — it is neither the PASS nor
    the FAIL of that check (measured 13/10/2026 on 0.20.2 under RLIMIT_NPROC 1: a valid pack was `valid: false`, exit 1)

    0.22.0: a verifier that computed everything else may attach its COMPLETE receipt (`receipt`, a dict) — the check that
    did not run marked there (`not_evaluated` / `instrument_failure`, SPEC §10); the command writes it with
    check_not_run_exit() (stderr `check not run here: <reason>`, exit 74). Without one, receipt_cli says `receipt not
    written: <reason>` and exits 74, as before."""

    def __init__(self, *args, receipt=None):
        super().__init__(*args)
        self.receipt = receipt


def _text_layer_bytes(out, buf, text: str) -> bytes:
    """The bytes Python's own stdout text layer writes for `text`: its encoding and error handler, "\\n" as os.linesep
    where the platform translates it (not Linux; not measured here), and a byte order mark only where that layer puts
    one — utf-16 / utf-32 only on a stdout seekable at offset 0, utf-8-sig on a pipe too, none on a seekable stdout
    past offset 0 (str.encode would put one on a pipe too)."""
    import codecs
    if os.linesep != "\n":
        text = text.replace("\n", os.linesep)
    encoding = out.encoding or "utf-8"
    enc = codecs.getincrementalencoder(encoding)(out.errors or "strict")
    try:
        seekable = buf.seekable()
        at_start = seekable and buf.tell() == 0
    except (OSError, ValueError):
        seekable = at_start = False
    if (seekable and not at_start) or (not seekable and codecs.lookup(encoding).name in ("utf-16", "utf-32")) \
            or getattr(out, "_cv_bytes_written", False):   # the text layer's encoder writes its mark once per stream
        enc.setstate(0)   # no byte order mark
    return enc.encode(text, final=True)


def _wait_writable(buf) -> None:
    """stdout is non-blocking and full: wait until it can take more, as a blocking write would (the reader is slow, not
    gone; one that goes away makes the next write EPIPE). `select` sleeps in the kernel and Python retries it after a
    signal (PEP 475). A byte stream with no descriptor (io.BytesIO under a TextIOWrapper) never blocks. POSIX only."""
    import select
    try:
        select.select([], [buf.fileno()], [])
    except (OSError, ValueError) as e:   # no descriptor, or one select cannot wait on
        raise OSError(f"stdout is non-blocking and cannot be waited for: {e}")


def write_all(text: str) -> None:
    """Write the whole text to stdout and flush it; ReceiptNotWritten when it did not all get there (see _write_stdout)."""
    _write_stdout(text, None)


def write_all_bytes(raw: bytes) -> None:
    """write_all for bytes that are the outcome as they are (a stored object): no text layer encoding"""
    _write_stdout(None, raw)


def _write_stdout(text, raw) -> None:
    """Write the whole text to stdout and flush it; ReceiptNotWritten when it did not all get there. The bytes go to
    `sys.stdout.buffer` in a loop that checks the count: with -u or PYTHONUNBUFFERED that is a raw FileIO whose write()
    can take part of the data (a file size limit, a disk nearly full) and return the count without raising, or None (a
    full non-blocking pipe) — the text layer above dropped the rest in silence. A full non-blocking stdout is waited for,
    never given up on. An in-process text stream with no bytes below it (io.StringIO) gets the text."""
    out = sys.stdout
    if out is None:   # started with fd 1 closed: print() would drop the outcome and say nothing
        raise ReceiptNotWritten("stdout is closed")
    try:
        buf = getattr(out, "buffer", None)
        while True:   # whatever the text layer still holds goes first, waited for like the outcome
            try:
                out.flush()
                break
            except BlockingIOError:
                if buf is None:
                    raise
                _wait_writable(buf)
        if buf is None:
            if text is None:
                raise OSError("stdout has no byte layer for a binary outcome")
            out.write(text)
            out.flush()
            return
        data = memoryview(_text_layer_bytes(out, buf, text) if text is not None else raw)
        try:
            out._cv_bytes_written = True   # a second outcome on this stream gets no second byte order mark
        except (AttributeError, TypeError):
            pass
        while data:
            try:
                n = buf.write(data)
                waited = False
            except BlockingIOError as e:   # buffered stdout on a full non-blocking pipe: part of it taken
                n, waited = e.characters_written, True
            if n is None:   # raw stdout on a full non-blocking pipe: nothing taken
                n, waited = 0, True
            if n < 0 or n > len(data) or (n == 0 and not waited):
                raise OSError(f"short write: {len(data)} bytes not written")
            data = data[n:]
            if data and waited:
                _wait_writable(buf)
        while True:   # flushed HERE, before the exit code is chosen, not by the interpreter at exit
            try:
                buf.flush()
                return
            except BlockingIOError:
                _wait_writable(buf)
    except ReceiptNotWritten:
        raise
    except (OSError, ValueError) as e:   # ValueError: I/O on a closed file, or text the stream cannot encode
        raise ReceiptNotWritten(f"{type(e).__name__}: {e}") from None


def emit(*parts, sep: str = " ", end: str = "\n", flush: bool = True) -> None:
    """print() for an outcome: the same text, written by write_all (ReceiptNotWritten when not written whole)"""
    write_all(sep.join(str(p) for p in parts) + end)


def say(text: str) -> bool:
    """Write `text` to stderr without ever raising; True when it was written. If stderr is full, closed or its reader
    gone, its descriptor is pointed at the null device (the interpreter's last flush cannot fail again and turn the
    exit code into 120) and the caller's exit code stands."""
    err = sys.stderr
    if err is None:   # started with fd 2 closed
        return False
    try:
        err.write(text)
        err.flush()
        return True
    except (OSError, ValueError):
        silence(err)
        return False


def silence(stream) -> None:
    """Point the descriptor BEHIND `stream` at /dev/null so the interpreter's own flush at exit does not fail again on
    what is still buffered ("Exception ignored", exit 120). The stream's own descriptor, never a fixed number: with fd
    1 closed at start, a file this run opened may hold descriptor 1."""
    try:
        if stream is None:
            return
        fd = stream.fileno()
    except (OSError, ValueError, AttributeError):
        return
    try:
        null = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(null, fd)
        finally:
            os.close(null)
    except OSError:
        pass


def receipt_lost(reason: str, stdout_failed: bool = True) -> int:
    """One line `receipt not written: <reason>` on stderr (nothing raised if stderr fails too) and EX_IOERR."""
    if stdout_failed:
        silence(sys.stdout)
    say(f"receipt not written: {reason}\n")
    return EX_IOERR


def check_not_run_exit(e: "CheckNotRun", text: str) -> int:
    """0.22.0 (SPEC §10): write the COMPLETE receipt `text` a verifier computed although one check could not run here,
    then `check not run here: <reason>` on stderr, exit 74; if the receipt is not taken whole, `receipt not written`."""
    why = write_stdout(text)
    if why is not None:
        return receipt_not_written(why)
    say(f"check not run here: {e}\n")
    return EX_IOERR


def receipt_not_written(why: str) -> int:
    """the 0.20.3 name of receipt_lost(why): stdout's descriptor is already silenced by write_stdout"""
    return receipt_lost(why, stdout_failed=False)


def write_stdout(text: str) -> Optional[str]:
    """Write `text` and a newline to stdout (write_all). None when every byte was taken, else the reason (and stdout's
    descriptor then points at /dev/null)."""
    try:
        write_all(text + "\n")
        return None
    except ReceiptNotWritten as e:
        silence(sys.stdout)
        return str(e)


def _unlink_quietly(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _write_fd(fd: int, data) -> None:
    data = memoryview(data)
    while data:
        n = os.write(fd, data)
        if n <= 0:
            raise OSError(f"short write: {len(data)} bytes not written")
        data = data[n:]


def write_tmp(path: str, data, mode: int = 0o666, exact_mode: Optional[int] = None) -> str:
    """Write `data` (str as UTF-8, or bytes) to a NEW temporary file next to `path` and return its name; on failure
    remove it and raise OutputNotWritten. The name is `<path>.<16 random hex>.tmp`, created with O_CREAT|O_EXCL (never
    an existing file, a symlink or a FIFO planted at a predictable name); written in a loop that checks the count,
    fsynced and closed inside the try (a deferred error at close is a failed write too); `mode` less the umask, or
    `exact_mode` as it is (the mode of the file the temporary will replace)."""
    import secrets
    raw = data if isinstance(data, (bytes, bytearray)) else data.encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    tmp = f"{path}.{secrets.token_hex(8)}.tmp"
    try:
        fd = os.open(tmp, flags, mode)
    except OSError as e:
        raise OutputNotWritten(f"{path}: {e.strerror or e}") from None
    try:
        try:
            if exact_mode is not None:
                os.fchmod(fd, exact_mode)
            _write_fd(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as e:
        _unlink_quietly(tmp)
        raise OutputNotWritten(f"{path}: {e.strerror or e}") from None
    return tmp


def _replace_target(path: str):
    """Where a promised file goes and the mode it keeps, as 0.20.2's open(path, "w") had it: a symlink at `path` is
    followed (its target gets the file, the link stays); an existing file this process may not write (chmod 444 / 400)
    is refused (OutputNotWritten), never replaced by a rename behind its owner's back — the kernel's own check, opened
    for writing WITHOUT truncating; an existing file's mode is kept. Returns (real path, os.stat or None)."""
    real = os.path.realpath(path)
    try:
        st = os.stat(real)
    except OSError:
        return real, None
    import stat
    if stat.S_ISREG(st.st_mode):
        try:
            os.close(os.open(real, os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)))
        except OSError as e:
            raise OutputNotWritten(f"{path}: {e.strerror or e}") from None
    return real, st


def commit_tmp(tmp: str, path: str) -> None:
    """rename `tmp` over `path`; on failure remove `tmp` and raise OutputNotWritten"""
    try:
        os.replace(tmp, path)
    except OSError as e:
        _unlink_quietly(tmp)
        raise OutputNotWritten(f"{path}: {e.strerror or e}") from None


def refuse_directory(path: str) -> None:
    """a path that names a directory (or ends with a separator) can never receive the file: OutputNotWritten"""
    p = str(path)
    if p.endswith(("/", os.sep)) or os.path.isdir(p):
        raise OutputNotWritten(f"{path}: is a directory")


def write_output(path: str, data, mode: int = 0o666) -> None:
    """The whole `data` at `path`, or nothing new there and OutputNotWritten. A regular file (or a new path) is written
    through a temporary file renamed over it once complete, so a file already at `path` stays intact on failure. A path
    that exists and is not a regular file (a FIFO, /dev/stdout, a device) is written directly, every byte, in a loop."""
    import stat
    refuse_directory(path)
    path, st = _replace_target(path)
    if st is not None and not stat.S_ISREG(st.st_mode):
        raw = data if isinstance(data, (bytes, bytearray)) else data.encode("utf-8")
        try:
            fd = os.open(path, os.O_WRONLY | getattr(os, "O_NOCTTY", 0))
            try:
                _write_fd(fd, raw)
            finally:
                os.close(fd)
        except OSError as e:
            raise OutputNotWritten(f"{path}: {e.strerror or e}") from None
        return
    # an existing file keeps its mode (a caller that asks for a mode, the key files, gets that mode)
    keep = stat.S_IMODE(st.st_mode) if st is not None and mode == 0o666 else None
    commit_tmp(write_tmp(path, data, mode, exact_mode=keep), path)


def write_new(path: str, data, mode: int = 0o600) -> None:
    """Create `path` with the whole `data`, never over an existing path: the bytes go to a temporary file (write_tmp),
    which is then hard-linked at `path` (FileExistsError, as O_EXCL, when something is already there) and removed. A
    key or a WORM object is either absent or whole at its path, never cut."""
    tmp = write_tmp(path, data, mode)
    try:
        os.link(tmp, path)
    except FileExistsError:
        raise
    except OSError as e:
        raise OutputNotWritten(f"{path}: {e.strerror or e}") from None
    finally:
        _unlink_quietly(tmp)


def copy_output(src: str, path: str) -> None:
    """Copy the file `src` to `path` whole, or leave nothing new at `path` (OutputNotWritten): read in chunks into a
    temporary file next to `path` (O_EXCL, random name), fsync, close, rename. An error READING `src` stays an OSError
    (the caller's input), with the temporary file removed."""
    import secrets
    import stat
    refuse_directory(path)
    path, st = _replace_target(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    tmp = f"{path}.{secrets.token_hex(8)}.tmp"

    def lost(e):
        return OutputNotWritten(f"{path}: {e.strerror or e}")
    with open(src, "rb") as f:
        try:
            fd = os.open(tmp, flags, 0o666)
        except OSError as e:
            raise lost(e) from None
        try:
            try:
                if st is not None:
                    try:
                        os.fchmod(fd, stat.S_IMODE(st.st_mode))   # the existing file's mode, as shutil.copyfile kept it
                    except OSError as e:
                        raise lost(e) from None
                while True:
                    chunk = f.read(1 << 20)
                    if not chunk:
                        break
                    try:
                        _write_fd(fd, chunk)
                    except OSError as e:
                        raise lost(e) from None
                try:
                    os.fsync(fd)
                except OSError as e:
                    raise lost(e) from None
            finally:
                try:
                    os.close(fd)
                except OSError as e:   # a deferred error at close is a failed write too
                    raise lost(e) from None
        except BaseException:
            _unlink_quietly(tmp)
            raise
    commit_tmp(tmp, path)


def write_file(path: str, text: str) -> Optional[str]:
    """write_output(path, text): None on success, else the reason (0.20.3 interface)"""
    try:
        write_output(path, text)
        return None
    except OutputNotWritten as e:
        return str(e)


def append_line(path: str, line: bytes, *, mode: int = 0o666, opened=None, sync: bool = True) -> None:
    """Append whole ledger lines (bytes ending in b"\\n") or nothing: unbuffered os.write in a loop, fsync (`sync`); on any
    failure the file is truncated back to the bytes it had and OutputNotWritten names what is left. `opened` = an
    already open binary file the caller holds a lock on (its descriptor is used); else `path` is opened O_APPEND."""
    if not line.endswith(b"\n"):
        raise ValueError("a ledger line ends with a newline")
    own = opened is None
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0), mode) if own else opened.fileno()
    try:
        if not own:
            opened.flush()
        end = os.lseek(fd, 0, os.SEEK_END)
        try:
            _write_fd(fd, line)
            if sync:
                os.fsync(fd)
        except BaseException as e:
            try:
                os.ftruncate(fd, end)   # back to the bytes this call found: never half a line in a hash-chained file
            except OSError:
                left = "the ledger could not be truncated back and may end in part of the line"
            else:
                try:
                    os.fsync(fd)
                    left = "the ledger is left as it was"
                except OSError:   # the truncation happened; only its flush to the disk failed
                    left = "the ledger was truncated back to the bytes it had (that truncation could not be synced)"
            if isinstance(e, OSError):
                raise OutputNotWritten(f"ledger {path}: {e.strerror or e}; nothing was recorded, {left}") from None
            raise
    finally:
        if own:
            os.close(fd)


class Parser(argparse.ArgumentParser):
    """argparse with its output through the writers above: usage and error lines (exit 2) go to stderr with a write that
    never raises (argparse's own exited 120 with stderr full, and with stderr closed it printed the usage to STDOUT);
    `--help` prints through write_all, and a help that is not written whole is exit 74."""

    def print_help(self, file=None):
        if file is not None:
            return super().print_help(file)
        try:
            write_all(self.format_help())
        except ReceiptNotWritten as e:
            raise SystemExit(receipt_lost(str(e)))

    def _print_message(self, message, file=None):   # argparse's only writer: error() and exit() print through it
        if not message:
            return
        if file is not None and file is not sys.stdout and file is not sys.stderr:   # a file the caller passed itself
            file.write(message)
        else:
            say(message)


def receipt_cli(main_fn):
    """Decorator for a command's main(): ReceiptNotWritten → 74 (stdout silenced), OutputNotWritten → 74; any other
    exception keeps exit 1 with its traceback written by say() (a full stderr no longer turns it into 120)."""
    import functools

    @functools.wraps(main_fn)
    def wrapper(*a, **kw):
        try:
            return main_fn(*a, **kw)
        except ReceiptNotWritten as e:
            return receipt_lost(str(e))
        except OutputNotWritten as e:
            return receipt_lost(str(e), stdout_failed=False)
        except Exception:
            import traceback
            say(traceback.format_exc())
            return 1
    return wrapper




def _reject_dup(pairs):
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise ValueError(f"duplicate JSON key {k!r}")
        seen[k] = v
    return seen


_SAFE_INT = 2 ** 53 - 1   # portable across Python/JS/Rust/Swift; decimals travel as strings


def _no_float(x):
    raise ValueError(f"non-portable float {x!r} (use a string; the format forbids floats)")


def _bounded_int(x):
    n = int(x)
    if abs(n) > _SAFE_INT:
        raise ValueError(f"integer {x} outside the portable range +/-(2**53-1)")
    return n


MAX_JSON_DEPTH = 512  # normative acceptance-profile bound (spec/CONFORMANCE.md, 2026-09-13)
MAX_INPUT_BYTES = 256 * 1024 * 1024  # a ledger/pack larger than this is refused fail-closed (input_too_large)
_RECURSION_HEADROOM = 3 * MAX_JSON_DEPTH + 256  # frames the C decoder + object_pairs_hook may need per line


def _ensure_recursion_headroom() -> None:
    """The PASS side of the bound must not depend on how deep the CALLER's stack already is (an MCP
    server or a report generator invoking verify_ledger from many frames down). Raise the interpreter
    recursion limit so that an in-profile line (<= MAX_JSON_DEPTH) can always be decoded (2026-09-13).
    Limits (declared in spec/CONFORMANCE.md): this raises the interpreter limit, not the thread's C stack;
    on CPython >= 3.12 the C decoder keeps its own counter, so the positive control for this guard was
    reproduced on 3.11. The raised limit is left in place on purpose (lowering it back under a still-deep
    caller would be the real hazard)."""
    depth = 0
    f = sys._getframe()
    while f is not None:
        depth += 1
        f = f.f_back
    need = depth + _RECURSION_HEADROOM
    if sys.getrecursionlimit() < need:
        sys.setrecursionlimit(need)


def input_too_large(path: str) -> bool:
    try:
        return os.path.getsize(path) > MAX_INPUT_BYTES
    except OSError:
        return False


def json_nesting_depth(text: str) -> int:
    """Maximum bracket nesting of a JSON text, by a LINEAR scan (no recursion, no parsing):
    brackets inside strings are ignored, escapes honoured. Used to refuse pathological nesting
    deterministically BEFORE the recursive stdlib decoder can hit the interpreter's stack."""
    depth = max_depth = 0
    in_str = esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            if depth > max_depth:
                max_depth = depth
        elif ch in "]}":
            depth -= 1
    return max_depth


class JsonTooDeep(ValueError):
    pass


# A raw surrogate code point in the decoded text can only come from bytes that are not UTF-8 (the file is read with
# errors="surrogateescape", which maps each such byte to U+DC80..U+DCFF): valid UTF-8 never decodes to one. SPEC §1/§3:
# a ledger is UTF-8 and MUST NOT contain non-UTF-8 bytes — refused, never hashed as the code point the decoder made up
# (review 12/10/2026: a 0xFF inside a value, self_hash computed over \udcff, was PASS here and FAIL in the five others).
_RAW_SURROGATE = re.compile("[\ud800-\udfff]")


def has_lone_surrogate(text: str) -> bool:
    """True if a `\\uD800-\\uDFFF` escape in the JSON text is not part of a proper high+low pair.
    Linear scan honouring backslash escapes (a `\\\\uD800` is literal text, not an escape). A lone surrogate is
    not a Unicode scalar value, cannot be UTF-8 encoded, and the stdlib decoders of the three reference
    languages disagree on it (Python/JS keep it, Go's replaces it with U+FFFD): the profile refuses it
    (review 14/09/2026, spec/CONFORMANCE.md)."""
    i, n = 0, len(text)
    while i < n:
        if text[i] != "\\":
            i += 1
            continue
        if i + 1 < n and text[i + 1] == "u" and i + 5 < n:
            try:
                cp = int(text[i + 2:i + 6], 16)
            except ValueError:
                i += 2                           # malformed escape: not this rule's business, the decoder refuses it
                continue
            if 0xD800 <= cp <= 0xDBFF:           # high: needs an immediate low
                if text[i + 6:i + 8] != "\\u":
                    return True
                try:
                    lo = int(text[i + 8:i + 12], 16)
                except ValueError:
                    return True                  # a high surrogate followed by a broken escape is still unpaired
                if not (0xDC00 <= lo <= 0xDFFF):
                    return True
                i += 12
                continue
            if 0xDC00 <= cp <= 0xDFFF:           # low without a preceding high
                return True
            i += 6
            continue
        i += 2                                   # any other escape (\\\\, \\", \\n, ...)
    return False


def _loads_strict(text):
    d = json_nesting_depth(text)
    if d > MAX_JSON_DEPTH:
        raise JsonTooDeep(f"json_too_deep: nesting {d} exceeds the acceptance-profile bound {MAX_JSON_DEPTH}")
    if _RAW_SURROGATE.search(text):
        raise ValueError("not_utf8: the line holds bytes that are not UTF-8 (SPEC §3)")
    if has_lone_surrogate(text):
        raise ValueError("lone_surrogate: unpaired UTF-16 surrogate escape is outside the acceptance profile")
    _ensure_recursion_headroom()
    return json.loads(text, object_pairs_hook=_reject_dup, parse_float=_no_float, parse_int=_bounded_int,
                      parse_constant=lambda c: (_ for _ in ()).throw(ValueError(f"JSON constant {c}")))

def canonical_payload(entry: Dict) -> bytes:
    """Canonical string of the entry, used to recompute self_hash. Excludes self_hash AND the attestations
    added AFTERWARDS (signature/signer): self_hash commits to the CONTENT, the signature commits to self_hash.
    So a signed ledger still passes the stdlib-only hash check, without touching the signatures."""
    # attestation fields (outside the content hash): classical and, since 0.12.0, the ML-DSA-65 companion; since 0.20.2
    # tsa_token too (SPEC §2: an RFC 3161 token over self_hash cannot sit inside the bytes self_hash is computed from)
    d = {k: v for k, v in entry.items() if k not in ("self_hash", "signature", "signer", "signature_pq", "signer_pq", "tsa_token")}
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def hash_with(algo: str, payload: bytes) -> str:
    if algo == "sha256":
        return hashlib.sha256(payload).hexdigest()
    if algo == "sha3_256":
        return hashlib.sha3_256(payload).hexdigest()
    raise ValueError(f"unsupported_algo:{algo}")


def detect_algo(entries: List[Dict]) -> Optional[str]:
    """Auto-detect: try both algorithms on the first entry."""
    if not entries:
        return None
    e0 = entries[0]
    if "self_hash" not in e0:
        return None
    payload = canonical_payload(e0)
    for algo in SUPPORTED_ALGOS:
        if hash_with(algo, payload) == e0["self_hash"]:
            return algo
    return None


def verify_ledger(path: str, algo: Optional[str] = None, tip: Optional[str] = None,
                  trusted_pubkey_hex: Optional[str] = None, require_tip: bool = False,
                  tip_not_before: Optional[str] = None, expect_ledger_id: Optional[str] = None,
                  trusted_pq_pubkey_b64: Optional[str] = None) -> Dict:
    """Verify the ledger's integrity. Returns a JSON-serializable receipt.

    `tip`: path of a signed chain tip (cryptovalid_tip.py); None = use `<path>.tip.json` when it exists. With a
    tip the tail limit moves: truncation, suffix rewrite and unsealed appends become named FAILs (the chain
    alone cannot see them). `require_tip`: a missing tip is a FAIL. `trusted_pubkey_hex`: the log key the
    relying party trusts (without it the tip's own key is used and the receipt says so: NOT trusted)."""
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    errors: List[Dict] = []

    if input_too_large(path):
        # fail-closed on size too: reading it would exhaust memory and die without a receipt (review 13/09)
        return {"verdict": "FAIL", "path": path, "verified_utc": started, "entries_count": 0,
                "parse_errors": [{"line": -1, "error": f"input_too_large: file exceeds {MAX_INPUT_BYTES} bytes"}]}
    try:
        # ONE line rule in the five verifiers (review 16/09 r5): lines are separated by LF only (no universal
        # newlines: a lone CR is data inside the line, hence a decode error), and a line is blank when it holds
        # nothing but ASCII space / tab / CR — never Unicode whitespace (str.strip() took U+00A0).
        with open(path, encoding="utf-8", errors="surrogateescape", newline="\n") as f:
            raw_lines = [ln for ln in f if ln.strip(" \t\r\n")]
    except FileNotFoundError:
        return {
            "verdict": "FILE_NOT_FOUND",
            "path": path,
            "verified_utc": started,
        }
    except OSError as e:   # a directory, a permission error: a receipt, never a traceback
        return {"verdict": "FAIL", "path": path, "verified_utc": started, "entries_count": 0,
                "parse_errors": [{"line": -1, "error": f"unreadable: {type(e).__name__}"}]}

    entries: List[Dict] = []
    for i, line in enumerate(raw_lines):
        try:
            obj = _loads_strict(line)
            if not isinstance(obj, dict):
                # a line that is JSON but not an object ([], 1, "x", null): named, like JS/Java/Rust — never a crash
                # further down (audit V1 #3, 30/09/2026: AttributeError/TypeError tracebacks, no receipt)
                errors.append({"line": i, "error": "not_a_json_object"})
                continue
            entries.append(obj)
        except JsonTooDeep as e:
            # Nesting beyond the NORMATIVE bound (MAX_JSON_DEPTH, measured by a linear scan, never by
            # recursion): a FAIL with a named error, never a crash (2026-09-13).
            errors.append({"line": i, "error": str(e)})
        except (json.JSONDecodeError, ValueError) as e:
            errors.append({"line": i, "error": f"json_decode:{e}"})
        except RecursionError as e:
            # Belt-and-braces: the pre-scan already refused > MAX_JSON_DEPTH, so reaching here means the
            # host process had less stack than the bound assumes (deep caller). Named, not disguised.
            errors.append({"line": i, "error": f"recursion_error: {str(e)[:120]}"})

    # No `idx` → the profile, like every other entry (0.20.0, closed by construction): the reference no longer takes a
    # native-schema fallback for ledgers whose first three entries lack idx (0.19.0 declared it: §2.1 and §5 step 4 were
    # not applied there, an unknown key passed). Such a ledger is FAIL, idx_mismatch named, as in the five other verifiers.
    if algo is None:
        algo = detect_algo(entries) or "sha256"

    # SPEC §2.1 (2026-10-10): the entry is a CLOSED object — a top-level key outside the core + optional fields is a named
    # FAIL, never a silent pass (measured: entries written with an extra key, hash recomputed over it, were PASS)
    schema_failures: List[Dict] = []
    for i, e in enumerate(entries):
        unknown = sorted(k for k in e if k not in ENTRY_KEYS)
        if unknown:
            schema_failures.append({"idx": e.get("idx", i), "reason": "unknown_field:" + ",".join(unknown)[:120]})

    # Re-hash check
    hash_recomputed = 0
    hash_failures: List[Dict] = []
    for i, e in enumerate(entries):
        expected = e.get("self_hash")
        if expected is None:
            hash_failures.append({"idx": e.get("idx", i), "reason": "missing_self_hash"})
            continue
        computed = hash_with(algo, canonical_payload(e))
        if computed == expected:
            hash_recomputed += 1
        else:
            hash_failures.append(
                {
                    "idx": e.get("idx", i),
                    "reason": "hash_mismatch",
                    "expected": expected,
                    "computed": computed,
                }
            )

    # Chain linkage check
    link_ok = 0
    link_failures: List[Dict] = []
    for i, e in enumerate(entries):
        expected_prev = entries[i - 1].get("self_hash") if i > 0 else GENESIS_PREV
        actual_prev = e.get("prev_hash")
        if actual_prev == expected_prev:
            link_ok += 1
        else:
            link_failures.append(
                {
                    "idx": e.get("idx", i),
                    "expected_prev": expected_prev,
                    "actual_prev": actual_prev,
                }
            )

    # Idx monotonicity
    idx_ok = True
    for i, e in enumerate(entries):
        idx = e.get("idx")
        if isinstance(idx, bool) or idx != i:   # True == 1 in Python: a boolean idx is NOT sequential (r5)
            idx_ok = False
            errors.append({"line": i, "error": f"idx_mismatch: expected {i}, got " + (json.dumps(idx, ensure_ascii=False, separators=(",", ":")) if "idx" in e else "(missing)")})   # 0.20.0: absent ≠ null ≠ "1"

    # Timestamp monotonicity: REPORTED, not enforced. A backwards `ts` does not break the hash chain
    # (the chain proves order of *appending*, not wall-clock time), but an auditor must see it.
    ts_ok, ts_backwards = True, []
    for i in range(1, len(entries)):
        a, b = entries[i - 1].get("ts"), entries[i].get("ts")
        if isinstance(a, str) and isinstance(b, str) and b < a:
            ts_ok = False
            ts_backwards.append({"idx": entries[i].get("idx", i), "prev_ts": a, "ts": b})

    chain_integrity = len(hash_failures) == 0 and len(link_failures) == 0 and idx_ok and len(errors) == 0 and len(schema_failures) == 0   # SPEC §2.1
    # A ledger with ZERO entries has no chain to verify: "PASS" on nothing was a false green (found
    # by the 2026-09-11 red-team pass: truncation to zero entries verified as PASS — in all four
    # verifiers of this family). The spec vocabulary is PASS/FAIL, so it is a FAIL with a named error.
    if not entries:
        chain_integrity = False
        errors.append({"line": 0, "error": "empty_ledger: zero entries, nothing to verify"})

    # Signed chain tip (15/09/2026): the only way a SNAPSHOT verifier can see tail truncation / suffix rewrite.
    tip_check: Optional[Dict] = None
    tip_file = tip if tip is not None else (path + ".tip.json" if os.path.exists(path + ".tip.json") else None)
    if trusted_pq_pubkey_b64:
        # a trusted post-quantum key is a REQUIREMENT: it implies a required tip, and it is meaningless without the
        # trusted log key (review 15/09: PQ key alone → tip never checked → PASS, a fail-open)
        require_tip = True
        if not trusted_pubkey_hex:
            chain_integrity = False
            errors.append({"line": len(entries), "error": "pq_key_without_log_key: --trusted-pq-pubkey needs --trusted-pubkey "
                                                            "(the post-quantum layer sits on top of the Ed25519 tip, never instead of it)"})
    if tip_file is not None and not trusted_pubkey_hex:
        # a tip is there but no trusted log key: it is NOT checked (the key inside the tip proves nothing), and
        # the verdict is the bare chain's — with require_tip that is a FAIL (review 15/09: no fail-open)
        tip_check = {"ok": False, "checked": False, "tip_path": tip_file, "pq_protected": None,   # not read: unknown
                     "error": "tip_untrusted: a signed tip is present but no trusted log key was given (--trusted-pubkey); "
                              "the tail limit applies in full"}
        if require_tip:
            chain_integrity = False
            errors.append({"line": len(entries), "error": tip_check["error"]})
    elif tip_file is not None:
        try:
            import cryptovalid_tip as _tip
            last = entries[-1].get("self_hash", "") if entries else _tip.GENESIS
            first = entries[0].get("self_hash", "") if entries else _tip.GENESIS
            tip_check = _tip.check_tip(len(entries), last if isinstance(last, str) else "", _tip.load_tip(tip_file),
                                       trusted_pubkey_hex, tip_not_before,
                                       first_self_hash=first if isinstance(first, str) else "",
                                       expect_ledger_id=expect_ledger_id,
                                       trusted_pq_pubkey_b64=trusted_pq_pubkey_b64)
        except (OSError, ValueError, ImportError) as e:
            tip_check = {"ok": False, "error": f"tip_unreadable: {type(e).__name__}: {str(e)[:120]}", "pq_protected": False}
        tip_check["tip_path"] = tip_file
        tip_check["checked"] = True
        if not tip_check["ok"]:
            chain_integrity = False
            errors.append({"line": len(entries), "error": tip_check["error"]})
    elif require_tip:
        chain_integrity = False
        errors.append({"line": len(entries), "error": "tip_missing: a signed chain tip is required and none was found"})

    receipt: Dict = {
        "verified_utc": started,
        "verifier": "pq-scitt ledger.standalone 0.1.0 (stdlib-only)",
        "path": path,
        "algorithm_used": algo,
        "algorithm_supported": list(SUPPORTED_ALGOS),
        "entries_count": len(entries),
        "hash_recomputed_ok": hash_recomputed,
        "hash_recomputed_total": len(entries),
        "hash_recompute_passed": len(hash_failures) == 0,
        "hash_failures": hash_failures[:10],  # cap
        "link_ok": link_ok,
        "link_total": len(entries),
        "link_passed": len(link_failures) == 0,
        "link_failures": link_failures[:10],
        "idx_monotonic": idx_ok,
        "ts_monotonic": ts_ok,
        "ts_backwards": ts_backwards[:10],
        "parse_errors": errors[:10],
        "schema_failures": schema_failures[:10],   # SPEC §2.1 (2026-10-10): top-level entry keys outside the closed schema
        "chain_integrity": chain_integrity,
        "tip": tip_check,   # None = no signed tip checked (the tail limit below applies in full)
        "verdict": "PASS" if chain_integrity else "FAIL",
        # What this verdict does and does not prove. A bare hash chain is internally consistent
        # evidence: anyone with write access to the file can truncate it or rewrite a suffix and
        # re-chain it, and this verifier will not see that. Those attacks are caught one layer up —
        # a signed evidence pack commits to entry count + head hash (evidence_pack.py) and RFC 3161 /
        # public anchors commit to time. Stated here so that "PASS" is never read as more than it is.
        "scope": {
            "proves": ["every self_hash recomputes from its entry (canonical JSON)",
                       "every prev_hash links to the previous self_hash (genesis = 64 zeros)",
                       "idx is contiguous from 0"],
            "does_not_prove": (["no truncation / suffix rewrite by a party holding the LOG KEY (key custody is "
                                "the limit: HSM/KMS, copies of the tip outside the writer's reach)",
                                "no ROLLBACK to an older signed state (truncation + an older genuine tip restored): "
                                "pass --tip-not-before, or compare with the monitor state / receipts / an anchor",
                                "not that this is the ledger YOU expect when the log key signs several ledgers: pass "
                                "--expect-ledger-id (self_hash of entry 0)"]
                               if tip_check and tip_check.get("ok") else
                               ["no truncation (a shorter prefix is a valid chain)",
                                "no suffix rewrite by a party with write access (re-chained fork)"]) + [
                               "authorship (use signer.py / a signed evidence pack)",
                               "wall-clock time (ts is reported, not attested: use RFC 3161 / anchors)"],
            "to_cover_those": ("a signed chain tip (cryptovalid_tip.py, --tip/--require-tip) turns truncation, "
                               "suffix rewrite and unsealed appends into named FAILs; evidence_pack.py verify <pack> "
                               "(signed manifest: entry count + head); receipts / monitor for time-ordered proof"),
        },
    }

    # 0.21.0 (SPEC v0.4 §5 step 5): this verifier does not check signatures; when the ledger carries a signature layer it
    # says how many entries carry one (only then, so the receipt of a ledger without signatures is the one of 0.20.3)
    signed_n = sum(1 for e in entries if isinstance(e, dict) and any(k in e for k in ("signature", "signer", "signature_pq", "signer_pq")))
    if signed_n:
        receipt["signatures_not_checked"] = signed_n

    # Receipt-of-receipt: hash of the receipt itself (deterministic, verified_utc excluded)
    receipt_canonical = {k: v for k, v in receipt.items() if k != "verified_utc"}
    receipt_payload = json.dumps(
        receipt_canonical, sort_keys=True, separators=(",", ":"), default=str
    ).encode()
    receipt["receipt_sha256"] = hashlib.sha256(receipt_payload).hexdigest()
    receipt["receipt_sha3_256"] = hashlib.sha3_256(receipt_payload).hexdigest()
    return receipt


@receipt_cli
def main(argv: Optional[List[str]] = None) -> int:
    parser = Parser(allow_abbrev=False, 
        prog="pq-scitt verify-ledger-standalone",
        description="Independent verification of a hash-chained .jsonl ledger (auditor-grade, stdlib-only).",
    )
    parser.add_argument("ledger_path", help="Path of the .jsonl file to verify")
    parser.add_argument(
        "--algo", choices=SUPPORTED_ALGOS, default=None, help="Force the algorithm (default: auto-detect)"
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Print only the short verdict (PASS/FAIL + exit code)"
    )
    parser.add_argument("--out", default=None, help="Also write the JSON receipt to a file")
    parser.add_argument("--tip", default=None, help="signed chain tip to check (default: <ledger>.tip.json if present)")
    parser.add_argument("--trusted-pubkey", default=None, help="log key (hex) the tip must be signed with")
    parser.add_argument("--trusted-pq-pubkey", default=None,
                        help="ML-DSA-65 log key (base64) a hybrid tip must ALSO be signed with (FAIL if missing/invalid)")
    parser.add_argument("--require-tip", action="store_true", help="FAIL when no signed tip is available")
    parser.add_argument("--tip-not-before", default=None, help="refuse a tip dated before this ISO-8601 instant (rollback)")
    parser.add_argument("--expect-ledger-id", default=None, help="the chain identity (self_hash of entry 0) you expect: refuses another ledger's pair")
    args = parser.parse_args(argv)
    for flag in ("algo", "pubkey", "tip", "trusted_pubkey", "trusted_pq_pubkey", "tip_not_before", "expect_ledger_id"):
        v = getattr(args, flag, None)
        if v is not None and (v == "" or v.startswith("-")):   # "" or a flag as a value would silently mean "not given" (21/09/2026: one grammar in the four)
            parser.error(f"--{flag.replace('_', '-')} needs a value (got {v!r})")

    try:
        receipt = verify_ledger(args.ledger_path, algo=args.algo, tip=args.tip,
                                trusted_pubkey_hex=args.trusted_pubkey, require_tip=args.require_tip,
                                tip_not_before=args.tip_not_before, expect_ledger_id=args.expect_ledger_id,
                                trusted_pq_pubkey_b64=args.trusted_pq_pubkey)
    except RecursionError as e:  # last-resort fail-closed: a receipt, never a traceback (2026-09-13).
        # Not labelled json_too_deep on purpose: here the cause is unknown (review 13/09 —
        # a recursion bug in the verifier itself must not be disguised as a malformed input).
        receipt = {"verdict": "FAIL", "path": args.ledger_path,
                   "verified_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                   "parse_errors": [{"line": -1, "error": f"recursion_error: {str(e)[:120]}"}]}

    # 0.20.3: a receipt that is not written whole (the --out file or stdout) is exit 74, whatever the verdict; both are
    # attempted, and the code is decided after the flush
    failed = []
    if args.out:
        why = write_file(args.out, json.dumps(receipt, indent=2, default=str))
        if why is not None:
            failed.append(why)
    why = write_stdout(receipt["verdict"] if args.quiet else json.dumps(receipt, indent=2, default=str))
    if why is not None:
        failed.append(why)
    if failed:
        return receipt_not_written("; ".join(failed))
    return 0 if receipt.get("verdict") == "PASS" else 1


if __name__ == "__main__":  # pragma: no cover - CLI entry point (main() is covered directly)
    sys.exit(main())
