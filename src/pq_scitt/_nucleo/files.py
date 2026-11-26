# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Roberto Locatelli
"""New files and folders at unpredictable names, with a bounded number of tries.

Unified from cryptovalid `verifier.create_private` (commit 809be6a, verifier.py; as in f7883c9) and ap2-evidence-pack
`_create_exclusive` / `_private_tmpdir` (commits df398fa and 5df7cb4, ap2_evidence.py); `_owner_only` from cryptovalid
`verifier.owner_only` (f7883c9). Where the two differed, the choice is written in DIFFERENZE.md.

Why not tempfile.mkstemp / mkdtemp: on Windows they retry a PermissionError while os.access(folder, W_OK) is true, and
os.access there reads only the read-only attribute, not the access list: in a folder whose list denies writing, name
after name (ap2-evidence-pack CI run 45481354290, Python 3.9: never ended). Here only a name already taken is tried
again, at most 64 times; any other OSError is raised at once."""
import errno
import os
import secrets
import tempfile
from typing import Optional, Tuple

TRIES = 64
_FLAGS = (os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
          | getattr(os, "O_BINARY", 0))


_WINDOWS_DEVICES = frozenset(["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
                             + [d + n for d in ("COM", "LPT") for n in "123456789\u00b9\u00b2\u00b3"])


def _windows_reserved(name: str) -> bool:
    """A file name Windows does not take as it is written (the rules of ntpath.isreserved of Python 3.13, and the
    colon): "C:x" is a path of another drive and "a:x" a stream of the file a; a wildcard or a control character;
    a final dot or space (dropped by the system: another name); a device name before the first dot ("NUL.x" is the
    device NUL on the Windows versions before 11: what is written there is lost)."""
    return (any(c in ':*?"<>|' or ord(c) < 32 for c in name) or name[-1:] in (".", " ")
            or name.partition(".")[0].rstrip(" ").upper() in _WINDOWS_DEVICES)


def _check_part(what: str, s) -> None:
    if not isinstance(s, str) or "\0" in s or any(c in s for c in {os.sep, os.altsep, "/", "\\"} - {None}):
        raise ValueError("%s is a str without a path separator or NUL: %r" % (what, s))


def _check_name(prefix, suffix: str = "") -> None:
    """ValueError unless prefix + 16 hex + suffix is one file name of the folder it is created in."""
    _check_part("prefix", prefix)
    _check_part("suffix", suffix)
    if os.name == "nt" and _windows_reserved(prefix + "0" * 16 + suffix):
        raise ValueError("prefix %r and suffix %r make a name Windows reserves" % (prefix, suffix))


def _set_dacl(path: str, sddl: str) -> None:
    """Windows: the access list of `path` becomes `sddl` (protected from inheritance). %s in `sddl` is this user's SID,
    read with whoami. OSError when it cannot be set."""
    import ctypes
    import re
    import subprocess
    from ctypes import wintypes
    sysdir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    who = subprocess.run([os.path.join(sysdir, "whoami.exe"), "/user", "/fo", "csv", "/nh"], capture_output=True,
                         timeout=60)
    sid = re.findall(rb'"(S-1-[0-9-]+)"', who.stdout)
    if who.returncode != 0 or len(sid) != 1:
        raise OSError("cannot read the SID of this user (whoami exit %d)" % who.returncode)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    conv = adv.ConvertStringSecurityDescriptorToSecurityDescriptorW
    conv.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p)
    conv.restype = wintypes.BOOL
    setsec = adv.SetFileSecurityW
    setsec.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p)
    setsec.restype = wintypes.BOOL
    sd = ctypes.c_void_p()
    if not conv(sddl % sid[0].decode("ascii"), 1, ctypes.byref(sd), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not setsec(os.fspath(path), 0x4 | 0x80000000, sd):   # DACL | PROTECTED_DACL_SECURITY_INFORMATION
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        ctypes.WinDLL("kernel32").LocalFree(sd)


def _owner_only(path: str, folder: bool) -> None:
    """Windows' equivalent of mode 0600 / 0700 (a mode there only sets the read-only attribute): one entry, this user,
    full control, nothing inherited; on a folder the entry is inherited by what is created in it (OICI)."""
    _set_dacl(path, "D:P(A;OICI;FA;;;%s)" if folder else "D:P(A;;FA;;;%s)")


def create_exclusive(folder: str, prefix: str, suffix: str = "", mode: int = 0o600) -> Tuple[int, str]:
    """A new file (fd, path) in `folder` at `prefix` + 16 random hex + `suffix`, opened read-write with
    O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC|O_BINARY: never a file, link, FIFO or folder already at the name. `mode` less
    the umask (on Windows a mode only sets the read-only attribute: see create_private). Only a name already
    taken is tried again, at most 64 times; any other OSError is raised at once."""
    _check_name(prefix, suffix)
    for _ in range(TRIES):
        path = os.path.join(folder, prefix + secrets.token_hex(8) + suffix)
        if os.name == "nt" and os.path.lexists(path):   # O_EXCL there makes the target of a link to nothing, and a folder
            continue                                    # at the name is a PermissionError (CI run 45583189095)
        try:
            return os.open(path, _FLAGS, mode), path
        except FileExistsError:
            continue
    raise FileExistsError(errno.EEXIST, "%d random names in a row already taken" % TRIES, folder)


def create_private(folder: str, prefix: str, suffix: str = "") -> Tuple[int, str]:
    """create_exclusive with mode 0600, and on Windows the access list of _owner_only, set before the caller writes a
    byte. If that fails, the descriptor is closed, the file removed and the error raised."""
    fd, path = create_exclusive(folder, prefix, suffix, 0o600)
    if os.name == "nt":
        try:
            _owner_only(path, folder=False)
        except BaseException:
            os.close(fd)
            try:
                os.unlink(path)
            except OSError:
                pass
            raise
    return fd, path


def private_tmpdir(prefix: str, base: Optional[str] = None) -> str:
    """A new folder in `base` (tempfile.gettempdir() when None) at `prefix` + 16 random hex, mode 0700 less the umask,
    on Windows the access list of _owner_only. Only FileExistsError is tried again, at most 64 times; any other OSError
    is raised at once. If the access list cannot be set, the folder is removed and the error raised."""
    _check_name(prefix)
    base = tempfile.gettempdir() if base is None else base
    for _ in range(TRIES):
        path = os.path.join(base, prefix + secrets.token_hex(8))
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            continue
        if os.name == "nt":
            try:
                _owner_only(path, folder=True)
            except BaseException:
                try:
                    os.rmdir(path)
                except OSError:
                    pass
                raise
        return path
    raise FileExistsError(errno.EEXIST, "%d random names in a row already taken" % TRIES, base)
