# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Roberto Locatelli
"""Finding and running an external program: never the one in the current folder, never through a shell
(on Windows a .bat or .cmd file is refused by run_program: the system runs it through cmd.exe).

which_absolute comes from cryptovalid `verifier.which` (commit f7883c9, verifier.py), with three
changes written in DIFFERENZE.md: the name must be a bare program name, on Windows a name that already ends with
an extension of PATHEXT is looked up as it is (as shutil.which does), and there an absolute path names its drive."""
import os
import posixpath
import re
import shutil
import subprocess
from typing import Mapping, Optional, Sequence

MAX_TIMEOUT = 2000000   # seconds, about 23 days: poll() takes at most 2**31 - 1 milliseconds


def _bare_name(name) -> str:
    """`name` if it is a program name alone, else ValueError: a path (any separator), "", "." / "..", or a NUL."""
    if not isinstance(name, str):
        raise TypeError("a program name is a str, not %s" % type(name).__name__)
    seps = {os.sep, os.altsep, "/", "\\"} - {None}
    if name in ("", ".", "..") or "\0" in name or any(s in name for s in seps) or (os.name == "nt" and ":" in name):
        raise ValueError("not a bare program name: %r" % (name,))
    return name


_WINDOWS_ABSOLUTE = re.compile(r"[A-Za-z]:[\\/]|[\\/]{2}[^\\/]+[\\/]+[^\\/]")   # C:\x, or \\server\share


def _is_absolute(path: str, windows: Optional[bool] = None) -> bool:
    """An absolute path. On Windows it must name its drive, or a server and a share: `\\tools` is a path of the CURRENT
    drive (the one of the current folder). Not asked to ntpath, whose answer changes with Python: isabs calls `\\tools`
    absolute before 3.13 and relative from 3.13, splitdrive finds a share in `\\\\server` from 3.11 and not in 3.9."""
    if os.name == "nt" if windows is None else windows:
        return _WINDOWS_ABSOLUTE.match(path) is not None
    return posixpath.isabs(path)


def which_absolute(name: str) -> Optional[str]:
    """shutil.which, never the current folder. On Windows shutil.which looks in the current folder before PATH (as
    cmd.exe does), and on every system an empty or relative PATH entry is the current folder: a program placed beside
    the evidence would be the one found, and the one run. An answer that is not an absolute path is dropped, and only
    the absolute folders of PATH are searched. None when there is none."""
    _bare_name(name)
    exe = shutil.which(name)
    if exe is not None and _is_absolute(exe):
        return exe
    if os.name == "nt":
        exts = [e for e in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(os.pathsep) if e]
        names = [name] if any(name.lower().endswith(e.lower()) for e in exts) else [name + e for e in exts]
    else:
        names = [name]
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        if _is_absolute(folder):
            for n in names:
                path = os.path.join(folder, n)
                if os.path.isfile(path) and os.access(path, os.X_OK):
                    return path
    return None


def run_program(argv: Sequence[str], *, env: Mapping[str, str], timeout: float, input: Optional[bytes] = None,
                cwd: Optional[str] = None) -> "subprocess.CompletedProcess[bytes]":
    """Run argv[0], found by which_absolute, with argv[1:]: no shell, the environment `env` and nothing else, standard
    input empty (or `input`), output and errors captured as bytes, stopped after `timeout` seconds
    (subprocess.TimeoutExpired, the child killed). FileNotFoundError when the program is not on an absolute folder of
    PATH. The exit status is the caller's to read: a non-zero status is not an exception. On Windows a program found
    as a .bat or .cmd file is a ValueError: the system hands a batch file to cmd.exe, which reads the arguments by the
    rules of a shell (Python's subprocess documentation, "Security Considerations")."""
    if isinstance(argv, (str, bytes)) or not argv or not all(isinstance(a, str) for a in argv):
        raise TypeError("argv is a non-empty list of str")
    if not isinstance(env, Mapping) or not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items()):
        raise TypeError("env is a mapping of str to str (pass {} for an empty environment)")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= MAX_TIMEOUT:
        raise ValueError("timeout is a number of seconds greater than 0, at most %d" % MAX_TIMEOUT)
    if input is not None and not isinstance(input, bytes):
        raise TypeError("input is bytes or None")
    exe = which_absolute(argv[0])
    if exe is None:
        raise FileNotFoundError("%s: not found on an absolute folder of PATH" % argv[0])
    if os.name == "nt" and exe.lower().endswith((".bat", ".cmd")):
        raise ValueError("%s is a batch file: Windows would run it through cmd.exe" % exe)
    return subprocess.run(  # nosec B603 - absolute path from which_absolute, list argv, no shell
        [exe, *argv[1:]], env=dict(env), timeout=timeout, cwd=cwd, shell=False, capture_output=True,
        input=input, stdin=None if input is not None else subprocess.DEVNULL)
