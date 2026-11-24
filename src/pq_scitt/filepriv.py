"""pq_scitt/filepriv.py — private files (key files, salts files) on POSIX and on Windows (0.1.1).

The rule is the same on both systems; the means differ:
  - owner: the running user. POSIX: st_uid == geteuid(). Windows: the owner SID of the file is the SID of the user of
    the process token, or the default owner of that token (an elevated administrator creates files owned by the
    Administrators group);
  - nobody else may access the file. POSIX: no group or other bit (mode & 0o077 == 0). Windows: every access-allowed
    entry of the DACL is for the owner, the user, the token's default owner, SYSTEM (S-1-5-18), Administrators
    (S-1-5-32-544) or OWNER RIGHTS (S-1-3-4): the accounts that can read a 0600 file on POSIX too (root). A NULL DACL,
    an entry for anyone else, or an entry of another type = refused;
  - not a link. POSIX: O_NOFOLLOW. Windows: os.lstat before opening (a symbolic link or another reparse point is
    refused) and the same file identity (st_dev, st_ino) on the open descriptor;
  - a new private file (salts). POSIX: O_EXCL|O_NOFOLLOW with mode 0600. Windows: CreateFileW CREATE_NEW with
    FILE_FLAG_OPEN_REPARSE_POINT (an existing link is never followed) and a protected DACL with one entry, the user,
    given at creation.
Any other system (neither POSIX nor Windows) = refused with the reason. Standard library only (ctypes on Windows).
"""
from __future__ import annotations

import errno
import os
import stat
from typing import Optional

WINDOWS = os.name == "nt"
POSIX = (not WINDOWS) and hasattr(os, "O_NOFOLLOW") and hasattr(os, "geteuid")
SUPPORTATO = WINDOWS or POSIX

# Windows: accounts that may hold an access-allowed entry besides the owner (they can read a 0600 file on POSIX too)
SID_AMMESSI = frozenset({"S-1-5-18", "S-1-5-32-544", "S-1-3-4"})
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class NonPrivato(Exception):
    """The reason, in a sentence; the caller adds its own prefix."""


class NonRegolare(Exception):
    """Windows: the path is a directory or a device, refused before opening (a directory cannot be opened there)."""


# ------------------------------------------------------------------ Windows (ctypes, advapi32)

def _win():
    import ctypes
    from ctypes import wintypes
    a = ctypes.WinDLL("advapi32", use_last_error=True)
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    a.GetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
                                  ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
                                  ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p)]
    a.GetSecurityInfo.restype = wintypes.DWORD
    a.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    a.ConvertSidToStringSidW.restype = wintypes.BOOL
    a.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    a.GetAce.restype = wintypes.BOOL
    a.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    a.OpenProcessToken.restype = wintypes.BOOL
    a.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                      ctypes.POINTER(wintypes.DWORD)]
    a.GetTokenInformation.restype = wintypes.BOOL
    a.GetLengthSid.argtypes = [ctypes.c_void_p]
    a.GetLengthSid.restype = wintypes.DWORD
    a.InitializeAcl.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
    a.InitializeAcl.restype = wintypes.BOOL
    a.AddAccessAllowedAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    a.AddAccessAllowedAce.restype = wintypes.BOOL
    a.InitializeSecurityDescriptor.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    a.InitializeSecurityDescriptor.restype = wintypes.BOOL
    a.SetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, wintypes.BOOL, ctypes.c_void_p, wintypes.BOOL]
    a.SetSecurityDescriptorDacl.restype = wintypes.BOOL
    a.SetSecurityDescriptorControl.argtypes = [ctypes.c_void_p, wintypes.WORD, wintypes.WORD]
    a.SetSecurityDescriptorControl.restype = wintypes.BOOL
    k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                              wintypes.DWORD, wintypes.HANDLE]
    k.CreateFileW.restype = wintypes.HANDLE
    k.GetCurrentProcess.restype = wintypes.HANDLE
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    k.LocalFree.argtypes = [ctypes.c_void_p]
    k.LocalFree.restype = ctypes.c_void_p
    return ctypes, wintypes, a, k


def _sid_testo(ctypes, wintypes, a, k, psid) -> str:
    s = wintypes.LPWSTR()
    if not a.ConvertSidToStringSidW(psid, ctypes.byref(s)):
        raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW")
    try:
        return s.value
    finally:
        k.LocalFree(s)


def _token(classe: int):
    """(ctypes objects, buffer) of one TOKEN_INFORMATION_CLASS of the current process (1 TokenUser, 4 TokenOwner)."""
    ctypes, wintypes, a, k = _win()
    h = wintypes.HANDLE()
    if not a.OpenProcessToken(k.GetCurrentProcess(), 0x0008, ctypes.byref(h)):   # TOKEN_QUERY
        raise OSError(ctypes.get_last_error(), "OpenProcessToken")
    try:
        n = wintypes.DWORD()
        a.GetTokenInformation(h, classe, None, 0, ctypes.byref(n))
        buf = ctypes.create_string_buffer(n.value)
        if not a.GetTokenInformation(h, classe, buf, n, ctypes.byref(n)):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation")
    finally:
        k.CloseHandle(h)
    return (ctypes, wintypes, a, k), buf


def _sid_del_token(classe: int):
    (ctypes, wintypes, a, k), buf = _token(classe)
    psid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]   # TOKEN_USER / TOKEN_OWNER: the SID pointer first
    return _sid_testo(ctypes, wintypes, a, k, psid), (ctypes, wintypes, a, k), buf, psid


def utente():
    """POSIX: the effective uid. Windows: the SIDs a private file may be owned by (token user, token default owner)."""
    if WINDOWS:
        return frozenset({_sid_del_token(1)[0], _sid_del_token(4)[0]})
    return os.geteuid()


def _problema_windows(fd: int) -> Optional[str]:
    import msvcrt
    ctypes, wintypes, a, k = _win()
    owner, dacl, sd = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    err = a.GetSecurityInfo(msvcrt.get_osfhandle(fd), 1, 0x1 | 0x4,   # SE_FILE_OBJECT; OWNER | DACL
                            ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(sd))
    if err:
        raise OSError(err, "GetSecurityInfo")
    try:
        ammessi = utente()
        proprietario = _sid_testo(ctypes, wintypes, a, k, owner)
        if proprietario not in ammessi:
            return "the owner is not the running user"
        if not dacl.value:
            return "permissions: no DACL, every account has access"
        n = ctypes.cast(dacl, ctypes.POINTER(ctypes.c_uint16))[2]    # ACL: AclRevision, Sbz1, AclSize, AceCount
        for i in range(n):
            ace = ctypes.c_void_p()
            if not a.GetAce(dacl, i, ctypes.byref(ace)):
                raise OSError(ctypes.get_last_error(), "GetAce")
            tipo, flag = ctypes.cast(ace, ctypes.POINTER(ctypes.c_ubyte))[0:2]
            if flag & 0x08:                    # INHERIT_ONLY_ACE: does not apply to this file
                continue
            if tipo == 1:                      # ACCESS_DENIED_ACE_TYPE: takes access away, allowed
                continue
            if tipo != 0:                      # anything but ACCESS_ALLOWED_ACE_TYPE: not understood, refused
                return "permissions: DACL entry of type %d" % tipo
            sid = _sid_testo(ctypes, wintypes, a, k, ace.value + 8)   # ACE_HEADER (4) + ACCESS_MASK (4) + SID
            if sid not in ammessi and sid != proprietario and sid not in SID_AMMESSI:
                return "permissions: the DACL gives access to another account (%s)" % sid
        return None
    finally:
        k.LocalFree(sd)


def _crea_windows(percorso: str) -> int:
    """CreateFileW with CREATE_NEW and FILE_FLAG_OPEN_REPARSE_POINT: an existing path, a symbolic link included (even
    one whose target does not exist), is FileExistsError, never followed; the file is born with a protected DACL with
    one entry, the user (no name-based change afterwards). 0.1.1: os.open(O_CREAT|O_EXCL) followed a dangling link on
    Windows and created its target (CI run 45341103851)."""
    import msvcrt
    sid, (ctypes, wintypes, a, k), buf, psid = _sid_del_token(1)
    lunghezza = 8 + 8 + a.GetLengthSid(psid)          # ACL header + ACCESS_ALLOWED_ACE without SidStart + the SID
    acl = ctypes.create_string_buffer((lunghezza + 3) & ~3)
    if not a.InitializeAcl(acl, len(acl), 2):           # ACL_REVISION
        raise OSError(ctypes.get_last_error(), "InitializeAcl")
    if not a.AddAccessAllowedAce(acl, 2, 0x1F01FF, psid):   # FILE_ALL_ACCESS for the user only
        raise OSError(ctypes.get_last_error(), "AddAccessAllowedAce")
    sd = ctypes.create_string_buffer(64)                # SECURITY_DESCRIPTOR_MIN_LENGTH is 40 on 64-bit
    if not a.InitializeSecurityDescriptor(sd, 1):
        raise OSError(ctypes.get_last_error(), "InitializeSecurityDescriptor")
    if not a.SetSecurityDescriptorDacl(sd, True, acl, False):
        raise OSError(ctypes.get_last_error(), "SetSecurityDescriptorDacl")
    if not a.SetSecurityDescriptorControl(sd, 0x1000, 0x1000):   # SE_DACL_PROTECTED: nothing inherited
        raise OSError(ctypes.get_last_error(), "SetSecurityDescriptorControl")

    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                    ("bInheritHandle", wintypes.BOOL)]
    sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), ctypes.cast(sd, ctypes.c_void_p), False)
    h = k.CreateFileW(percorso, 0x40000000 | 0x20000, 0, ctypes.byref(sa),   # GENERIC_WRITE | READ_CONTROL
                      1, 0x80 | 0x00200000, None)        # CREATE_NEW; NORMAL | FILE_FLAG_OPEN_REPARSE_POINT
    if h is None or h == ctypes.c_void_p(-1).value:
        err = ctypes.get_last_error()
        if err in (80, 183):                             # ERROR_FILE_EXISTS, ERROR_ALREADY_EXISTS
            raise FileExistsError(17, "the path exists (a link included): the file must be new", percorso)
        raise OSError(err, "CreateFileW", percorso)
    try:
        return msvcrt.open_osfhandle(h, os.O_WRONLY | getattr(os, "O_BINARY", 0))
    except BaseException:
        k.CloseHandle(h)
        raise


def descrivi(fd: int) -> dict:
    """Windows diagnostics: owner SID and every DACL entry (type, flags, mask, SID) as filepriv reads them."""
    import msvcrt
    ctypes, wintypes, a, k = _win()
    owner, dacl, sd = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    err = a.GetSecurityInfo(msvcrt.get_osfhandle(fd), 1, 0x1 | 0x4, ctypes.byref(owner), None, ctypes.byref(dacl),
                            None, ctypes.byref(sd))
    if err:
        raise OSError(err, "GetSecurityInfo")
    try:
        voci = []
        n = ctypes.cast(dacl, ctypes.POINTER(ctypes.c_uint16))[2] if dacl.value else 0
        for i in range(n):
            ace = ctypes.c_void_p()
            if not a.GetAce(dacl, i, ctypes.byref(ace)):
                raise OSError(ctypes.get_last_error(), "GetAce")
            tipo, flag = ctypes.cast(ace, ctypes.POINTER(ctypes.c_ubyte))[0:2]
            maschera = ctypes.cast(ace.value + 4, ctypes.POINTER(ctypes.c_uint32))[0]
            sid = _sid_testo(ctypes, wintypes, a, k, ace.value + 8) if tipo in (0, 1) else "?"
            voci.append({"tipo": tipo, "flag": flag, "maschera": "0x%08x" % maschera, "sid": sid})
        return {"proprietario": _sid_testo(ctypes, wintypes, a, k, owner), "dacl": voci if dacl.value else None,
                "utente": sorted(utente())}
    finally:
        k.LocalFree(sd)


# ------------------------------------------------------------------ API

def apri_in_lettura(percorso: str):
    """Open without following a final link, without blocking: (descriptor, lstat taken before the open, or None).
    The caller compares the identity with `stesso_file` after its own fstat. Raises OSError (a link included) or
    NonPrivato on a system that is neither POSIX nor Windows."""
    if POSIX:
        return os.open(percorso, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)), None
    if not WINDOWS:
        raise NonPrivato("this system has neither POSIX nor Windows file ownership")
    from pq_scitt.strict_json import dispositivo_windows
    if dispositivo_windows(percorso):   # \\.\pipe\…: by name, before lstat (which would connect to the pipe)
        raise NonRegolare(percorso)
    prima = os.lstat(percorso)
    if stat.S_ISLNK(prima.st_mode) or getattr(prima, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise OSError(errno.ELOOP, "a link", percorso)               # as O_NOFOLLOW says it on POSIX
    if stat.S_ISDIR(prima.st_mode):
        raise NonRegolare(percorso)
    return os.open(percorso, os.O_RDONLY | getattr(os, "O_BINARY", 0)), prima


def stesso_file(prima, st: os.stat_result) -> bool:
    """Windows: the file opened is the one checked by lstat (same st_dev and st_ino). POSIX: O_NOFOLLOW did it."""
    return prima is None or not stat.S_ISREG(prima.st_mode) or (prima.st_dev, prima.st_ino) == (st.st_dev, st.st_ino)


def problema(fd: int, st: os.stat_result) -> Optional[str]:
    """None if the open file is private to the running user, otherwise the reason."""
    if WINDOWS:
        return _problema_windows(fd)
    if not POSIX:
        return "this system has neither POSIX nor Windows file ownership"
    if st.st_uid != utente():
        return "the owner is not the running user"
    if st.st_mode & 0o077:
        return "permissions %o, no permissions for group and others (e.g. 0600 or 0400)" % stat.S_IMODE(st.st_mode)
    return None


def crea_privato(percorso: str) -> int:
    """A NEW file (O_EXCL, never through a link) that only the running user can access, open for writing."""
    if POSIX:
        return os.open(percorso, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    if not WINDOWS:
        raise NonPrivato("this system has neither POSIX nor Windows file ownership")
    fd = _crea_windows(percorso)
    try:
        motivo = _problema_windows(fd)
        if motivo:
            raise NonPrivato(motivo)
    except BaseException:
        os.close(fd)
        try:
            os.unlink(percorso)
        except OSError:
            pass
        raise
    return fd
