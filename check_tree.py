#!/usr/bin/env python3
"""check_tree.py — the repository holds ONLY what is listed in FILE_LIST.tsv.

Fails (exit 1) with one reason per defect found:
  1. a file in the repository that is not listed, a listed file that is missing, a sha256 different from the listed one;
  2. an import of a module that is not allowed (allowed: the standard library, the listed modules of src/pq_scitt and of
     the tests, and a closed list of third-party packages);
  3. a string matching a deny-list of generic rules (home-directory paths, hidden folders under ~, e-mail addresses,
     tailnet host names and addresses);
  4. a secret found by gitleaks (gitleaks missing = error, not a skip).
--positive-control copies the repository to a temporary folder, checks that the untouched copy passes and that each of
six alterations (import of a module that is not allowed, unlisted file, deleted listed file, home-directory path, hidden
folder under ~, fake secret) makes it fail with the expected reason, and that --update makes an edited copy, and a copy
with a file added and one deleted, pass again; and that the command line --update changes only the edited
line, still fails on a defect left, and refuses an extra argument.
--update rewrites FILE_LIST.tsv: new sha256 for the listed files, unlisted files added with kind "new", entries of
missing files removed; it prints every change (review them in the diff), then runs the checks.
"""
import ast
import hashlib
import os
import re
import secrets
import shutil
import string
import subprocess
import sys
import tempfile

ELENCO = "FILE_LIST.tsv"
KINDS = ("copy", "derived", "new")
TERZE_PARTI = {"cryptography", "slhdsa", "oqs", "boto3", "botocore"}
# modules absent from the repository, imported only inside a try that treats their absence as an error (failed, not skipped)
ASSENTI_DICHIARATI = {("src/pq_scitt/ledger/standalone.py", "cryptovalid_tip")}
RADICE_PACCHETTO = "pq_scitt"
SRC = "src/"
REGOLE = [  # split in two pieces so that this file does not match itself
    ("percorso_di_casa", re.compile("/ho" + r"me/[A-Za-z0-9_.-]+")),
    ("cartella_nascosta_di_casa", re.compile(r"~/\." + r"[A-Za-z]")),
    ("host_tailnet", re.compile(r"[A-Za-z0-9-]+\.ts" + r"\.net\b")),
    ("ip_tailnet", re.compile(r"\b10" + r"0\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}\b")),
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@(?!example\.(?:com|org|net)\b)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")),
]


def sha256(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def file_del_repo(radice):
    r = subprocess.run(["git", "-C", radice, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                       capture_output=True)
    if r.returncode != 0:
        raise SystemExit("ERROR git ls-files: " + r.stderr.decode(errors="replace").strip())
    # a file deleted from the working tree but still in the git index is not in the repository any more: it is then
    # reported as "listed_file_missing" (and dropped by --update) instead of crashing on open()
    return sorted({p for p in r.stdout.decode("utf-8").split("\0") if p and os.path.lexists(os.path.join(radice, p))})


def leggi_elenco(radice, difetti):
    voci = {}
    with open(os.path.join(radice, ELENCO), encoding="utf-8") as f:
        for n, riga in enumerate(f, 1):
            riga = riga.rstrip("\n")
            if not riga or riga.startswith("#"):
                continue
            c = riga.split("\t")
            if len(c) != 4 or c[2] not in KINDS or not re.fullmatch(r"[0-9a-f]{64}", c[1]) \
                    or not (c[3] == "-" or re.fullmatch(r"[0-9a-f]{64}", c[3])) or (c[2] == "new") != (c[3] == "-"):
                difetti.append(f"list_malformed line {n}")
                continue
            if c[0] in voci:
                difetti.append(f"list_duplicate {c[0]}")
            voci[c[0]] = c[1]
    return voci


def moduli_ammessi(radice, voci):
    """nudi: names of the test modules outside src/; qualificati: modules and packages of src/; nomi_pacchetto: for each
    package, the names assigned at the top level of its __init__.py (for "from pq_scitt import __version__")."""
    nudi, qualificati, nomi_pacchetto = set(), set(), {}
    for p in voci:
        if not p.endswith(".py"):
            continue
        if not p.startswith(SRC):
            nudi.add(p[:-3].split("/")[-1])
            continue
        parti = p[len(SRC):-3].split("/")
        if parti[-1] == "__init__":
            nome = ".".join(parti[:-1])
            nomi = set()
            try:
                with open(os.path.join(radice, p), encoding="utf-8") as f:
                    corpo = ast.parse(f.read()).body
            except (OSError, SyntaxError, UnicodeDecodeError):
                corpo = []
            for n in corpo:
                if isinstance(n, ast.Assign):
                    nomi |= {t.id for t in n.targets if isinstance(t, ast.Name)}
            nomi_pacchetto[nome] = nomi
        else:
            nome = ".".join(parti)
        qualificati.add(nome)
    return nudi - {"__init__"}, qualificati, nomi_pacchetto


def controlla_import(percorso, testo, nudi, qualificati, nomi_pacchetto, difetti):
    try:
        albero = ast.parse(testo, filename=percorso)
    except SyntaxError as e:
        difetti.append(f"syntax {percorso}: {e.msg}")
        return
    std = set(sys.stdlib_module_names)

    def ammesso(nome):
        if (percorso, nome) in ASSENTI_DICHIARATI:
            return True
        testa = nome.split(".")[0]
        if testa == RADICE_PACCHETTO:
            if nome in qualificati:
                return True
            pacchetto, _, attributo = nome.rpartition(".")
            return attributo in nomi_pacchetto.get(pacchetto, ())
        return testa in std or testa in TERZE_PARTI or nome in nudi

    for n in ast.walk(albero):
        nomi = []
        if isinstance(n, ast.Import):
            nomi = [a.name for a in n.names]
        elif isinstance(n, ast.ImportFrom):
            if n.level:
                difetti.append(f"relative_import {percorso}:{n.lineno}")
                continue
            if n.module in nomi_pacchetto:
                nomi = [n.module + "." + a.name for a in n.names]
            else:
                nomi = [n.module]
        elif isinstance(n, ast.Call) and isinstance(n.func, (ast.Name, ast.Attribute)) \
                and (getattr(n.func, "id", None) == "__import__" or getattr(n.func, "attr", None) == "import_module"):
            if n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str):
                nomi = [n.args[0].value]
            else:
                difetti.append(f"dynamic_import_not_literal {percorso}:{n.lineno}")
        for nome in nomi:
            if not ammesso(nome):
                difetti.append(f"import_not_allowed {percorso}:{n.lineno} {nome}")


def controlla_stringhe(percorso, testo, difetti):
    for nome, rx in REGOLE:
        for m in rx.finditer(testo):
            difetti.append(f"deny_list {percorso}:{testo.count(chr(10), 0, m.start()) + 1} rule {nome}")


def gitleaks(radice, difetti):
    exe = shutil.which("gitleaks")
    if not exe:
        difetti.append("gitleaks_missing: install it (the secret scan is never skipped)")
        return
    comandi = [[exe, "dir", radice, "--no-banner", "--redact", "--exit-code", "1"]]
    if subprocess.run(["git", "-C", radice, "rev-parse", "--verify", "-q", "HEAD"], capture_output=True).returncode == 0:
        comandi.append([exe, "git", radice, "--no-banner", "--redact", "--exit-code", "1"])
    for c in comandi:
        r = subprocess.run(c, capture_output=True, text=True)
        if r.returncode == 1:
            difetti.append(f"secret found by gitleaks {c[1]}: " + (r.stdout + r.stderr).strip().splitlines()[-1][:200])
        elif r.returncode != 0:
            difetti.append(f"gitleaks {c[1]} error rc={r.returncode}")


def controlla(radice):
    difetti = []
    if not os.path.isfile(os.path.join(radice, ELENCO)):
        return [f"list_missing {ELENCO}"]
    voci = leggi_elenco(radice, difetti)
    nel_repo = file_del_repo(radice)
    for p in nel_repo:
        if p == ELENCO:
            continue
        if p not in voci:
            difetti.append(f"file_not_listed {p}")
        elif sha256(os.path.join(radice, p)) != voci[p]:
            difetti.append(f"sha256_differs {p}")
    for p in sorted(set(voci) - set(nel_repo)):
        difetti.append(f"listed_file_missing {p}")
    nudi, qualificati, nomi_pacchetto = moduli_ammessi(radice, voci)
    for p in nel_repo:
        try:
            with open(os.path.join(radice, p), encoding="utf-8") as f:
                testo = f.read()
        except (UnicodeDecodeError, OSError) as e:
            difetti.append(f"unreadable {p}: {type(e).__name__}")
            continue
        if p.endswith(".py"):
            controlla_import(p, testo, nudi, qualificati, nomi_pacchetto, difetti)
        controlla_stringhe(p, testo, difetti)
    gitleaks(radice, difetti)
    return difetti


def aggiorna(radice):
    """--update: rewrite FILE_LIST.tsv from the files in the repository; print every change."""
    percorso = os.path.join(radice, ELENCO)
    with open(percorso, encoding="utf-8") as f:
        righe = f.read().splitlines()
    nel_repo = [p for p in file_del_repo(radice) if p != ELENCO]
    visti, nuove = set(), []
    for riga in righe:
        c = riga.split("\t")
        if not riga or riga.startswith("#") or len(c) != 4:
            nuove.append(riga)
            continue
        if c[0] not in nel_repo:
            print(f"removed {c[0]}")
            continue
        visti.add(c[0])
        h = sha256(os.path.join(radice, c[0]))
        if h != c[1]:
            print(f"sha256 updated {c[0]}")
            c[1] = h
        nuove.append("\t".join(c))
    for p in nel_repo:
        if p not in visti:
            print(f"added {p} (kind new)")
            nuove.append("\t".join((p, sha256(os.path.join(radice, p)), "new", "-")))
    with open(percorso, "w", encoding="utf-8") as f:
        f.write("\n".join(nuove) + "\n")


def controllo_positivo(radice):
    def copia():
        d = tempfile.mkdtemp(prefix="positive_control_")
        for p in file_del_repo(radice) + [ELENCO]:
            os.makedirs(os.path.join(d, os.path.dirname(p)), exist_ok=True)
            shutil.copy2(os.path.join(radice, p), os.path.join(d, p))
        subprocess.run(["git", "-C", d, "init", "-q"], check=True)
        return d

    def aggiungi(d, p, testo):
        with open(os.path.join(d, p), "a", encoding="utf-8") as f:
            f.write(testo)

    def indicizza(d):   # the deleted file stays in the git index, as in a clone where it was not "git rm"-ed
        subprocess.run(["git", "-C", d, "add", "-A"], check=True)

    finto = "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
    casi = [
        ("untouched", lambda d: None, None),
        ("import of a module that is not allowed", lambda d: aggiungi(d, "src/pq_scitt/__init__.py", "\nimport numpy\n"),
         "import_not_allowed"),
        ("unlisted file", lambda d: aggiungi(d, "src/pq_scitt/extraneous.py", "X = 1\n"), "file_not_listed"),
        ("home-directory path", lambda d: aggiungi(d, "README.md", "\n/ho" + "me/alice/project\n"), "deny_list"),
        ("hidden folder under ~", lambda d: aggiungi(d, "README.md", "\n~/" + ".config/x\n"), "deny_list"),
        ("edited file, then --update", lambda d: (aggiungi(d, "README.md", "\nedited\n"), aggiorna(d)), None),
        ("listed file deleted, still in the git index",
         lambda d: (indicizza(d), os.remove(os.path.join(d, "tests", "test_cli.py"))), "listed_file_missing"),
        ("files added and deleted, then --update",
         lambda d: (indicizza(d), aggiungi(d, "src/pq_scitt/extraneous.py", "X = 1\n"),
                    os.remove(os.path.join(d, "tests", "test_cli.py")), aggiorna(d)), None),
        ("fake secret", lambda d: aggiungi(d, "README.md", f'\ngithub_token = "{finto}"\n'), "secret"),
    ]
    esito = 0
    for nome, altera, atteso in casi:
        d = copia()
        try:
            altera(d)
            dif = controlla(d)
        finally:
            shutil.rmtree(d)
        if atteso is None:
            ok = not dif
        else:
            ok = any(x.startswith(atteso) for x in dif)
        print(f"{'OK ' if ok else 'KO '} {nome}: {len(dif)} defects" + (f", expected \"{atteso}\"" if atteso else "")
              + ("" if ok else " -> " + "; ".join(dif[:5])))
        esito |= not ok
    # the command line: --update rewrites only what changed and still runs the checks; extra arguments are refused
    casi_cli = [
        ("--update after an edit", ["--update"], lambda d: aggiungi(d, "README.md", "\nedited\n"), 0, 1),
        ("--update with a defect left", ["--update"], lambda d: aggiungi(d, "README.md", "\n/ho" + "me/alice/x\n"), 1, 1),
        ("--update with an extra argument", ["--update", "--update"], lambda d: None, 2, 0),
    ]
    for nome, argv, altera, rc_atteso, righe_attese in casi_cli:
        d = copia()
        try:
            with open(os.path.join(d, ELENCO), encoding="utf-8") as f:
                prima = f.read().split("\n")
            altera(d)
            rc = subprocess.run([sys.executable, os.path.join(d, "check_tree.py")] + argv, capture_output=True).returncode
            with open(os.path.join(d, ELENCO), encoding="utf-8") as f:
                dopo = f.read().split("\n")
        finally:
            shutil.rmtree(d)
        righe = sum(x != y for x, y in zip(prima, dopo)) + abs(len(prima) - len(dopo))
        ok = rc == rc_atteso and righe == righe_attese
        print(f"{'OK ' if ok else 'KO '} {nome}: exit {rc}, {righe} lines of {ELENCO} changed"
              + ("" if ok else f" (expected exit {rc_atteso}, {righe_attese} lines)"))
        esito |= not ok
    return esito


def main():
    radice = os.path.dirname(os.path.abspath(__file__))
    if sys.argv[1:] == ["--positive-control"]:
        return controllo_positivo(radice)
    if sys.argv[1:] == ["--update"]:
        aggiorna(radice)
    elif sys.argv[1:]:
        print("usage: check_tree.py [--positive-control | --update]")
        return 2
    difetti = controlla(radice)
    for d in difetti:
        print(d)
    print(f"{'FAILED' if difetti else 'OK'}: {len(difetti)} defects")
    return 1 if difetti else 0


if __name__ == "__main__":
    sys.exit(main())
