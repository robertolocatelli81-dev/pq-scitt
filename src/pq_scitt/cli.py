"""pq-scitt command line: one entry point that hands the remaining arguments to the existing module functions.

    pq-scitt export ...                    pq_scitt.scitt.export._main
    pq-scitt verify ...                    pq_scitt.scitt.verify._main
    pq-scitt verify-ledger ...             pq_scitt.ledger.verify.main
    pq-scitt verify-ledger-standalone ...  pq_scitt.ledger.standalone.main
    pq-scitt kms ...                       pq_scitt.kms.main
    pq-scitt anchor-selftest               pq_scitt.anchors.slh_dsa.self_test (needs slh-dsa or liboqs-python)

Each subcommand keeps its own options and exit codes (`pq-scitt <subcommand> --help`). An unknown subcommand is an
error (exit 2), never a default.
"""
import sys

from pq_scitt import __version__


def _export(argv):
    from pq_scitt.scitt import export
    return export._main(argv)


def _verify(argv):
    from pq_scitt.scitt import verify
    return verify._main(argv)


def _verify_ledger(argv):
    from pq_scitt.ledger import verify
    return verify.main(argv)


def _verify_ledger_standalone(argv):
    from pq_scitt.ledger import standalone
    return standalone.main(argv)


def _kms(argv):
    from pq_scitt import kms
    return kms.main(argv)


def _anchor_selftest(argv):
    if argv:
        sys.stderr.write("pq-scitt anchor-selftest: no arguments expected\n")
        return 2
    from pq_scitt.anchors import slh_dsa
    return 0 if slh_dsa.self_test() else 1


COMANDI = {
    "export": _export,
    "verify": _verify,
    "verify-ledger": _verify_ledger,
    "verify-ledger-standalone": _verify_ledger_standalone,
    "kms": _kms,
    "anchor-selftest": _anchor_selftest,
}


def _uso():
    return "usage: pq-scitt {" + ",".join(COMANDI) + "} [arguments]\n       pq-scitt --version | --help\n"


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if not argv:
        sys.stderr.write(_uso())
        return 2
    if argv == ["--help"] or argv == ["-h"]:
        sys.stdout.write(_uso() + "\n" + __doc__)
        return 0
    if argv == ["--version"]:
        sys.stdout.write("pq-scitt " + __version__ + "\n")
        return 0
    comando = COMANDI.get(argv[0])
    if comando is None:
        sys.stderr.write("pq-scitt: unknown subcommand %r\n" % argv[0] + _uso())
        return 2
    return comando(argv[1:])


if __name__ == "__main__":
    sys.exit(main())
