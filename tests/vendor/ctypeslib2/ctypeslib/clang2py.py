#!/usr/bin/env python3

"""
clang2py - generate Python-friendly interfaces to C libraries, such as automatically generating Python classes
that represent C data structures, simplifying the process of wrapping C functions with Python functions,
and providing tools for handling errors and exceptions that may occur when calling C functions.

"""

import argparse
import logging
import os
import platform
import sys
import tempfile
import traceback

import ctypeslib
from ctypeslib import clang_version, clang_py_version
from ctypeslib.codegen import config
from ctypeslib.codegen.codegenerator import translate_files
from ctypeslib.codegen.handler import InvalidTranslationUnitException

################################################################
windows_dll_names = """\
imagehlp
user32
kernel32
gdi32
advapi32
oleaut32
ole32
imm32
comdlg32
shell32
version
winmm
mpr
winscard
winspool.drv
urlmon
crypt32
cryptnet
ws2_32
opengl32
glu32
mswsock
msvcrt
msimg32
netapi32
rpcrt4""".split()


# rpcndr
# ntdll


def _is_typedesc(item):
    for char in item:
        if char not in "acdefmstu":
            raise argparse.ArgumentTypeError("types choices are 'acdefmstu'")
    return item


class Input:
    """A context manager to abstract input file, files or stdin"""

    def __init__(self, options):
        self.files = []
        self._stdin = None
        for in_file in options.files:
            # stdin case
            if in_file == sys.stdin:
                # pylint: disable-next=consider-using-with
                _stdin = tempfile.NamedTemporaryFile(mode="w", prefix="stdin", suffix=".c", delete=False)
                _stdin.write(in_file.read())
                in_file = _stdin
            self.files.append(in_file.name)
            in_file.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, ecx_tb):
        if self._stdin:
            os.remove(self._stdin.name)
        return False


class Output:
    """A context manager to abstract out file or stdout"""

    def __init__(self, options):
        # handle output
        if options.output == "-":
            self.stream = sys.stdout
            self.output_file = None
        else:
            # pylint: disable-next=unspecified-encoding,consider-using-with
            self.stream = open(options.output, "w")
            self.output_file = self.stream

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, ecx_tb):
        if self.output_file is not None:
            self.output_file.close()
            # we do not want to delete the output file.
            # os.remove(self.output_file.name)
        # If an exception is supplied, and the method wishes to suppress the exception
        # (i.e., prevent it from being propagated), it should return a true value.
        return False


def _make_parser(cfg):
    """Build the argparse parser"""

    def windows_dlls(option, opt, value, _parser):  # pylint: disable=unused-argument
        _parser.values.dlls.extend(windows_dll_names)

    parser = argparse.ArgumentParser(
        prog="clang2py", description=f"Version {ctypeslib.__version__}. Generate python code from C headers"
    )
    parser.add_argument(
        "-c",
        "--comments",
        dest="generate_comments",
        action="store_true",
        help="include source doxygen-style comments",
        default=False,
    )
    parser.add_argument(
        "-d",
        "--doc",
        dest="generate_docstrings",
        action="store_true",
        help="include docstrings containing C prototype and source file location",
        default=False,
    )
    parser.add_argument("--debug", action="store_const", const=True, help="setLevel to DEBUG")
    parser.add_argument(
        "-e",
        "--show-definition-location",
        dest="generate_locations",
        action="store_true",
        help="include source file location in comments",
        default=False,
    )
    parser.add_argument(
        "-k",
        "--kind",
        action="store",
        dest="kind",
        help="kind of type descriptions to include: "
             "a = Alias,\n"
             "c = Class,\n"
             "d = Variable,\n"
             "e = Enumeration,\n"
             "f = Function,\n"
             "m = Macro, #define\n"
             "s = Structure,\n"
             "t = Typedef,\n"
             "u = Union\n"
             "default = 'cdefstu'\n",
        metavar="TYPEKIND",
        default="cdefstu",
        type=_is_typedesc,
    )

    parser.add_argument(
        "-i",
        "--includes",
        dest="generate_includes",
        action="store_true",
        help="include declaration defined outside of the sourcefiles",
        default=False,
    )

    parser.add_argument(
        "-l",
        "--include-library",
        dest="dll",
        help="library to search for exported functions. Add multiple times if required",
        action="append",
        default=[],
    )

    if os.name in ("ce", "nt"):
        default_modules = ["ctypes.wintypes"]
    else:
        default_modules = []  # ctypes is already imported

    parser.add_argument(
        "-m",
        "--module",
        dest="modules",
        metavar="module",
        help="Python module(s) containing symbols which will " "be imported instead of generated",
        action="append",
        default=default_modules,
    )

    parser.add_argument("--nm", dest="nm", default="nm", help="nm program to use to extract symbols from libraries")

    parser.add_argument(
        "-o",
        "--output",
        dest="output",
        help="output filename (if not specified, standard output will be used)",
        default="-",
    )
    # type=argparse.FileType('w'))

    parser.add_argument(
        "-p",
        "--preload",
        dest="preload",
        metavar="DLL",
        help="dll to be loaded before all others (to resolve symbols)",
        action="append",
        default=[],
    )

    parser.add_argument(
        "-q", "--quiet", action="store_const", const="quiet", help="Shut down warnings and below", default=False
    )

    parser.add_argument(
        "-r",
        "--regex",
        dest="expressions",
        metavar="EXPRESSION",
        action="append",
        help="regular expression for symbols to include "
             "(if neither symbols nor expressions are specified,"
             "everything will be included)",
        default=[],
    )

    parser.add_argument(
        "-s",
        "--symbol",
        dest="symbols",
        metavar="SYMBOL",
        action="append",
        help="symbol to include " "(if neither symbols nor expressions are specified," "everything will be included)",
        default=[],
    )

    parser.add_argument(
        "-t",
        "--target",
        dest="target",
        help=f"target architecture (default: {cfg.local_platform_triple})",
        default=None,
    )  # actually let clang alone decide.

    parser.add_argument("-v", "--verbose", action="store_true", dest="verbose", help="verbose output", default=False)

    def version_string():
        version = "versions - %(prog)s:" \
                  f"{ctypeslib.__version__} python-clang:{clang_py_version()} clang:{clang_version()} " \
                  f"clang_filename:{ctypeslib.__clang_library_filename}"  # pylint: disable=protected-access
        return version

    parser.add_argument("-V", "--version", action="version", version=version_string())

    parser.add_argument(
        "-w", action="store", default=windows_dlls, help="add all standard windows dlls to the searched dlls list"
    )

    parser.add_argument(
        "-x",
        "--exclude-includes",
        action="store_true",
        default=False,
        help="Parse object in sources files only. Ignore includes",
    )

    parser.add_argument("--show-ids", dest="showIDs", help="Don't compute cursor IDs (very slow)", default=False)

    parser.add_argument(
        "--max-depth", dest="maxDepth", help="Limit cursor expansion to depth N", metavar="N", type=int, default=None
    )

    parser.add_argument(
        "--validate", dest="validate", help="validate the python code is correct", type=bool, default=True
    )

    # we do support stdin
    parser.add_argument(
        "files", nargs="+", help="source filenames. use '-' for stdin ", type=argparse.FileType("r")
    )

    parser.add_argument(
        "--clang-args",
        action="store",
        default=None,
        required=False,
        help='clang options, in quotes: --clang-args="-std=c99 -Wall"',
        type=str,
    )

    parser.epilog = """Cross-architecture: You can pass target modifiers to clang.
    For example, try --clang-args="-target x86_64" or "-target i386-linux" to change the target CPU arch."""

    return parser


def main(argv=None):
    """entry point for clang2py"""
    if argv is None:
        argv = sys.argv[1:]
    cfg = config.CodegenConfig()
    cfg.local_platform_triple = f"{platform.machine()}-{platform.system()}"
    cfg.known_symbols = {}
    cfg.searched_dlls = []

    parser = _make_parser(cfg)
    options = parser.parse_args(argv)

    # cfg is the CodegenConfig, not the runtime config.
    level = logging.INFO
    if options.debug:
        level = logging.DEBUG
    elif options.quiet:
        level = logging.ERROR
    logging.basicConfig(level=level, stream=sys.stderr)

    # capture codegen options in config
    cfg.parse_options(options)

    # handle input files, and outputs
    try:
        with Input(options) as inputs, Output(options) as outputs:
            # start codegen
            if cfg.generate_comments:
                outputs.stream.write("# generated by 'clang2py'\n")
                outputs.stream.write(f"# flags '{' '.join(argv[1:])}'\n")

            # Preload libraries
            # [Library(name, mode=RTLD_GLOBAL) for name in options.preload]

            translate_files(inputs.files, outputs.stream, cfg)
    except InvalidTranslationUnitException:
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception:  # pylint: disable=broad-exception-caught
        # return non-zero exit status in case of an unhandled exception
        traceback.print_exc()
        sys.exit(1)
