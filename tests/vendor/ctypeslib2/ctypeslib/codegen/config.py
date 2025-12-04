"""
The configuration class that will modify the behavior of ctypeslib
"""
import os
import re
import subprocess
import sys

from ctypeslib.library import Library
from ctypeslib.codegen import typedesc


class CodegenConfig:
    # symbol to include, if empty, everything will be included
    symbols: list = []
    # regular expression for symbols to include
    expressions: list = []
    # verbose output
    verbose: bool = False
    # include source doxygen-style comments
    generate_comments: bool = False
    # include docstrings containing C prototype and source file location
    generate_docstrings: bool = False
    # include source file location in comments
    generate_locations: bool = False
    # do not include declaration defined outside the source files
    filter_location: bool = True
    # dll to be loaded before all others (to resolve symbols)
    preloaded_dlls: list = []
    # kind of type descriptions to include
    types: list = []
    # the host's triplet
    local_platform_triple: str = None
    #
    known_symbols: dict = {}
    #
    searched_dlls: list = []
    # clang preprocessor options
    clang_opts: list = []

    def __init__(self):
        self._init_types()
        self.clang_opts = []
        if sys.platform == 'darwin':
            try:
                sysroot = subprocess.check_output(['xcrun', '--show-sdk-path']).decode('utf8').strip()
            except subprocess.CalledProcessError:
                raise RuntimeError("The XCode Command Line Tools must be installed to provide the C standard library headers. Set CTYPESLIB2_SKIP_MACOS_SDK=1 in the environment to skip this check.")
            self.clang_opts.extend(['-isysroot', sysroot])

    def parse_options(self, options):
        self.symbols = options.symbols
        self.expressions = options.expressions
        if options.expressions:
            self.expressions = list(map(re.compile, options.expressions))
        self.verbose = options.verbose
        self.generate_comments = options.generate_comments
        self.generate_docstrings = options.generate_docstrings
        self.generate_locations = options.generate_locations
        self.filter_location = not options.generate_includes
        self.preloaded_dlls = options.preload
        # List exported symbols from libraries
        self.searched_dlls = [Library(name, nm=options.nm) for name in options.dll]
        self._parse_options_clang_opts(options)
        self._parse_options_modules(options)
        self._parse_options_types(options)

    _type_table = {"a": typedesc.Alias,
                   "c": typedesc.Structure,
                   "d": typedesc.Variable,
                   "e": typedesc.Enumeration,  # , typedesc.EnumValue],
                   "f": typedesc.Function,
                   "m": typedesc.Macro,
                   "s": typedesc.Structure,
                   "t": typedesc.Typedef,
                   "u": typedesc.Union,
                   }

    def _init_types(self, _default="cdefstu"):
        types = []
        for char in _default:
            typ = self._type_table[char]
            types.append(typ)
        self.types = types

    def _parse_options_types(self, options):
        """ Filter objects types """
        self._init_types(options.kind)

    def _parse_options_modules(self, options):
        # preload python modules with these names
        for name in options.modules:
            mod = __import__(name)
            for submodule in name.split(".")[1:]:
                mod = getattr(mod, submodule)
            for name, item in mod.__dict__.items():
                if isinstance(item, type):
                    self.known_symbols[name] = mod.__name__

    def _parse_options_clang_opts(self, options):
        if options.target is not None:
            self.clang_opts = ["-target", options.target]
        if options.clang_args is not None:
            self.clang_opts.extend(re.split("\s+", options.clang_args))

    @property
    def cross_arch(self):
        """
        Is there a cross architecture option in clang_opts
        """
        return '-target' in ' '.join(self.clang_opts)
