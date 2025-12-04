import os
import subprocess
import sys
from ctypes import RTLD_LOCAL, RTLD_GLOBAL


class LibraryMeta(type):

    def __call__(cls, name, mode=RTLD_LOCAL, nm="nm"):

        if os.name == "nt":
            from ctypes import WinDLL
            # WinDLL does demangle the __stdcall names, so use that.
            return WinDLL(name, mode=mode)
        if os.path.exists(name) and mode != RTLD_GLOBAL and nm is not None:
            # Use 'nm' on Unixes to load native and cross-compiled libraries
            # (this is only possible if mode != RTLD_GLOBAL)
            return super(LibraryMeta, cls).__call__(name, nm)
        from ctypes import CDLL
        from ctypes.util import find_library
        path = find_library(name)
        if path is None:
            # Maybe 'name' is not a library name in the linker style,
            # give CDLL a last chance to find the library.
            path = name
        return CDLL(path, mode=mode)


class Library(metaclass=LibraryMeta):

    def __init__(self, filepath, nm):
        self._filepath = filepath
        self._name = os.path.basename(self._filepath)
        self.__symbols = {}
        self._get_symbols(nm)

    # nm will print lines like this:
    # <addr> <kind> <name>
    def _get_symbols(self, nm):

        cmd = [nm,]
        if sys.platform != 'darwin':
            # fix for #125, nm error "File format has no dynamic symbol table" for dylib
            cmd.append("--dynamic")
        cmd.extend(["--defined-only", self._filepath])
        output = subprocess.check_output(cmd, universal_newlines=True)
        for line in output.split('\n'):
            fields = line.split(' ', 2)
            if len(fields) >= 3 and fields[1] in ("T", "D", "G", "R", "S"):
                if '@@' in fields[2]: fields[2] = fields[2].split('@@')[0]
                self.__symbols[fields[2]] = fields[0]

    def __getattr__(self, name):
        try:
            return self.__symbols[name]
        except KeyError:
            pass
        raise AttributeError(name)


