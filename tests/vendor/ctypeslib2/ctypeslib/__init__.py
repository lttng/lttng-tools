# -*- coding: utf-8 -*-
"""
ctypeslib2 package

ctypeslib2 helps generate Python-friendly interfaces to C libraries, such as automatically generating Python classes
that represent C data structures, simplifying the process of wrapping C functions with Python functions,
and providing tools for handling errors and exceptions that may occur when calling C functions.

"""

import ctypes
import os
import re
import sys
import warnings
from ctypes.util import find_library

import importlib.metadata
from importlib.metadata import PackageNotFoundError

try:
    __version__ = importlib.metadata.version('ctypeslib22')
except PackageNotFoundError:
    __version__ = 'Please install the latest version of this python package'


def __find_clang_libraries():
    """ configure python-clang to use the local clang library """
    _libs = []
    # try for a file with a version match with the clang python package version
    version_major = __clang_py_version__.split('.')[0]
    # try default system name
    v_list = [f"clang-{__clang_py_version__}", f"clang-{version_major}", "libclang", "clang"]
    # tries clang version 16 to 7
    v_list += [f"clang-{_}" for _ in range(16, 6, -1)]
    # with the dotted form of clang 6.0 to 4.0
    v_list += [f"clang-{_:.1f}" for _ in range(6, 3, -1)]
    # clang 3 supported versions
    v_list += ["clang-3.9", "clang-3.8", "clang-3.7"]
    for _version in v_list:
        _filename = find_library(_version)
        if _filename:
            _libs.append(_filename)
    # On darwin, also consider either Xcode or CommandLineTools.
    if os.name == "posix" and sys.platform == "darwin":
        for _ in ['/Library/Developer/CommandLineTools/usr/lib/libclang.dylib',
                  '/Applications/Xcode.app/Contents/Frameworks/libclang.dylib',
                  ]:
            if os.path.exists(_):
                _libs.insert(0, _)
    return _libs


def clang_version():
    """Pull the clang C library version from the API"""
    # avoid loading the cindex API (cindex.conf.lib) to avoid version conflicts
    get_version = cindex.conf.get_cindex_library().clang_getClangVersion
    get_version.restype = ctypes.c_char_p
    version_string = get_version()
    version = 'Unknown'
    if version_string and len(version_string) > 0:
        version_groups = re.match(br'.+version ((\d+\.)?(\d+\.)?(\*|\d+))', version_string)
        if version_groups and len(version_groups.groups()) > 0:
            version = version_groups.group(1).decode()
    return version


def clang_py_version():
    """Return the python clang package version"""
    return __clang_py_version__


def __configure_clang_cindex():
    """
    First we attempt to configure clang with the library path set in environment variable
    Second we attempt to configure clang with a clang library version similar to the clang python package version
    Third we attempt to configure clang with any clang library we can find
    """
    # first, use environment variables set by user
    __libs = []
    __lib_path = os.environ.get('CLANG_LIBRARY_PATH')
    if __lib_path is not None:
        if not os.path.exists(__lib_path):
            warnings.warn("Filepath in CLANG_LIBRARY_PATH does not exist", RuntimeWarning)
        else:
            __libs.append(__lib_path)
    __libs.extend(__find_clang_libraries())
    for __library_path in __libs:
        try:
            if os.path.isdir(__library_path):
                cindex.Config.set_library_path(__library_path)
            else:
                cindex.Config.set_library_file(__library_path)
            # force-check that clang is configured properly
            clang_version()
        except cindex.LibclangError:
            warnings.warn(f"Could not configure clang with library_path={__library_path}", RuntimeWarning)
            continue
        return __library_path
    return None


# check which clang python module is available
# check which clang library is available
try:
    from clang import cindex
    from ctypeslib.codegen.codegenerator import translate, translate_files

    __clang_py_version__ = importlib.metadata.version('clang')
    __clang_library_filename = __configure_clang_cindex()
    if __clang_library_filename is None:
        warnings.warn("Could not find the clang library. please install llvm libclang", RuntimeWarning)
        # do not fail - maybe the user has a plan
    else:
        # set a warning if major versions differs.
        if clang_version().split('.')[0] != clang_py_version().split('.')[0]:
            clang_major = clang_version().split('.')[0]
            warnings.warn(f"Version of python-clang ({clang_py_version()}) and "
                          f"clang C library ({clang_version()}) are different. "
                          f"Did you try pip install clang=={clang_major}.*", RuntimeWarning)
except ImportError as e:
    __clang_py_version__ = None
    warnings.warn("Could not find a version of python-clang installed. "
                  "Please pip install clang==<version>.*", RuntimeWarning)
    raise e


__all__ = ['translate', 'translate_files', 'clang_version', 'clang_py_version']
