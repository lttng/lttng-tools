# From clang/bindings/python/cindex/test
# This file provides common utility functions for the test suite.
#

from clang.cindex import Cursor
from clang.cindex import TranslationUnit
from collections.abc import Iterable

import logging
import re

from ctypeslib.codegen import typedesc

log = logging.getLogger('utils')


def get_tu(source, lang='c', all_warnings=False, flags=None):
    """Obtain a translation unit from source and language.

    By default, the translation unit is created from source file "t.<ext>"
    where <ext> is the default file extension for the specified language. By
    default it is C, so "t.c" is the default file name.

    Supported languages are {c, cpp, objc}.

    all_warnings is a convenience argument to enable all compiler warnings.
    """
    args = list(flags or [])
    name = 'memory_input.c'
    if lang == 'cpp':
        name = 'memory_input.cpp'
        args.append('-std=c++11')
    elif lang == 'objc':
        name = 'memory_input.m'
    elif lang != 'c':
        raise Exception('Unknown language: %s' % lang)

    if all_warnings:
        args += ['-Wall', '-Wextra']

    return TranslationUnit.from_source(name, args, unsaved_files=[(name, source)])


def get_cursor(source, spelling):
    """Obtain a cursor from a source object.

    This provides a convenient search mechanism to find a cursor with specific
    spelling within a source. The first argument can be either a
    TranslationUnit or Cursor instance.

    If the cursor is not found, None is returned.
    """
    children = []
    if isinstance(source, Cursor):
        children = source.get_children()
    else:
        # Assume TU
        children = source.cursor.get_children()

    for cursor in children:
        if cursor.spelling == spelling:
            return cursor

        # Recurse into children.
        result = get_cursor(cursor, spelling)
        if result is not None:
            return result

    return None


def get_cursors(source, spelling):
    """Obtain all cursors from a source object with a specific spelling.

    This provides a convenient search mechanism to find all cursors with specific
    spelling within a source. The first argument can be either a
    TranslationUnit or Cursor instance.

    If no cursors are found, an empty list is returned.
    """
    cursors = []
    children = []
    if isinstance(source, Cursor):
        children = source.get_children()
    else:
        # Assume TU
        children = source.cursor.get_children()

    for cursor in children:
        if cursor.spelling == spelling:
            cursors.append(cursor)

        # Recurse into children.
        cursors.extend(get_cursors(cursor, spelling))

    return cursors


def decorator(dec):
    def new_decorator(f):
        g = dec(f)
        g.__name__ = f.__name__
        g.__doc__ = f.__doc__
        g.__dict__.update(f.__dict__)
        return g
    new_decorator.__name__ = dec.__name__
    new_decorator.__doc__ = dec.__doc__
    new_decorator.__dict__.update(dec.__dict__)
    return new_decorator


@decorator
def log_entity(func):
    def fn(*args, **kwargs):
        name = args[0].get_unique_name(args[1])
        if name == '':
            parent = getattr(args[1], 'semantic_parent', None)
            if parent:
                name = 'child of %s' % parent.displayname
        log.debug("%s: displayname:'%s'",func.__name__, name)
        # print 'calling {}'.format(func.__name__)
        return func(*args, **kwargs)
    return fn


class ADict(dict):

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)


_c_literal_regex = re.compile(
    r"^([+-]?((\d+(e|E)[+-]?\d+)|(\d+(\.\d*)?((e|E)[+-]?\d+)?)|(\.\d+((e|E)[+-]?\d+)?)))(f|F|l|L)?$"
)


def from_c_float_literal(value):
    if (not isinstance(value, str) and
            isinstance(value, Iterable) and
            all(map(lambda v: isinstance(v, str), value))):
        value = "".join(value)
    if not isinstance(value, str):
        return None
    match = _c_literal_regex.match(value)
    if not match:
        return None
    return match.group(1)


def contains_undefined_identifier(macro):
    # body is undefined
    if isinstance(macro.body, typedesc.UndefinedIdentifier):
        return True

    def _list_contains_undefined_identifier(l):
        for b in l:
            if isinstance(b, typedesc.UndefinedIdentifier):
                return True
            if isinstance(b, list) and _list_contains_undefined_identifier(b):
                return True
        return False

    # or one item is undefined
    if isinstance(macro.body, list):
        if _list_contains_undefined_identifier(macro.body):
            return True

    return False


def token_is_string(token):
    # we need at list 2 delimiters in there
    if not isinstance(token, Iterable) or len(token) < 2:
        return False
    delim = token[0]
    return delim in ["'", '"'] and token[0] == token[-1]


def body_is_all_string_tokens(macro_body):
    if isinstance(macro_body, list):
        for b in macro_body:
            if token_is_string(b):
                continue
            else:
                return False
        return True
    return False


__all__ = [
    'get_cursor',
    'get_cursors',
    'get_tu',
    'from_c_float_literal',
    'log_entity'
]
