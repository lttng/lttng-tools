# SPDX-FileCopyrightText: 2023-2026 Philippe Proulx <eeppeliteloop@gmail.com>
# SPDX-License-Identifier: MIT
#
# The MIT License (MIT)
#
# Copyright (c) 2023-2026 Philippe Proulx <eeppeliteloop@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# This module is the portable Normand processor. It offers both the
# parse() function and the command-line tool (run the module itself)
# without external dependencies.
#
# Feel free to copy this module file to your own project to use Normand.
#
# Upstream repository: <https://github.com/efficios/normand>.

__author__ = "Philippe Proulx"
__version__ = "0.24.1"
__all__ = [
    "__author__",
    "__version__",
    "ByteOrder",
    "LabelsT",
    "parse",
    "ParseError",
    "ParseErrorMessage",
    "ParseResult",
    "TextLocation",
    "VariablesT",
]

import io
import re
import abc
import ast
import bz2
import sys
import copy
import enum
import gzip
import math
import base64
import quopri
import struct
import typing
import functools
from typing import Any, Set, Dict, List, Union, Pattern, Callable, NoReturn, Optional


# Text location (line and column numbers).
class TextLocation:
    @classmethod
    def _create(cls, line_no: int, col_no: int):
        self = cls.__new__(cls)
        self._init(line_no, col_no)
        return self

    def __init__(*args, **kwargs):  # type: ignore
        raise NotImplementedError

    def _init(self, line_no: int, col_no: int):
        self._line_no = line_no
        self._col_no = col_no

    # Line number.
    @property
    def line_no(self):
        return self._line_no

    # Column number.
    @property
    def col_no(self):
        return self._col_no

    def __repr__(self):
        return f"TextLocation({self._line_no}, {self._col_no})"


# Any item.
class _Item:
    def __init__(self, text_loc: TextLocation):
        self._text_loc = text_loc

    # Source text location.
    @property
    def text_loc(self):
        return self._text_loc


# Scalar item.
class _ScalarItem(_Item):
    # Returns the size, in bytes, of this item.
    @property
    @abc.abstractmethod
    def size(self) -> int: ...


# A repeatable item.
class _RepableItem:
    pass


# Single byte.
class _Byte(_ScalarItem, _RepableItem):
    def __init__(self, val: int, text_loc: TextLocation):
        super().__init__(text_loc)
        self._val = val

    # Byte value.
    @property
    def val(self):
        return self._val

    @property
    def size(self):
        return 1

    def __repr__(self):
        return f"_Byte({hex(self._val)}, {self._text_loc!r})"


# Literal string.
class _LitStr(_ScalarItem, _RepableItem):
    def __init__(self, data: bytes, text_loc: TextLocation):
        super().__init__(text_loc)
        self._data = data

    # Encoded bytes.
    @property
    def data(self):
        return self._data

    @property
    def size(self):
        return len(self._data)

    def __repr__(self):
        return f"_LitStr({self._data!r}, {self._text_loc!r})"


# Byte order.
@enum.unique
class ByteOrder(enum.Enum):
    # Big endian.
    BE = "be"

    # Little endian.
    LE = "le"


# Byte order setting.
class _SetBo(_Item):
    def __init__(self, bo: ByteOrder, text_loc: TextLocation):
        super().__init__(text_loc)
        self._bo = bo

    @property
    def bo(self):
        return self._bo

    def __repr__(self):
        return f"_SetBo({self._bo!r}, {self._text_loc!r})"


# Label.
class _Label(_Item):
    def __init__(self, name: str, text_loc: TextLocation):
        super().__init__(text_loc)
        self._name = name

    # Label name.
    @property
    def name(self):
        return self._name

    def __repr__(self):
        return f"_Label({self._name!r}, {self._text_loc!r})"


# Offset setting.
class _SetOffset(_Item):
    def __init__(self, val: int, text_loc: TextLocation):
        super().__init__(text_loc)
        self._val = val

    # Offset value (bytes).
    @property
    def val(self):
        return self._val

    def __repr__(self):
        return f"_SetOffset({self._val!r}, {self._text_loc!r})"


# Offset alignment.
class _AlignOffset(_Item):
    def __init__(self, val: int, pad_val: int, text_loc: TextLocation):
        super().__init__(text_loc)
        self._val = val
        self._pad_val = pad_val

    # Alignment value (bits).
    @property
    def val(self):
        return self._val

    # Padding byte value.
    @property
    def pad_val(self):
        return self._pad_val

    def __repr__(self):
        return f"_AlignOffset({self._val!r}, {self._pad_val!r}, {self._text_loc!r})"


# Mixin of containing an AST expression and its string.
class _ExprMixin:
    def __init__(self, expr_str: str, expr: ast.Expression):
        self._expr_str = expr_str
        self._expr = expr

    # Expression string.
    @property
    def expr_str(self):
        return self._expr_str

    # Expression node to evaluate.
    @property
    def expr(self):
        return self._expr


# Fill until some offset.
class _FillUntil(_Item, _ExprMixin):
    def __init__(
        self, expr_str: str, expr: ast.Expression, pad_val: int, text_loc: TextLocation
    ):
        super().__init__(text_loc)
        _ExprMixin.__init__(self, expr_str, expr)
        self._pad_val = pad_val

    # Padding byte value.
    @property
    def pad_val(self):
        return self._pad_val

    def __repr__(self):
        return f"_FillUntil({self._expr_str!r}, {self._expr!r}, {self._pad_val!r}, {self._text_loc!r})"


# Variable assignment.
class _VarAssign(_Item, _ExprMixin):
    def __init__(
        self, name: str, expr_str: str, expr: ast.Expression, text_loc: TextLocation
    ):
        super().__init__(text_loc)
        _ExprMixin.__init__(self, expr_str, expr)
        self._name = name

    # Name.
    @property
    def name(self):
        return self._name

    def __repr__(self):
        return f"_VarAssign({self._name!r}, {self._expr_str!r}, {self._expr!r}, {self._text_loc!r})"


# Fixed-length number, possibly needing more than one byte.
class _FlNum(_ScalarItem, _RepableItem, _ExprMixin):
    def __init__(
        self,
        expr_str: str,
        expr: ast.Expression,
        len: int,
        bo: Optional[ByteOrder],
        text_loc: TextLocation,
    ):
        super().__init__(text_loc)
        _ExprMixin.__init__(self, expr_str, expr)
        self._len = len
        self._bo = bo

    # Length (bits).
    @property
    def len(self):
        return self._len

    # Byte order override.
    @property
    def bo(self):
        return self._bo

    @property
    def size(self):
        return self._len // 8

    def __repr__(self):
        return f"_FlNum({self._expr_str!r}, {self._expr!r}, {self._len!r}, {self._bo!r}, {self._text_loc!r})"


# LEB128 integer.
class _Leb128Int(_Item, _RepableItem, _ExprMixin):
    def __init__(self, expr_str: str, expr: ast.Expression, text_loc: TextLocation):
        super().__init__(text_loc)
        _ExprMixin.__init__(self, expr_str, expr)

    def __repr__(self):
        return f"{self.__class__.__name__}({self._expr_str!r}, {self._expr!r}, {self._text_loc!r})"


# Unsigned LEB128 integer.
class _ULeb128Int(_Leb128Int, _RepableItem, _ExprMixin):
    pass


# Signed LEB128 integer.
class _SLeb128Int(_Leb128Int, _RepableItem, _ExprMixin):
    pass


# String.
class _Str(_Item, _RepableItem, _ExprMixin):
    def __init__(
        self, expr_str: str, expr: ast.Expression, codec: str, text_loc: TextLocation
    ):
        super().__init__(text_loc)
        _ExprMixin.__init__(self, expr_str, expr)
        self._codec = codec

    # Codec name.
    @property
    def codec(self):
        return self._codec

    def __repr__(self):
        return f"_Str({self._expr_str!r}, {self._expr!r}, {self._codec!r}, {self._text_loc!r})"


# Group of items.
class _Group(_Item, _RepableItem):
    def __init__(self, items: List[_Item], text_loc: TextLocation):
        super().__init__(text_loc)
        self._items = items

    # Contained items.
    @property
    def items(self):
        return self._items

    def __repr__(self):
        return f"_Group({self._items!r}, {self._text_loc!r})"


# Repetition item.
class _Rep(_Group, _ExprMixin):
    def __init__(
        self,
        items: List[_Item],
        expr_str: str,
        expr: ast.Expression,
        text_loc: TextLocation,
    ):
        super().__init__(items, text_loc)
        _ExprMixin.__init__(self, expr_str, expr)

    def __repr__(self):
        return f"_Rep({self._items!r}, {self._expr_str!r}, {self._expr!r}, {self._text_loc!r})"


# Conditional item.
class _Cond(_Item, _ExprMixin):
    def __init__(
        self,
        true_item: _Group,
        false_item: _Group,
        expr_str: str,
        expr: ast.Expression,
        text_loc: TextLocation,
    ):
        super().__init__(text_loc)
        _ExprMixin.__init__(self, expr_str, expr)
        self._true_item = true_item
        self._false_item = false_item

    # Item when condition is true.
    @property
    def true_item(self):
        return self._true_item

    # Item when condition is false.
    @property
    def false_item(self):
        return self._false_item

    def __repr__(self):
        return f"_Cond({self._true_item!r}, {self._false_item!r}, {self._expr_str!r}, {self._expr!r}, {self._text_loc!r})"


# Transformation.
class _Trans(_Group, _RepableItem):
    def __init__(
        self,
        items: List[_Item],
        name: str,
        func: Callable[[Union[bytes, bytearray]], bytes],
        text_loc: TextLocation,
    ):
        super().__init__(items, text_loc)
        self._name = name
        self._func = func

    @property
    def name(self):
        return self._name

    # Transforms the data `data`.
    def trans(self, data: Union[bytes, bytearray]):
        return self._func(data)

    def __repr__(self):
        return f"_Trans({self._items!r}, {self._name!r}, {self._func!r}, {self._text_loc!r})"


# Macro definition item.
class _MacroDef(_Group):
    def __init__(
        self,
        name: str,
        param_names: List[str],
        items: List[_Item],
        text_loc: TextLocation,
    ):
        super().__init__(items, text_loc)
        self._name = name
        self._param_names = param_names

    # Name.
    @property
    def name(self):
        return self._name

    # Parameters.
    @property
    def param_names(self):
        return self._param_names

    def __repr__(self):
        return f"_MacroDef({self._name!r}, {self._param_names!r}, {self._items!r}, {self._text_loc!r})"


# Macro expansion parameter.
class _MacroExpParam:
    def __init__(self, expr_str: str, expr: ast.Expression, text_loc: TextLocation):
        self._expr_str = expr_str
        self._expr = expr
        self._text_loc = text_loc

    # Expression string.
    @property
    def expr_str(self):
        return self._expr_str

    # Expression.
    @property
    def expr(self):
        return self._expr

    # Source text location.
    @property
    def text_loc(self):
        return self._text_loc

    def __repr__(self):
        return f"_MacroExpParam({self._expr_str!r}, {self._expr!r}, {self._text_loc!r})"


# Macro expansion item.
class _MacroExp(_Item, _RepableItem):
    def __init__(
        self,
        name: str,
        params: List[_MacroExpParam],
        text_loc: TextLocation,
    ):
        super().__init__(text_loc)
        self._name = name
        self._params = params

    # Name.
    @property
    def name(self):
        return self._name

    # Parameters.
    @property
    def params(self):
        return self._params

    def __repr__(self):
        return f"_MacroExp({self._name!r}, {self._params!r}, {self._text_loc!r})"


# A parsing error message: a string and a text location.
class ParseErrorMessage:
    @classmethod
    def _create(cls, text: str, text_loc: TextLocation):
        self = cls.__new__(cls)
        self._init(text, text_loc)
        return self

    def __init__(self, *args, **kwargs):  # type: ignore
        raise NotImplementedError

    def _init(self, text: str, text_loc: TextLocation):
        self._text = text
        self._text_loc = text_loc

    # Message text.
    @property
    def text(self):
        return self._text

    # Source text location.
    @property
    def text_location(self):
        return self._text_loc


# A parsing error containing one or more messages (`ParseErrorMessage`).
class ParseError(RuntimeError):
    @classmethod
    def _create(cls, msg: str, text_loc: TextLocation):
        self = cls.__new__(cls)
        self._init(msg, text_loc)
        return self

    def __init__(self, *args, **kwargs):  # type: ignore
        raise NotImplementedError

    def _init(self, msg: str, text_loc: TextLocation):
        super().__init__(msg)
        self._msgs: List[ParseErrorMessage] = []
        self._add_msg(msg, text_loc)

    def _add_msg(self, msg: str, text_loc: TextLocation):
        self._msgs.append(
            ParseErrorMessage._create(  # pyright: ignore[reportPrivateUsage]
                msg, text_loc
            )
        )

    # Parsing error messages.
    #
    # The first message is the most specific one.
    @property
    def messages(self):
        return self._msgs


# Raises a parsing error, forwarding the parameters to the constructor.
def _raise_error(msg: str, text_loc: TextLocation) -> NoReturn:
    raise ParseError._create(msg, text_loc)  # pyright: ignore[reportPrivateUsage]


# Adds a message to the parsing error `exc`.
def _add_error_msg(exc: ParseError, msg: str, text_loc: TextLocation):
    exc._add_msg(msg, text_loc)  # pyright: ignore[reportPrivateUsage]


# Appends a message to the parsing error `exc` and reraises it.
def _augment_error(exc: ParseError, msg: str, text_loc: TextLocation) -> NoReturn:
    _add_error_msg(exc, msg, text_loc)
    raise exc


# Returns a normalized version (so as to be parseable by int()) of
# the constant integer string `s`, possibly negative, dealing with
# any radix suffix.
def _norm_const_int(s: str):
    neg = ""
    pos = s

    if s.startswith("-"):
        neg = "-"
        pos = s[1:]

    # Already correct?
    #
    # Check the whole string: `0bh` (hexadecimal) and `0b` (binary) also
    # start with `0b`, for example.
    if _prefixed_const_int_pat.fullmatch(pos) is not None:
        return s

    # Try suffix
    asm_suf_base = {
        "h": "x",
        "H": "x",
        "q": "o",
        "Q": "o",
        "o": "o",
        "O": "o",
        "b": "b",
        "B": "B",
    }

    base = asm_suf_base.get(pos[-1])

    if base is not None:
        s = f"{neg}0{base}{pos[:-1]}"

    return s


# Pattern of a positive constant integer having a radix prefix.
_prefixed_const_int_pat = re.compile(r"0[Xx][A-Fa-f0-9]+|0[Oo][0-7]+|0[Bb][01]+")


# Encodes the string `s` using the codec `codec`, raising `ParseError`
# with `text_loc` on encoding error.
def _encode_str(s: str, codec: str, text_loc: TextLocation):
    try:
        return s.encode(codec)
    except UnicodeEncodeError:
        _raise_error(f"Cannot encode `{s}` with the `{codec}` encoding", text_loc)


# Compresses `data` with gzip and returns the result.
#
# The modification time of the gzip header is always zero so that the
# result is reproducible: gzip.compress() sets it to the current time by
# default before Python 3.14 and only accepts an `mtime` parameter
# since Python 3.8.
def _gzip_compress(data: Union[bytes, bytearray]):
    with io.BytesIO() as f:
        with gzip.GzipFile(fileobj=f, mode="wb", mtime=0) as gz_f:
            gz_f.write(data)

        return f.getvalue()


# Variables dictionary type (for type hints).
VariablesT = Dict[str, Union[int, float, str]]


# Labels dictionary type (for type hints).
LabelsT = Dict[str, int]


# Common patterns.
_py_name_pat = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*")
_pos_const_int_pat = re.compile(
    r"(?:0[Xx][A-Fa-f0-9]+|0[Oo][0-7]+|0[Bb][01]+|[A-Fa-f0-9]+[hH]|[0-7]+[qQoO]|[01]+[bB]|\d+)\b"
)
_const_int_pat = re.compile(rf"(?P<neg>-)?(?:{_pos_const_int_pat.pattern})")
_const_float_pat = re.compile(
    r"[-+]?(?:(?:\d*\.\d+)|(?:\d+\.))(?:[Ee][+-]?\d+)?(?=\W|)"
)


# Macro definition dictionary.
_MacroDefsT = Dict[str, _MacroDef]


# Normand parser.
#
# The constructor accepts a Normand input. After building, use the `res`
# property to get the resulting main group.
class _Parser:
    # Builds a parser to parse the Normand input `normand`, parsing
    # immediately.
    def __init__(self, normand: str, variables: VariablesT, labels: LabelsT):
        self._normand = normand
        self._at = 0
        self._line_no = 1
        self._col_no = 1
        self._label_names = set(labels.keys())
        self._var_names = set(variables.keys())
        self._macro_defs: _MacroDefsT = {}
        self._base_item_parse_funcs = [
            self._try_parse_byte,
            self._try_parse_str,
            self._try_parse_val,
            self._try_parse_var_assign,
            self._try_parse_set_bo,
            self._try_parse_label_or_set_offset,
            self._try_parse_align_offset,
            self._try_parse_fill_until,
            self._try_parse_group,
            self._try_parse_rep_block,
            self._try_parse_cond_block,
            self._try_parse_macro_exp,
            self._try_parse_trans_block,
        ]
        self._parse()

    # Result (main group).
    @property
    def res(self):
        return self._res

    # Macro definitions.
    @property
    def macro_defs(self):
        return self._macro_defs

    # Current text location.
    @property
    def _text_loc(self):
        return TextLocation._create(  # pyright: ignore[reportPrivateUsage]
            self._line_no, self._col_no
        )

    # Returns `True` if this parser is done parsing.
    def _is_done(self):
        return self._at == len(self._normand)

    # Returns `True` if this parser isn't done parsing.
    def _isnt_done(self):
        return not self._is_done()

    # Raises a parse error, creating it using the message `msg` and the
    # current text location.
    def _raise_error(self, msg: str) -> NoReturn:
        _raise_error(msg, self._text_loc)

    # Tries to make the pattern `pat` match the current substring,
    # returning the match object and updating `self._at`,
    # `self._line_no`, and `self._col_no` on success.
    def _try_parse_pat(self, pat: Pattern[str]):
        m = pat.match(self._normand, self._at)

        if m is None:
            return

        # Skip matched string
        matched = m.group(0)
        self._at += len(matched)

        # Update line and column numbers from the matched string only
        last_nl_index = matched.rfind("\n")

        if last_nl_index == -1:
            # Same line
            self._col_no += len(matched)
        else:
            # New line
            self._line_no += matched.count("\n")
            self._col_no = len(matched) - last_nl_index

        # Return match object
        return m

    # Expects the pattern `pat` to match the current substring,
    # returning the match object and updating `self._at`,
    # `self._line_no`, and `self._col_no` on success, or raising a parse
    # error with the message `error_msg` on error.
    def _expect_pat(self, pat: Pattern[str], error_msg: str):
        # Match
        m = self._try_parse_pat(pat)

        if m is None:
            # No match: error
            self._raise_error(error_msg)

        # Return match object
        return m

    # Patterns for _skip_*()
    _comment_pat = re.compile(r"#[^#]*?(?:$|#)", re.M)
    _ws_or_comments_pat = re.compile(rf"(?:\s|{_comment_pat.pattern})*", re.M)
    _ws_or_syms_or_comments_pat = re.compile(
        rf"(?:[\s/\\?&:;.,_=|-]|{_comment_pat.pattern})*", re.M
    )

    # Skips as many whitespaces and comments as possible, but not
    # insignificant symbol characters.
    def _skip_ws_and_comments(self):
        self._try_parse_pat(self._ws_or_comments_pat)

    # Skips as many whitespaces, insignificant symbol characters, and
    # comments as possible.
    def _skip_ws_and_comments_and_syms(self):
        self._try_parse_pat(self._ws_or_syms_or_comments_pat)

    # Pattern for _try_parse_hex_byte()
    _nibble_pat = re.compile(r"[A-Fa-f0-9]")

    # Tries to parse a hexadecimal byte, returning a byte item on
    # success.
    def _try_parse_hex_byte(self):
        begin_text_loc = self._text_loc

        # Match initial nibble
        m_high = self._try_parse_pat(self._nibble_pat)

        if m_high is None:
            # No match
            return

        # Expect another nibble
        self._skip_ws_and_comments_and_syms()
        m_low = self._expect_pat(
            self._nibble_pat, "Expecting another hexadecimal nibble"
        )

        # Return item
        return _Byte(int(m_high.group(0) + m_low.group(0), 16), begin_text_loc)

    # Patterns for _try_parse_bin_byte()
    _bin_byte_bit_pat = re.compile(r"[01]")
    _bin_byte_prefix_pat = re.compile(r"%+")

    # Tries to parse a binary byte, returning a byte item on success.
    def _try_parse_bin_byte(self):
        begin_text_loc = self._text_loc

        # Match prefix
        m = self._try_parse_pat(self._bin_byte_prefix_pat)

        if m is None:
            # No match
            return

        # Expect as many bytes as there are `%` prefixes
        items: List[_Item] = []

        for _ in range(len(m.group(0))):
            self._skip_ws_and_comments_and_syms()
            byte_text_loc = self._text_loc
            bits: List[str] = []

            # Expect eight bits
            for _ in range(8):
                self._skip_ws_and_comments_and_syms()
                m = self._expect_pat(
                    self._bin_byte_bit_pat, "Expecting a bit (`0` or `1`)"
                )
                bits.append(m.group(0))

            items.append(_Byte(int("".join(bits), 2), byte_text_loc))

        # Return item
        if len(items) == 1:
            return items[0]

        # As group
        return _Group(items, begin_text_loc)

    # Patterns for _try_parse_dec_byte()
    _dec_byte_prefix_pat = re.compile(r"\$")
    _dec_byte_val_pat = re.compile(r"(?P<neg>-?)(?P<val>\d+)")

    # Tries to parse a decimal byte, returning a byte item on success.
    def _try_parse_dec_byte(self):
        begin_text_loc = self._text_loc

        # Match prefix
        if self._try_parse_pat(self._dec_byte_prefix_pat) is None:
            # No match
            return

        # Expect the value
        self._skip_ws_and_comments()
        m = self._expect_pat(self._dec_byte_val_pat, "Expecting a decimal constant")

        # Compute value
        val = int(m.group("val")) * (-1 if m.group("neg") == "-" else 1)

        # Validate
        if val < -128 or val > 255:
            _raise_error(f"Invalid decimal byte value {val}", begin_text_loc)

        # Two's complement
        val %= 256

        # Return item
        return _Byte(val, begin_text_loc)

    # Tries to parse a byte, returning a byte item on success.
    def _try_parse_byte(self):
        # Hexadecimal
        item = self._try_parse_hex_byte()

        if item is not None:
            return item

        # Binary
        item = self._try_parse_bin_byte()

        if item is not None:
            return item

        # Decimal
        item = self._try_parse_dec_byte()

        if item is not None:
            return item

    # Strings corresponding to escape sequence characters
    _lit_str_escape_seq_strs = {
        "0": "\0",
        "a": "\a",
        "b": "\b",
        "e": "\x1b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "v": "\v",
        "\\": "\\",
        '"': '"',
    }

    # Patterns for _try_parse_lit_str()
    _lit_str_prefix_suffix_pat = re.compile(r'"')
    _lit_str_contents_pat = re.compile(r'(?:(?:\\.)|[^"])*')
    _lit_str_escape_seq_pat = re.compile(r'\\([0abefnrtv"\\])')

    # Parses a literal string between double quotes (without an encoding
    # prefix) and returns the resulting string.
    def _try_parse_lit_str(self, with_prefix: bool):
        # Match prefix if needed
        if with_prefix:
            if self._try_parse_pat(self._lit_str_prefix_suffix_pat) is None:
                # No match
                return

        # Expect literal string
        m = self._expect_pat(self._lit_str_contents_pat, "Expecting a literal string")

        # Expect end of string
        self._expect_pat(
            self._lit_str_prefix_suffix_pat, 'Expecting `"` (end of literal string)'
        )

        # Replace escape sequences in a single pass so that the result
        # of a replacement (for example, `\` from `\\`) never takes part
        # in another one.
        return self._lit_str_escape_seq_pat.sub(
            lambda m_esc: self._lit_str_escape_seq_strs[m_esc.group(1)], m.group(0)
        )

    # Patterns for _try_parse_utf_str_encoding()
    _str_encoding_utf_prefix_pat = re.compile(r"u")
    _str_encoding_utf_pat = re.compile(r"(?:8|(?:(?:16|32)(?:[bl]e)))\b")

    # Tries to parse a UTF encoding specification, returning the Python
    # codec name on success.
    def _try_parse_utf_str_encoding(self):
        # Match prefix
        if self._try_parse_pat(self._str_encoding_utf_prefix_pat) is None:
            # No match
            return

        # Expect UTF specification
        m = self._expect_pat(
            self._str_encoding_utf_pat,
            "Expecting `8`, `16be`, `16le`, `32be` or `32le`",
        )

        # Convert to codec name
        return {
            "8": "utf_8",
            "16be": "utf_16_be",
            "16le": "utf_16_le",
            "32be": "utf_32_be",
            "32le": "utf_32_le",
        }[m.group(0)]

    # Patterns for _try_parse_str_encoding()
    _str_encoding_gen_prefix_pat = re.compile(r"s")
    _str_encoding_colon_pat = re.compile(r":")
    _str_encoding_non_utf_pat = re.compile(r"latin(?:[1-9]|10)\b")

    # Tries to parse a string encoding specification, returning the
    # Python codec name on success.
    #
    # Requires the general prefix (`s:`) if `req_gen_prefix` is `True`.
    def _try_parse_str_encoding(self, req_gen_prefix: bool = False):
        # General prefix?
        if self._try_parse_pat(self._str_encoding_gen_prefix_pat) is not None:
            # Expect `:`
            self._skip_ws_and_comments()
            self._expect_pat(self._str_encoding_colon_pat, "Expecting `:`")

            # Expect encoding specification
            self._skip_ws_and_comments()

            # UTF?
            codec = self._try_parse_utf_str_encoding()

            if codec is not None:
                return codec

            # Expect Latin
            m = self._expect_pat(
                self._str_encoding_non_utf_pat,
                "Expecting `u8`, `u16be`, `u16le`, `u32be`, `u32le`, or `latin1` to `latin10`",
            )
            return m.group(0)

        # UTF?
        if not req_gen_prefix:
            return self._try_parse_utf_str_encoding()

    # Patterns for _try_parse_str()
    _lit_str_prefix_pat = re.compile(r'"')
    _str_prefix_pat = re.compile(r'"|\{')
    _str_expr_pat = re.compile(r"[^}]+")
    _str_expr_suffix_pat = re.compile(r"\}")

    # Tries to parse a string, returning a literal string or string item
    # on success.
    def _try_parse_str(self):
        begin_text_loc = self._text_loc

        # Encoding
        codec = self._try_parse_str_encoding()

        # Match prefix (expect if there's an encoding specification)
        self._skip_ws_and_comments()

        if codec is None:
            # No encoding: only a literal string (UTF-8) is legal
            m_prefix = self._try_parse_pat(self._lit_str_prefix_pat)

            if m_prefix is None:
                return
        else:
            # Encoding present: expect a string prefix
            m_prefix = self._expect_pat(self._str_prefix_pat, 'Expecting `"` or `{`')

        # Literal string or expression?
        prefix = m_prefix.group(0)

        if prefix == '"':
            # Expect literal string
            str_text_loc = self._text_loc
            val = self._try_parse_lit_str(False)

            if val is None:
                self._raise_error("Expecting a literal string")

            # Encode string
            data = _encode_str(val, "utf_8" if codec is None else codec, str_text_loc)

            # Return item
            return _LitStr(data, begin_text_loc)
        else:
            # Expect expression
            self._skip_ws_and_comments()
            expr_text_loc = self._text_loc
            m = self._expect_pat(self._str_expr_pat, "Expecting an expression")

            # Expect `}`
            self._expect_pat(self._str_expr_suffix_pat, "Expecting `}`")

            # Create an expression node from the expression string
            expr_str, expr = self._ast_expr_from_str(m.group(0), expr_text_loc)

            # Return item
            assert codec is not None
            return _Str(expr_str, expr, codec, begin_text_loc)

    # Common right parenthesis pattern
    _right_paren_pat = re.compile(r"\)")

    # Patterns for _try_parse_group()
    _group_prefix_pat = re.compile(r"\(|!g(?:roup)?\b")

    # Tries to parse a group, returning a group item on success.
    def _try_parse_group(self):
        begin_text_loc = self._text_loc

        # Match prefix
        m_open = self._try_parse_pat(self._group_prefix_pat)

        if m_open is None:
            # No match
            return

        # Parse items
        items = self._parse_items()

        # Expect end of group
        self._skip_ws_and_comments_and_syms()

        if m_open.group(0) == "(":
            pat = self._right_paren_pat
            exp = ")"
        else:
            pat = self._block_end_pat
            exp = "!end"

        self._expect_pat(pat, f"Expecting an item or `{exp}` (end of group)")

        # Return item
        return _Group(items, begin_text_loc)

    # Returns a stripped expression string and an AST expression node
    # from the expression string `expr_str` at text location `text_loc`.
    def _ast_expr_from_str(self, expr_str: str, text_loc: TextLocation):
        # Create an expression node from the expression string
        expr_str = expr_str.strip().replace("\n", " ")

        try:
            expr = ast.parse(expr_str, mode="eval")
        except SyntaxError:
            _raise_error(
                f"Invalid expression `{expr_str}`: invalid syntax",
                text_loc,
            )

        return expr_str, expr

    # Returns a `ByteOrder` value from the _valid_ byte order string
    # `bo_str`.
    @staticmethod
    def _bo_from_str(bo_str: str):
        return {
            "be": ByteOrder.BE,
            "le": ByteOrder.LE,
        }[bo_str]

    # Patterns for _try_parse_val()
    _val_prefix_pat = re.compile(r"\[")
    _val_expr_pat = re.compile(r"([^\]:]+):")
    _fl_num_len_fmt_pat = re.compile(r"(?P<len>8|16|24|32|40|48|56|64)(?P<bo>[bl]e)?")
    _leb128_int_fmt_pat = re.compile(r"(u|s)leb128")
    _val_suffix_pat = re.compile(r"]")

    # Tries to parse a value (number or string) and format (fixed length
    # in bits and optional byte order override, `uleb128`, `sleb128`, or
    # `s:` followed with an encoding name), returning an item on
    # success.
    def _try_parse_val(self):
        # Match prefix
        if self._try_parse_pat(self._val_prefix_pat) is None:
            # No match
            return

        # Expect expression and `:`
        self._skip_ws_and_comments()
        expr_text_loc = self._text_loc
        m = self._expect_pat(self._val_expr_pat, "Expecting an expression")

        # Create an expression node from the expression string
        expr_str, expr = self._ast_expr_from_str(m.group(1), expr_text_loc)

        # Fixed length?
        self._skip_ws_and_comments()
        m_fmt = self._try_parse_pat(self._fl_num_len_fmt_pat)

        if m_fmt is not None:
            # Byte order override
            if m_fmt.group("bo") is None:
                bo = None
            else:
                bo = self._bo_from_str(m_fmt.group("bo"))

            # Create fixed-length number item
            item = _FlNum(
                expr_str,
                expr,
                int(m_fmt.group("len")),
                bo,
                expr_text_loc,
            )
        else:
            # LEB128?
            m_fmt = self._try_parse_pat(self._leb128_int_fmt_pat)

            if m_fmt is not None:
                # Create LEB128 integer item
                cls = _ULeb128Int if m_fmt.group(1) == "u" else _SLeb128Int
                item = cls(expr_str, expr, expr_text_loc)
            else:
                # String encoding?
                codec = self._try_parse_str_encoding(True)

                if codec is not None:
                    # Create string item
                    item = _Str(expr_str, expr, codec, expr_text_loc)
                else:
                    # At this point it's invalid
                    self._raise_error(
                        "Expecting a fixed length (multiple of eight bits and optional `be` or `le`), `uleb128`, `sleb128`, or `s:` followed with a valid encoding (`u8`, `u16be`, `u16le`, `u32be`, `u32le`, or `latin1` to `latin10`)"
                    )

        # Expect `]`
        self._skip_ws_and_comments()
        m = self._expect_pat(self._val_suffix_pat, "Expecting `]`")

        # Return item
        return item

    # Patterns for _try_parse_var_assign()
    _var_assign_prefix_pat = re.compile(r"\{")
    _var_assign_equal_pat = re.compile(r"=")
    _var_assign_expr_pat = re.compile(r"[^}]+")
    _var_assign_suffix_pat = re.compile(r"\}")

    # Tries to parse a variable assignment, returning a variable
    # assignment item on success.
    def _try_parse_var_assign(self):
        # Match prefix
        if self._try_parse_pat(self._var_assign_prefix_pat) is None:
            # No match
            return

        # Expect a name
        self._skip_ws_and_comments()
        name_text_loc = self._text_loc
        m = self._expect_pat(_py_name_pat, "Expecting a valid Python name")
        name = m.group(0)

        # Expect `=`
        self._skip_ws_and_comments()
        self._expect_pat(self._var_assign_equal_pat, "Expecting `=`")

        # Expect expression
        self._skip_ws_and_comments()
        expr_text_loc = self._text_loc
        m_expr = self._expect_pat(self._var_assign_expr_pat, "Expecting an expression")

        # Expect `}`
        self._skip_ws_and_comments()
        self._expect_pat(self._var_assign_suffix_pat, "Expecting `}`")

        # Validate name
        if name == _icitte_name:
            _raise_error(f"`{_icitte_name}` is a reserved variable name", name_text_loc)

        if name in self._label_names:
            _raise_error(f"Existing label named `{name}`", name_text_loc)

        # Create an expression node from the expression string
        expr_str, expr = self._ast_expr_from_str(m_expr.group(0), expr_text_loc)

        # Add to known variable names
        self._var_names.add(name)

        # Return item
        return _VarAssign(
            name,
            expr_str,
            expr,
            name_text_loc,
        )

    # Pattern for _try_parse_set_bo()
    _set_bo_pat = re.compile(r"!([bl]e)\b")

    # Tries to parse a byte order setting, returning a byte order
    # setting item on success.
    def _try_parse_set_bo(self):
        begin_text_loc = self._text_loc

        # Match
        m = self._try_parse_pat(self._set_bo_pat)

        if m is None:
            # No match
            return

        # Return corresponding item
        if m.group(1) == "be":
            bo = ByteOrder.BE
        else:
            assert m.group(1) == "le"
            bo = ByteOrder.LE

        return _SetBo(bo, begin_text_loc)

    # Tries to parse an offset setting value (after the initial `<`),
    # returning an offset item on success.
    def _try_parse_set_offset_val(self):
        begin_text_loc = self._text_loc

        # Match
        m = self._try_parse_pat(_pos_const_int_pat)

        if m is None:
            # No match
            return

        # Return item
        return _SetOffset(int(_norm_const_int(m.group(0)), 0), begin_text_loc)

    # Tries to parse a label name (after the initial `<`), returning a
    # label item on success.
    def _try_parse_label_name(self):
        begin_text_loc = self._text_loc

        # Match
        m = self._try_parse_pat(_py_name_pat)

        if m is None:
            # No match
            return

        # Validate
        name = m.group(0)

        if name == _icitte_name:
            _raise_error(f"`{_icitte_name}` is a reserved label name", begin_text_loc)

        if name in self._label_names:
            _raise_error(f"Duplicate label name `{name}`", begin_text_loc)

        if name in self._var_names:
            _raise_error(f"Existing variable named `{name}`", begin_text_loc)

        # Add to known label names
        self._label_names.add(name)

        # Return item
        return _Label(name, begin_text_loc)

    # Patterns for _try_parse_label_or_set_offset()
    _label_set_offset_prefix_pat = re.compile(r"<")
    _label_set_offset_suffix_pat = re.compile(r">")

    # Tries to parse a label or an offset setting, returning an item on
    # success.
    def _try_parse_label_or_set_offset(self):
        # Match prefix
        if self._try_parse_pat(self._label_set_offset_prefix_pat) is None:
            # No match
            return

        # Offset setting item?
        self._skip_ws_and_comments()
        item = self._try_parse_set_offset_val()

        if item is None:
            # Label item?
            item = self._try_parse_label_name()

            if item is None:
                # At this point it's invalid
                self._raise_error("Expecting a label name or an offset setting value")

        # Expect suffix
        self._skip_ws_and_comments()
        self._expect_pat(self._label_set_offset_suffix_pat, "Expecting `>`")
        return item

    # Pattern for _parse_pad_val()
    _pad_val_prefix_pat = re.compile(r"~")

    # Tries to parse a padding value, returning the padding value, or 0
    # if none.
    def _parse_pad_val(self):
        # Padding value?
        self._skip_ws_and_comments()
        pad_val = 0

        if self._try_parse_pat(self._pad_val_prefix_pat) is not None:
            self._skip_ws_and_comments()
            pad_val_text_loc = self._text_loc
            m = self._expect_pat(
                _pos_const_int_pat,
                "Expecting a positive constant integer (byte value)",
            )

            # Validate
            pad_val = int(_norm_const_int(m.group(0)), 0)

            if pad_val > 255:
                _raise_error(
                    f"Invalid padding byte value {pad_val}",
                    pad_val_text_loc,
                )

        return pad_val

    # Patterns for _try_parse_align_offset()
    _align_offset_prefix_pat = re.compile(r"@")
    _align_offset_val_pat = re.compile(r"\d+")

    # Tries to parse an offset alignment, returning an offset alignment
    # item on success.
    def _try_parse_align_offset(self):
        begin_text_loc = self._text_loc

        # Match prefix
        if self._try_parse_pat(self._align_offset_prefix_pat) is None:
            # No match
            return

        # Expect an alignment
        self._skip_ws_and_comments()
        align_text_loc = self._text_loc
        m = self._expect_pat(
            self._align_offset_val_pat,
            "Expecting an alignment (positive multiple of eight bits)",
        )

        # Validate alignment
        val = int(m.group(0))

        if val <= 0 or (val % 8) != 0:
            _raise_error(
                f"Invalid alignment value {val} (not a positive multiple of eight)",
                align_text_loc,
            )

        # Padding value
        pad_val = self._parse_pad_val()

        # Return item
        return _AlignOffset(val, pad_val, begin_text_loc)

    # Patterns for _expect_expr()
    _inner_expr_prefix_pat = re.compile(r"\{")
    _inner_expr_pat = re.compile(r"[^}]+")
    _inner_expr_suffix_pat = re.compile(r"\}")

    # Parses an expression outside a `{`/`}` context.
    #
    # This function accepts:
    #
    # • A Python expression within `{` and `}`.
    #
    # • A Python name.
    #
    # • If `accept_const_int` is `True`: a constant integer, which may
    #   be negative if `allow_neg_int` is `True`.
    #
    # • If `accept_float` is `True`: a constant floating point number.
    #
    # Returns the stripped expression string and AST expression.
    def _expect_expr(
        self,
        accept_const_int: bool = False,
        allow_neg_int: bool = False,
        accept_const_float: bool = False,
        accept_lit_str: bool = False,
    ):
        begin_text_loc = self._text_loc

        # Constant floating point number?
        if accept_const_float:
            m = self._try_parse_pat(_const_float_pat)

            if m is not None:
                return self._ast_expr_from_str(m.group(0), begin_text_loc)

        # Constant integer?
        if accept_const_int:
            m = self._try_parse_pat(_const_int_pat)

            if m is not None:
                # Negative and allowed?
                if m.group("neg") == "-" and not allow_neg_int:
                    _raise_error(
                        "Expecting a positive constant integer", begin_text_loc
                    )

                expr_str = _norm_const_int(m.group(0))
                return self._ast_expr_from_str(expr_str, begin_text_loc)

        # Name?
        m = self._try_parse_pat(_py_name_pat)

        if m is not None:
            return self._ast_expr_from_str(m.group(0), begin_text_loc)

        # Literal string
        if accept_lit_str:
            val = self._try_parse_lit_str(True)

            if val is not None:
                return self._ast_expr_from_str(repr(val), begin_text_loc)

        # Expect `{`
        msg_accepted_parts = ["a name", "or `{`"]

        if accept_lit_str:
            msg_accepted_parts.insert(0, "a literal string")

        if accept_const_float:
            msg_accepted_parts.insert(0, "a constant floating point number")

        if accept_const_int:
            msg_pos = "" if allow_neg_int else "positive "
            msg_accepted_parts.insert(0, f"a {msg_pos}constant integer")

        if len(msg_accepted_parts) == 2:
            msg_accepted = " ".join(msg_accepted_parts)
        else:
            msg_accepted = ", ".join(msg_accepted_parts)

        self._expect_pat(
            self._inner_expr_prefix_pat,
            f"Expecting {msg_accepted}",
        )

        # Expect an expression
        self._skip_ws_and_comments()
        expr_text_loc = self._text_loc
        m = self._expect_pat(self._inner_expr_pat, "Expecting an expression")
        expr_str = m.group(0)

        # Expect `}`
        self._skip_ws_and_comments()
        self._expect_pat(self._inner_expr_suffix_pat, "Expecting `}`")

        return self._ast_expr_from_str(expr_str, expr_text_loc)

    # Patterns for _try_parse_fill_until()
    _fill_until_prefix_pat = re.compile(r"\+")
    _fill_until_pad_val_prefix_pat = re.compile(r"~")

    # Tries to parse a filling, returning a filling item on success.
    def _try_parse_fill_until(self):
        begin_text_loc = self._text_loc

        # Match prefix
        if self._try_parse_pat(self._fill_until_prefix_pat) is None:
            # No match
            return

        # Expect expression
        self._skip_ws_and_comments()
        expr_str, expr = self._expect_expr(accept_const_int=True)

        # Padding value
        pad_val = self._parse_pad_val()

        # Return item
        return _FillUntil(expr_str, expr, pad_val, begin_text_loc)

    # Parses the multiplier expression of a repetition (block or
    # post-item) and returns the expression string and AST node.
    def _expect_rep_mul_expr(self):
        return self._expect_expr(accept_const_int=True)

    # Common block end pattern
    _block_end_pat = re.compile(r"!end\b")

    # Pattern for _try_parse_rep_block()
    _rep_block_prefix_pat = re.compile(r"!r(?:epeat)?\b")

    # Tries to parse a repetition block, returning a repetition item on
    # success.
    def _try_parse_rep_block(self):
        begin_text_loc = self._text_loc

        # Match prefix
        if self._try_parse_pat(self._rep_block_prefix_pat) is None:
            # No match
            return

        # Expect expression
        self._skip_ws_and_comments()
        expr_str, expr = self._expect_rep_mul_expr()

        # Parse items
        self._skip_ws_and_comments_and_syms()
        items = self._parse_items()

        # Expect end of block
        self._skip_ws_and_comments_and_syms()
        self._expect_pat(
            self._block_end_pat, "Expecting an item or `!end` (end of repetition block)"
        )

        # Return item
        return _Rep(items, expr_str, expr, begin_text_loc)

    # Pattern for _try_parse_cond_block()
    _cond_block_prefix_pat = re.compile(r"!if\b")
    _cond_block_else_pat = re.compile(r"!else\b")

    # Tries to parse a conditional block, returning a conditional item
    # on success.
    def _try_parse_cond_block(self):
        begin_text_loc = self._text_loc

        # Match prefix
        if self._try_parse_pat(self._cond_block_prefix_pat) is None:
            # No match
            return

        # Expect expression
        self._skip_ws_and_comments()
        expr_str, expr = self._expect_expr()

        # Parse "true" items
        self._skip_ws_and_comments_and_syms()
        true_items_text_loc = self._text_loc
        true_items = self._parse_items()
        false_items: List[_Item] = []
        false_items_text_loc = begin_text_loc

        # `!else`?
        self._skip_ws_and_comments_and_syms()

        if self._try_parse_pat(self._cond_block_else_pat) is not None:
            # Parse "false" items
            self._skip_ws_and_comments_and_syms()
            false_items_text_loc = self._text_loc
            false_items = self._parse_items()

        # Expect end of block
        self._expect_pat(
            self._block_end_pat,
            "Expecting an item, `!else`, or `!end` (end of conditional block)",
        )

        # Return item
        return _Cond(
            _Group(true_items, true_items_text_loc),
            _Group(false_items, false_items_text_loc),
            expr_str,
            expr,
            begin_text_loc,
        )

    # Pattern for _try_parse_trans_block()
    _trans_block_prefix_pat = re.compile(r"!t(?:ransform)?\b")
    _trans_block_type_pat = re.compile(
        r"(?:(?:base|b)64(?:u)?|(?:base|b)(?:16|32)|(?:ascii|a|base|b)85(?:p)?|(?:quopri|qp)(?:t)?|gzip|gz|bzip2|bz2)\b"
    )

    # Tries to parse a transformation block, returning a transformation
    # block item on success.
    def _try_parse_trans_block(self):
        begin_text_loc = self._text_loc

        # Match prefix
        if self._try_parse_pat(self._trans_block_prefix_pat) is None:
            # No match
            return

        # Expect type
        self._skip_ws_and_comments()
        m = self._expect_pat(
            self._trans_block_type_pat, "Expecting a known transformation type"
        )

        # Parse items
        self._skip_ws_and_comments_and_syms()
        items = self._parse_items()

        # Expect end of block
        self._expect_pat(
            self._block_end_pat,
            "Expecting an item or `!end` (end of transformation block)",
        )

        # Choose encoding function
        enc = m.group(0)

        if enc in ("base64", "b64"):
            func = base64.standard_b64encode
            name = "standard Base64"
        elif enc in ("base64u", "b64u"):
            func = base64.urlsafe_b64encode
            name = "URL-safe Base64"
        elif enc in ("base32", "b32"):
            func = base64.b32encode
            name = "Base32"
        elif enc in ("base16", "b16"):
            func = base64.b16encode
            name = "Base16"
        elif enc in ("ascii85", "a85"):
            func = base64.a85encode
            name = "Ascii85"
        elif enc in ("ascii85p", "a85p"):
            func = functools.partial(base64.a85encode, pad=True)
            name = "padded Ascii85"
        elif enc in ("base85", "b85"):
            func = base64.b85encode
            name = "Base85"
        elif enc in ("base85p", "b85p"):
            func = functools.partial(base64.b85encode, pad=True)
            name = "padded Base85"
        elif enc in ("quopri", "qp"):
            func = quopri.encodestring
            name = "MIME quoted-printable"
        elif enc in ("quoprit", "qpt"):
            func = functools.partial(quopri.encodestring, quotetabs=True)
            name = "MIME quoted-printable (with quoted tabs)"
        elif enc in ("gzip", "gz"):
            func = _gzip_compress
            name = "gzip"
        else:
            assert enc in ("bzip2", "bz2")
            func = bz2.compress
            name = "bzip2"

        # Return item
        return _Trans(
            items,
            name,
            func,
            begin_text_loc,
        )

    # Common left parenthesis pattern
    _left_paren_pat = re.compile(r"\(")

    # Patterns for _try_parse_macro_def() and _try_parse_macro_exp()
    _macro_params_comma_pat = re.compile(",")

    # Patterns for _try_parse_macro_def()
    _macro_def_prefix_pat = re.compile(r"!m(?:acro)?\b")

    # Tries to parse a macro definition, adding it to `self._macro_defs`
    # and returning `True` on success.
    def _try_parse_macro_def(self):
        begin_text_loc = self._text_loc

        # Match prefix
        if self._try_parse_pat(self._macro_def_prefix_pat) is None:
            # No match
            return False

        # Expect a name
        self._skip_ws_and_comments()
        name_text_loc = self._text_loc
        m = self._expect_pat(_py_name_pat, "Expecting a valid macro name")

        # Validate name
        name = m.group(0)

        if name in self._macro_defs:
            _raise_error(f"Duplicate macro named `{name}`", name_text_loc)

        # Expect `(`
        self._skip_ws_and_comments()
        self._expect_pat(self._left_paren_pat, "Expecting `(`")

        # Try to parse comma-separated parameter names
        param_names: List[str] = []
        expect_comma = False

        while True:
            self._skip_ws_and_comments()

            # End?
            if self._try_parse_pat(self._right_paren_pat) is not None:
                # End
                break

            # Comma?
            if expect_comma:
                self._expect_pat(self._macro_params_comma_pat, "Expecting `,`")

            # Expect parameter name
            self._skip_ws_and_comments()
            param_text_loc = self._text_loc
            m = self._expect_pat(_py_name_pat, "Expecting valid parameter name")

            if m.group(0) in param_names:
                _raise_error(
                    f"Duplicate macro parameter named `{m.group(0)}`",
                    param_text_loc,
                )

            param_names.append(m.group(0))
            expect_comma = True

        # Expect items
        self._skip_ws_and_comments_and_syms()
        old_var_names = self._var_names.copy()
        old_label_names = self._label_names.copy()
        self._var_names: Set[str] = set()
        self._label_names: Set[str] = set()
        items = self._parse_items()
        self._var_names = old_var_names
        self._label_names = old_label_names

        # Expect suffix
        self._expect_pat(
            self._block_end_pat, "Expecting an item or `!end` (end of macro block)"
        )

        # Register macro
        self._macro_defs[name] = _MacroDef(name, param_names, items, begin_text_loc)

        return True

    # Patterns for _try_parse_macro_exp()
    _macro_exp_prefix_pat = re.compile(r"m\b")
    _macro_exp_colon_pat = re.compile(r":")

    # Tries to parse a macro expansion, returning a macro expansion item
    # on success.
    def _try_parse_macro_exp(self):
        begin_text_loc = self._text_loc

        # Match prefix
        if self._try_parse_pat(self._macro_exp_prefix_pat) is None:
            # No match
            return

        # Expect `:`
        self._skip_ws_and_comments()
        self._expect_pat(self._macro_exp_colon_pat, "Expecting `:`")

        # Expect a macro name
        self._skip_ws_and_comments()
        name_text_loc = self._text_loc
        m = self._expect_pat(_py_name_pat, "Expecting a valid macro name")

        # Validate name
        name = m.group(0)
        macro_def = self._macro_defs.get(name)

        if macro_def is None:
            _raise_error(f"Unknown macro name `{name}`", name_text_loc)

        # Expect `(`
        self._skip_ws_and_comments()
        self._expect_pat(self._left_paren_pat, "Expecting `(`")

        # Try to parse comma-separated parameter values
        params_text_loc = self._text_loc
        params: List[_MacroExpParam] = []
        expect_comma = False

        while True:
            self._skip_ws_and_comments()

            # End?
            if self._try_parse_pat(self._right_paren_pat) is not None:
                # End
                break

            # Expect a value
            if expect_comma:
                self._expect_pat(self._macro_params_comma_pat, "Expecting `,`")

            self._skip_ws_and_comments()
            param_text_loc = self._text_loc
            params.append(
                _MacroExpParam(
                    *self._expect_expr(
                        accept_const_int=True,
                        allow_neg_int=True,
                        accept_const_float=True,
                        accept_lit_str=True,
                    ),
                    text_loc=param_text_loc,
                )
            )
            expect_comma = True

        # Validate parameter values
        if len(params) != len(macro_def.param_names):
            sing_plur = "" if len(params) == 1 else "s"
            _raise_error(
                f"Macro expansion passes {len(params)} parameter{sing_plur} while the definition expects {len(macro_def.param_names)}",
                params_text_loc,
            )

        # Return item
        return _MacroExp(name, params, begin_text_loc)

    # Tries to parse a base item (anything except a post-item
    # repetition), returning it on success.
    def _try_parse_base_item(self):
        for func in self._base_item_parse_funcs:
            item = func()

            if item is not None:
                return item

    # Pattern for _try_parse_rep_post()
    _rep_post_prefix_pat = re.compile(r"\*")

    # Tries to parse a post-item repetition, returning the expression
    # string and AST expression node on success.
    def _try_parse_rep_post(self):
        # Match prefix
        if self._try_parse_pat(self._rep_post_prefix_pat) is None:
            # No match
            return

        # Return expression string and AST expression
        self._skip_ws_and_comments()
        return self._expect_rep_mul_expr()

    # Tries to parse an item, possibly followed by a repetition,
    # returning `True` on success.
    #
    # Appends any parsed item to `items`.
    def _try_append_item(self, items: List[_Item]):
        self._skip_ws_and_comments_and_syms()

        # Base item
        item = self._try_parse_base_item()

        if item is None:
            return

        # Parse repetition if the base item is repeatable
        if isinstance(item, _RepableItem):
            self._skip_ws_and_comments()
            rep_text_loc = self._text_loc
            rep_ret = self._try_parse_rep_post()

            if rep_ret is not None:
                item = _Rep([item], *rep_ret, text_loc=rep_text_loc)

        items.append(item)
        return True

    # Parses and returns items, skipping whitespaces, insignificant
    # symbols, and comments when allowed, and stopping at the first
    # unknown character.
    #
    # Accepts and registers macro definitions if `accept_macro_defs`
    # is `True`.
    def _parse_items(self, accept_macro_defs: bool = False) -> List[_Item]:
        items: List[_Item] = []

        while self._isnt_done():
            # Try to append item
            if not self._try_append_item(items):
                if accept_macro_defs and self._try_parse_macro_def():
                    continue

                # Unknown at this point
                break

        return items

    # Parses the whole Normand input, setting `self._res` to the main
    # group item on success.
    def _parse(self):
        if len(self._normand.strip()) == 0:
            # Special case to make sure there's something to consume
            self._res = _Group([], self._text_loc)
            return

        # Parse first level items
        items = self._parse_items(True)

        # Make sure there's nothing left
        self._skip_ws_and_comments_and_syms()

        if self._isnt_done():
            self._raise_error(f"Unexpected character `{self._normand[self._at]}`")

        # Set main group item
        self._res = _Group(items, self._text_loc)


# The return type of parse().
class ParseResult:
    @classmethod
    def _create(
        cls,
        data: bytearray,
        variables: VariablesT,
        labels: LabelsT,
        offset: int,
        bo: Optional[ByteOrder],
    ):
        self = cls.__new__(cls)
        self._init(data, variables, labels, offset, bo)
        return self

    def __init__(self, *args, **kwargs):  # type: ignore
        raise NotImplementedError

    def _init(
        self,
        data: bytearray,
        variables: VariablesT,
        labels: LabelsT,
        offset: int,
        bo: Optional[ByteOrder],
    ):
        self._data = data
        self._vars = variables
        self._labels = labels
        self._offset = offset
        self._bo = bo

    # Generated data.
    @property
    def data(self):
        return self._data

    # Dictionary of updated variable names to their last computed value.
    @property
    def variables(self):
        return self._vars

    # Dictionary of updated main group label names to their computed
    # value.
    @property
    def labels(self):
        return self._labels

    # Updated offset.
    @property
    def offset(self):
        return self._offset

    # Updated byte order.
    @property
    def byte_order(self):
        return self._bo


# Raises a parse error for the item `item`, creating it using the
# message `msg`.
def _raise_error_for_item(msg: str, item: _Item) -> NoReturn:
    _raise_error(msg, item.text_loc)


# The `ICITTE` reserved name.
_icitte_name = "ICITTE"


# Base node visitor.
#
# Calls the _visit_name() method for each name node which isn't the name
# of a call.
class _NodeVisitor(ast.NodeVisitor):
    def __init__(self):
        self._parent_is_call = False

    def generic_visit(self, node: ast.AST):
        if type(node) is ast.Call:
            self._parent_is_call = True
        elif type(node) is ast.Name and not self._parent_is_call:
            self._visit_name(node.id)

        super().generic_visit(node)
        self._parent_is_call = False

    @abc.abstractmethod
    def _visit_name(self, name: str): ...


# Expression validator: validates that all the names within the
# expression are allowed.
class _ExprValidator(_NodeVisitor):
    def __init__(self, expr_str: str, text_loc: TextLocation, allowed_names: Set[str]):
        super().__init__()
        self._expr_str = expr_str
        self._text_loc = text_loc
        self._allowed_names = allowed_names

    def _visit_name(self, name: str):
        # Make sure the name refers to a known and reachable
        # variable/label name.
        if name != _icitte_name and name not in self._allowed_names:
            msg = f"Illegal (unknown or unreachable) variable/label name `{name}` in expression `{self._expr_str}`"

            allowed_names = self._allowed_names.copy()
            allowed_names.add(_icitte_name)

            if len(allowed_names) > 0:
                allowed_names_str = ", ".join(
                    sorted([f"`{name}`" for name in allowed_names])
                )
                msg += f"; the legal names are {{{allowed_names_str}}}"

            _raise_error(
                msg,
                self._text_loc,
            )


# Generator state.
class _GenState:
    def __init__(
        self,
        variables: VariablesT,
        labels: LabelsT,
        offset: int,
        bo: Optional[ByteOrder],
    ):
        self.variables = variables.copy()
        self.labels = labels.copy()
        self.offset = offset
        self.bo = bo

    def __repr__(self):
        return f"_GenState({self.variables!r}, {self.labels!r}, {self.offset!r}, {self.bo!r})"


# Fixed-length number item instance.
class _FlNumItemInst:
    def __init__(
        self,
        item: _FlNum,
        offset_in_data: int,
        state: _GenState,
        parse_error_msgs: List[ParseErrorMessage],
    ):
        self._item = item
        self._offset_in_data = offset_in_data
        self._state = state
        self._parse_error_msgs = parse_error_msgs

        # `True` if the labels of the enclosing groups must not update
        # `self._state` anymore (end of macro expansion).
        self._is_sealed = False

    @property
    def item(self):
        return self._item

    @property
    def offset_in_data(self):
        return self._offset_in_data

    @property
    def state(self):
        return self._state

    @property
    def parse_error_msgs(self):
        return self._parse_error_msgs

    @property
    def is_sealed(self):
        return self._is_sealed

    # Seals this instance: the labels of the enclosing groups won't
    # update its state anymore.
    def seal(self):
        self._is_sealed = True


# Generator of data and final state from a group item.
#
# Generation happens in memory at construction time. After building, use
# the `data`, `variables`, `labels`, `offset`, and `bo` properties to
# get the resulting context.
#
# The steps of generation are:
#
# 1. Handle each item in prefix order.
#
#    The handlers append bytes to `self._data` and update some current
#    state object (`_GenState` instance).
#
#    When handling a fixed-length number item, try to evaluate its
#    expression using the current state. If this fails, then it might be
#    because the expression refers to a "future" label: save the current
#    offset in `self._data` (generated data) and a snapshot of the
#    current state within `self._fl_num_item_insts` (`_FlNumItemInst`
#    object). _gen_fl_num_item_insts() will deal with this later. A
#    `_FlNumItemInst` instance also contains a snapshot of the current
#    parsing error messages (`self._parse_error_msgs`) which need to be
#    taken into account when handling the instance later.
#
#    When handling the items of a group, keep a map of immediate label
#    names to their offset. Then, after having processed all the items,
#    update the relevant saved state snapshots in
#    `self._fl_num_item_insts` with those immediate label values.
#    _gen_fl_num_item_insts() will deal with this later.
#
# 2. Handle all the fixed-length number item instances of which the
#    expression evaluation failed before.
#
#    At this point, `self._fl_num_item_insts` contains everything that's
#    needed to evaluate the expressions, including the values of
#    "future" labels from the point of view of some fixed-length number
#    item instance.
#
#    If an evaluation fails at this point, then it's a user error. Add
#    to the parsing error all the saved parsing error messages of the
#    instance. Those additional messages add precious context to the
#    error.
class _Gen:
    def __init__(
        self,
        group: _Group,
        macro_defs: _MacroDefsT,
        variables: VariablesT,
        labels: LabelsT,
        offset: int,
        bo: Optional[ByteOrder],
    ):
        self._macro_defs = macro_defs
        self._fl_num_item_insts: List[_FlNumItemInst] = []
        self._parse_error_msgs: List[ParseErrorMessage] = []
        self._in_trans = False
        self._gen(group, _GenState(variables, labels, offset, bo))

    # Generated bytes.
    @property
    def data(self):
        return self._data

    # Updated variables.
    @property
    def variables(self):
        return self._final_state.variables

    # Updated main group labels.
    @property
    def labels(self):
        return self._final_state.labels

    # Updated offset.
    @property
    def offset(self):
        return self._final_state.offset

    # Updated byte order.
    @property
    def bo(self):
        return self._final_state.bo

    # Evaluates the expression `expr` of which the original string is
    # `expr_str` at the location `text_loc` considering the current
    # generation state `state`.
    #
    # If `accept_float` is `True`, then the type of the result may be
    # `float` too.
    #
    # If `accept_str` is `True`, then the type of the result may be
    # `str` too.
    @staticmethod
    def _eval_expr(
        expr_str: str,
        expr: ast.Expression,
        text_loc: TextLocation,
        state: _GenState,
        accept_float: bool = False,
        accept_str: bool = False,
    ):
        syms: VariablesT = {}
        syms.update(state.labels)

        # Set the `ICITTE` name to the current offset
        syms[_icitte_name] = state.offset

        # Add the current variables
        syms.update(state.variables)

        # Validate the node and its children
        _ExprValidator(expr_str, text_loc, set(syms.keys())).visit(expr)

        # Compile and evaluate expression node
        try:
            val = eval(compile(expr, "", "eval"), None, syms)
        except Exception as exc:
            _raise_error(
                f"Failed to evaluate expression `{expr_str}`: {exc}",
                text_loc,
            )

        # Convert `bool` result type to `int` to normalize
        if type(val) is bool:
            val = int(val)

        # Validate result type
        expected_types: Set[type] = {int}

        if accept_float:
            expected_types.add(float)

        if accept_str:
            expected_types.add(str)

        if type(val) not in expected_types:
            expected_types_str = sorted([f"`{t.__name__}`" for t in expected_types])

            if len(expected_types_str) == 1:
                msg_expected = expected_types_str[0]
            elif len(expected_types_str) == 2:
                msg_expected = " or ".join(expected_types_str)
            else:
                expected_types_str[-1] = f"or {expected_types_str[-1]}"
                msg_expected = ", ".join(expected_types_str)

            _raise_error(
                f"Invalid expression `{expr_str}`: expecting result type {msg_expected}, not `{type(val).__name__}`",
                text_loc,
            )

        return val

    # Forwards to _eval_expr() with the expression and text location of
    # `item`.
    @staticmethod
    def _eval_item_expr(
        item: Union[_Cond, _FillUntil, _FlNum, _Leb128Int, _Rep, _Str, _VarAssign],
        state: _GenState,
        accept_float: bool = False,
        accept_str: bool = False,
    ):
        return _Gen._eval_expr(
            item.expr_str, item.expr, item.text_loc, state, accept_float, accept_str
        )

    # Handles the byte item `item`.
    def _handle_byte_item(self, item: _Byte, state: _GenState):
        self._data.append(item.val)
        state.offset += item.size

    # Handles the literal string item `item`.
    def _handle_lit_str_item(self, item: _LitStr, state: _GenState):
        self._data += item.data
        state.offset += item.size

    # Handles the byte order setting item `item`.
    def _handle_set_bo_item(self, item: _SetBo, state: _GenState):
        # Update current byte order
        state.bo = item.bo

    # Handles the variable assignment item `item`.
    def _handle_var_assign_item(self, item: _VarAssign, state: _GenState):
        # Update variable
        state.variables[item.name] = self._eval_item_expr(
            item, state, accept_float=True, accept_str=True
        )

    # Returns the effective byte order to use to encode the fixed-length
    # number `item` considering the current state `state`.
    @staticmethod
    def _fl_num_item_effective_bo(item: _FlNum, state: _GenState):
        return state.bo if item.bo is None else item.bo

    # Handles the fixed-length number item `item`.
    def _handle_fl_num_item(self, item: _FlNum, state: _GenState):
        # Effective byte order
        bo = self._fl_num_item_effective_bo(item, state)

        # Validate current byte order
        if bo is None and item.len > 8:
            _raise_error_for_item(
                f"Current byte order isn't defined at first fixed-length number (`{item.expr_str}`) to encode on more than 8 bits",
                item,
            )

        # Try an immediate evaluation. If it fails, then keep everything
        # needed to (try to) generate the bytes of this item later.
        try:
            data = self._gen_fl_num_item_inst_data(item, state)
        except Exception:
            if self._in_trans:
                _raise_error_for_item(
                    f"Invalid expression `{item.expr_str}`: failed to evaluate within a transformation block",
                    item,
                )

            self._fl_num_item_insts.append(
                _FlNumItemInst(
                    item,
                    len(self._data),
                    copy.deepcopy(state),
                    copy.deepcopy(self._parse_error_msgs),
                )
            )

            # Reserve space in `self._data` for this instance
            data = bytes([0] * (item.len // 8))

        # Append bytes
        self._data += data

        # Update offset
        state.offset += len(data)

    # Returns the size, in bytes, required to encode the value `val`
    # with LEB128 (signed version if `is_signed` is `True`).
    @staticmethod
    def _leb128_size_for_val(val: int, is_signed: bool):
        if val < 0:
            # Equivalent upper bound.
            #
            # For example, if `val` is -128, then the full integer for
            # this number of bits would be [-128, 127].
            val = -val - 1

        # Number of bits (add one for the sign if needed)
        bits = val.bit_length() + int(is_signed)

        if bits == 0:
            bits = 1

        # Seven bits per byte
        return math.ceil(bits / 7)

    # Handles the LEB128 integer item `item`.
    def _handle_leb128_int_item(self, item: _Leb128Int, state: _GenState):
        # Compute value
        val = self._eval_item_expr(item, state)

        # Size in bytes
        size = self._leb128_size_for_val(val, type(item) is _SLeb128Int)

        # For each byte
        for _ in range(size):
            # Seven LSBs, MSB of the byte set (continue)
            self._data.append((val & 0x7F) | 0x80)
            val >>= 7

        # Clear MSB of last byte (stop)
        self._data[-1] &= ~0x80

        # Update offset
        state.offset += size

    # Handles the string item `item`.
    def _handle_str_item(self, item: _Str, state: _GenState):
        # Compute value
        val = str(self._eval_item_expr(item, state, accept_float=True, accept_str=True))

        # Encode
        data = _encode_str(val, item.codec, item.text_loc)

        # Add to data
        self._data += data

        # Update offset
        state.offset += len(data)

    # Handles the group item `item`, removing the immediate labels from
    # `state` at the end if `remove_immediate_labels` is `True`.
    def _handle_group_item(
        self, item: _Group, state: _GenState, remove_immediate_labels: bool = True
    ):
        first_fl_num_item_inst_index = len(self._fl_num_item_insts)
        immediate_labels: LabelsT = {}

        # Handle each item
        for subitem in item.items:
            if type(subitem) is _Label:
                # Add to local immediate labels
                immediate_labels[subitem.name] = state.offset

            self._handle_item(subitem, state)

        # Remove immediate labels from current state if needed
        if remove_immediate_labels:
            for name in immediate_labels:
                del state.labels[name]

        # Add all immediate labels to all the unsealed state snapshots
        # since `first_fl_num_item_inst_index`.
        for inst in self._fl_num_item_insts[first_fl_num_item_inst_index:]:
            if not inst.is_sealed:
                inst.state.labels.update(immediate_labels)

    # Handles the repetition item `item`.
    def _handle_rep_item(self, item: _Rep, state: _GenState):
        # Compute the repetition count
        mul = _Gen._eval_item_expr(item, state)

        # Validate result
        if mul < 0:
            _raise_error_for_item(
                f"Invalid expression `{item.expr_str}`: unexpected negative result {mul:,}",
                item,
            )

        # Generate group data `mul` times
        for _ in range(mul):
            self._handle_group_item(item, state)

    # Handles the conditional item `item`.
    def _handle_cond_item(self, item: _Cond, state: _GenState):
        # Compute the conditional value
        val = _Gen._eval_item_expr(item, state)

        # Generate selected group data
        if val:
            self._handle_group_item(item.true_item, state)
        else:
            self._handle_group_item(item.false_item, state)

    # Handles the transformation item `item`.
    def _handle_trans_item(self, item: _Trans, state: _GenState):
        init_in_trans = self._in_trans
        self._in_trans = True
        init_data_len = len(self._data)
        init_offset = state.offset

        # Generate group data
        self._handle_group_item(item, state)

        # Remove and keep group data
        to_trans = self._data[init_data_len:]
        del self._data[init_data_len:]

        # Encode group data and append to current data
        try:
            transformed = item.trans(to_trans)
        except Exception as exc:
            _raise_error_for_item(
                f"Cannot apply the {item.name} transformation to this data: {exc}",
                item,
            )

        self._data += transformed

        # Update offset and restore
        state.offset = init_offset + len(transformed)
        self._in_trans = init_in_trans

    # Evaluates the parameters of the macro expansion item `item`
    # considering the initial state `init_state` and returns a new state
    # to handle the items of the macro.
    def _eval_macro_exp_params(self, item: _MacroExp, init_state: _GenState):
        # New state
        exp_state = _GenState({}, {}, init_state.offset, init_state.bo)

        # Evaluate the parameter expressions
        macro_def = self._macro_defs[item.name]

        for param_name, param in zip(macro_def.param_names, item.params):
            exp_state.variables[param_name] = _Gen._eval_expr(
                param.expr_str,
                param.expr,
                param.text_loc,
                init_state,
                accept_float=True,
                accept_str=True,
            )

        return exp_state

    # Handles the macro expansion item `item`.
    def _handle_macro_exp_item(self, item: _MacroExp, state: _GenState):
        parse_error_msg_text = f"While expanding the macro `{item.name}`:"

        try:
            # New state
            exp_state = self._eval_macro_exp_params(item, state)

            # Process the contained group
            init_data_size = len(self._data)
            first_fl_num_item_inst_index = len(self._fl_num_item_insts)
            parse_error_msg = (
                ParseErrorMessage._create(  # pyright: ignore[reportPrivateUsage]
                    parse_error_msg_text, item.text_loc
                )
            )
            self._parse_error_msgs.append(parse_error_msg)
            self._handle_group_item(self._macro_defs[item.name], exp_state)
            self._parse_error_msgs.pop()

            # Seal the state snapshots of this expansion: the labels of
            # the enclosing groups aren't reachable from within a macro.
            for inst in self._fl_num_item_insts[first_fl_num_item_inst_index:]:
                inst.seal()
        except ParseError as exc:
            _augment_error(exc, parse_error_msg_text, item.text_loc)

        # Update state offset and return
        state.offset += len(self._data) - init_data_size

    # Handles the offset setting item `item`.
    def _handle_set_offset_item(self, item: _SetOffset, state: _GenState):
        state.offset = item.val

    # Handles the offset alignment item `item` (adds padding).
    def _handle_align_offset_item(self, item: _AlignOffset, state: _GenState):
        init_offset = state.offset
        align_bytes = item.val // 8
        state.offset = (state.offset + align_bytes - 1) // align_bytes * align_bytes
        self._data += bytes([item.pad_val] * (state.offset - init_offset))

    # Handles the filling item `item` (adds padding).
    def _handle_fill_until_item(self, item: _FillUntil, state: _GenState):
        # Compute the new offset
        new_offset = _Gen._eval_item_expr(item, state)

        # Validate the new offset
        if new_offset < state.offset:
            _raise_error_for_item(
                f"Invalid expression `{item.expr_str}`: new offset {new_offset:,} is less than current offset {state.offset:,}",
                item,
            )

        # Fill
        self._data += bytes([item.pad_val] * (new_offset - state.offset))

        # Update offset
        state.offset = new_offset

    # Handles the label item `item`.
    def _handle_label_item(self, item: _Label, state: _GenState):
        state.labels[item.name] = state.offset

    # Handles the item `item`, returning the updated next repetition
    # instance.
    def _handle_item(self, item: _Item, state: _GenState):
        return self._item_handlers[type(item)](item, state)

    # Generates the data for a fixed-length integer item instance having
    # the value `val` and the effective byte order `bo` and returns it.
    def _gen_fl_int_item_inst_data(
        self, val: int, bo: Optional[ByteOrder], item: _FlNum
    ):
        # Validate range
        if val < -(2 ** (item.len - 1)) or val > 2**item.len - 1:
            _raise_error_for_item(
                f"Value {val:,} is outside the {item.len}-bit range when evaluating expression `{item.expr_str}`",
                item,
            )

        # Encode result on 64 bits (to extend the sign bit whatever the
        # value of `item.len`).
        data = struct.pack(
            f"{'>' if bo in (None, ByteOrder.BE) else '<'}{'Q' if val >= 0 else 'q'}",
            val,
        )

        # Keep only the requested length
        len_bytes = item.len // 8

        if bo in (None, ByteOrder.BE):
            # Big endian: keep last bytes
            data = data[-len_bytes:]
        else:
            # Little endian: keep first bytes
            assert bo == ByteOrder.LE
            data = data[:len_bytes]

        # Return data
        return data

    # Generates the data for a fixed-length floating point number item
    # instance having the value `val` and the effective byte order `bo`
    # and returns it.
    def _gen_fl_float_item_inst_data(
        self, val: float, bo: Optional[ByteOrder], item: _FlNum
    ):
        # Validate length
        if item.len not in (32, 64):
            _raise_error_for_item(
                f"Invalid {item.len}-bit length for a fixed-length floating point number (value {val:,})",
                item,
            )

        # Encode and return result
        return struct.pack(
            f"{'>' if bo in (None, ByteOrder.BE) else '<'}{'f' if item.len == 32 else 'd'}",
            val,
        )

    # Generates the data for a fixed-length number item instance and
    # returns it.
    def _gen_fl_num_item_inst_data(self, item: _FlNum, state: _GenState):
        # Effective byte order
        bo = self._fl_num_item_effective_bo(item, state)

        # Compute value
        val = self._eval_item_expr(item, state, True)

        # Handle depending on type
        if type(val) is int:
            return self._gen_fl_int_item_inst_data(val, bo, item)
        else:
            assert type(val) is float
            return self._gen_fl_float_item_inst_data(val, bo, item)

    # Generates the data for all the fixed-length number item instances
    # and writes it at the correct offset within `self._data`.
    def _gen_fl_num_item_insts(self):
        for inst in self._fl_num_item_insts:
            # Generate bytes
            try:
                data = self._gen_fl_num_item_inst_data(inst.item, inst.state)
            except ParseError as exc:
                # Add all the saved parse error messages for this
                # instance.
                for msg in reversed(inst.parse_error_msgs):
                    _add_error_msg(exc, msg.text, msg.text_location)

                raise

            # Insert bytes into `self._data`
            self._data[inst.offset_in_data : inst.offset_in_data + len(data)] = data

    # Generates the data (`self._data`) and final state
    # (`self._final_state`) from `group` and the initial state `state`.
    def _gen(self, group: _Group, state: _GenState):
        # Initial state
        self._data = bytearray()

        # Item handlers
        self._item_handlers: Dict[type, Callable[[Any, _GenState], None]] = {
            _AlignOffset: self._handle_align_offset_item,
            _Byte: self._handle_byte_item,
            _Cond: self._handle_cond_item,
            _FillUntil: self._handle_fill_until_item,
            _FlNum: self._handle_fl_num_item,
            _Group: self._handle_group_item,
            _Label: self._handle_label_item,
            _LitStr: self._handle_lit_str_item,
            _MacroExp: self._handle_macro_exp_item,
            _Rep: self._handle_rep_item,
            _SetBo: self._handle_set_bo_item,
            _SetOffset: self._handle_set_offset_item,
            _SLeb128Int: self._handle_leb128_int_item,
            _Str: self._handle_str_item,
            _Trans: self._handle_trans_item,
            _ULeb128Int: self._handle_leb128_int_item,
            _VarAssign: self._handle_var_assign_item,
        }

        # Handle the group item, _not_ removing the immediate labels
        # because the `labels` property offers them.
        self._handle_group_item(group, state, False)

        # This is actually the final state
        self._final_state = state

        # Generate all the fixed-length number bytes now that we know
        # their full state
        self._gen_fl_num_item_insts()


# Returns a `ParseResult` instance containing the bytes encoded by the
# input string `normand`.
#
# `init_variables` is a dictionary of initial variable names (valid
# Python names) to integral values. A variable name must not be the
# reserved name `ICITTE`.
#
# `init_labels` is a dictionary of initial label names (valid Python
# names) to integral values. A label name must not be the reserved name
# `ICITTE`.
#
# `init_offset` is the initial offset.
#
# `init_byte_order` is the initial byte order.
#
# Raises `ParseError` on any parsing error.
def parse(
    normand: str,
    init_variables: Optional[VariablesT] = None,
    init_labels: Optional[LabelsT] = None,
    init_offset: int = 0,
    init_byte_order: Optional[ByteOrder] = None,
):
    if init_variables is None:
        init_variables = {}

    if init_labels is None:
        init_labels = {}

    parser = _Parser(normand, init_variables, init_labels)
    gen = _Gen(
        parser.res,
        parser.macro_defs,
        init_variables,
        init_labels,
        init_offset,
        init_byte_order,
    )
    return ParseResult._create(  # pyright: ignore[reportPrivateUsage]
        gen.data, gen.variables, gen.labels, gen.offset, gen.bo
    )


# Raises a command-line error with the message `msg`.
def _raise_cli_error(msg: str) -> NoReturn:
    raise RuntimeError(f"Command-line error: {msg}")


# Returns the `int` or `float` value out of a CLI assignment value.
def _val_from_assign_val_str(s: str, is_label: bool):
    s = s.strip()

    # Floating point number?
    if not is_label:
        m = _const_float_pat.fullmatch(s)

        if m is not None:
            return float(m.group(0))

    # Integer?
    m = _const_int_pat.fullmatch(s)

    if m is not None:
        return int(_norm_const_int(m.group(0)), 0)

    exp = "an integer" if is_label else "a number"
    _raise_cli_error(f"Invalid assignment value `{s}`: expecting {exp}")


# Returns a dictionary of string to numbers from the list of strings
# `args` containing `NAME=VAL` entries.
def _dict_from_arg(args: Optional[List[str]], is_label: bool, is_str_only: bool):
    d: VariablesT = {}

    if args is None:
        return d

    for arg in args:
        m = re.match(rf"({_py_name_pat.pattern})\s*=\s*(.*)$", arg)

        if m is None:
            _raise_cli_error(f"Invalid assignment `{arg}`")

        if is_str_only:
            val = m.group(2)
        else:
            val = _val_from_assign_val_str(m.group(2), is_label)

        d[m.group(1)] = val

    return d


# Parses the command-line arguments and returns, in this order:
#
# 1. The input file path, or `None` if none.
# 2. The Normand input text.
# 3. The initial offset.
# 4. The initial byte order.
# 5. The initial variables.
# 6. The initial labels.
def _parse_cli_args():
    import argparse

    # Build parser
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--offset",
        metavar="OFFSET",
        action="store",
        type=int,
        default=0,
        help="initial offset (positive)",
    )
    ap.add_argument(
        "-b",
        "--byte-order",
        metavar="BO",
        choices=["be", "le"],
        type=str,
        help="initial byte order (`be` or `le`)",
    )
    ap.add_argument(
        "-v",
        "--var",
        metavar="NAME=VAL",
        action="append",
        help="add an initial numeric variable (may be repeated)",
    )
    ap.add_argument(
        "-s",
        "--var-str",
        metavar="NAME=VAL",
        action="append",
        help="add an initial string variable (may be repeated)",
    )
    ap.add_argument(
        "-l",
        "--label",
        metavar="NAME=VAL",
        action="append",
        help="add an initial label (may be repeated)",
    )
    ap.add_argument("--version", action="version", version=f"Normand {__version__}")
    ap.add_argument(
        "path",
        metavar="PATH",
        action="store",
        nargs="?",
        help="input path (none means standard input)",
    )

    # Parse
    args = ap.parse_args()

    # Read input
    if args.path is None:
        normand = sys.stdin.read()
    else:
        with open(args.path) as f:
            normand = f.read()

    # Variables and labels
    variables = _dict_from_arg(args.var, False, False)
    variables.update(_dict_from_arg(args.var_str, False, True))
    labels = _dict_from_arg(args.label, True, False)

    # Validate offset
    if args.offset < 0:
        _raise_cli_error(f"Invalid negative offset {args.offset}")

    # Validate and set byte order
    bo: Optional[ByteOrder] = None

    if args.byte_order is not None:
        if args.byte_order == "be":
            bo = ByteOrder.BE
        else:
            assert args.byte_order == "le"
            bo = ByteOrder.LE

    # Return input and initial state
    return args.path, normand, args.offset, bo, variables, typing.cast(LabelsT, labels)


# CLI entry point without exception handling.
def _run_cli_with_args(
    normand: str,
    offset: int,
    bo: Optional[ByteOrder],
    variables: VariablesT,
    labels: LabelsT,
):
    sys.stdout.buffer.write(parse(normand, variables, labels, offset, bo).data)


# Prints the exception message `msg` and exits with status 1.
def _fail(msg: str) -> NoReturn:
    if not msg.endswith("."):
        msg += "."

    print(msg.strip(), file=sys.stderr)
    sys.exit(1)


# CLI entry point.
def _run_cli():
    try:
        args = _parse_cli_args()
    except Exception as exc:
        _fail(str(exc))

    try:
        _run_cli_with_args(*args[1:])
    except ParseError as exc:
        import os.path

        prefix = "" if args[0] is None else f"{os.path.abspath(args[0])}:"
        fail_msg = ""

        for msg in reversed(exc.messages):
            fail_msg += f"{prefix}{msg.text_location.line_no}:{msg.text_location.col_no} - {msg.text}"

            if fail_msg[-1] not in ".:;":
                fail_msg += "."

            fail_msg += "\n"

        _fail(fail_msg.strip())
    except Exception as exc:
        _fail(str(exc))


if __name__ == "__main__":
    _run_cli()
