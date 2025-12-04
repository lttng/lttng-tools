"""clangparser - use clang to get preprocess a source code."""

import logging
import os
import collections

from clang.cindex import Index, TranslationUnit
from clang.cindex import TypeKind

from ctypeslib.codegen import cursorhandler
from ctypeslib.codegen import typedesc
from ctypeslib.codegen import typehandler
from ctypeslib.codegen import util
from ctypeslib.codegen.handler import DuplicateDefinitionException
from ctypeslib.codegen.handler import InvalidDefinitionError
from ctypeslib.codegen.handler import InvalidTranslationUnitException

log = logging.getLogger("clangparser")


class Clang_Parser:
    """
    Will parse libclang AST tree to create a representation of Types and
    different others source code objects objets as described in Typedesc.

    For each Declaration a declaration will be saved, and the type of that
    declaration will be cached and saved.
    """

    has_values = {
        "Enumeration",
        "Function",
        "FunctionType",
        "OperatorFunction",
        "Method",
        "Constructor",
        "Destructor",
        "OperatorMethod",
        "Converter",
    }

    # FIXME, macro definition __SIZEOF_DOUBLE__
    ctypes_typename = {
        TypeKind.VOID: "None",  # because ctypes.POINTER(None) == c_void_p
        TypeKind.BOOL: "c_bool",
        TypeKind.CHAR_U: "c_ubyte",  # ?? used for PADDING
        TypeKind.UCHAR: "c_ubyte",  # unsigned char
        TypeKind.CHAR16: "c_wchar",  # char16_t
        TypeKind.CHAR32: "c_wchar",  # char32_t
        TypeKind.USHORT: "c_ushort",
        TypeKind.UINT: "c_uint",
        TypeKind.ULONG: "TBD",
        TypeKind.ULONGLONG: "c_ulonglong",
        TypeKind.UINT128: "c_uint128",  # FIXME
        TypeKind.CHAR_S: "c_char",  # char
        TypeKind.SCHAR: "c_byte",  # signed char
        TypeKind.WCHAR: "c_wchar",
        TypeKind.SHORT: "c_short",
        TypeKind.INT: "c_int",
        TypeKind.LONG: "TBD",
        TypeKind.LONGLONG: "c_longlong",
        TypeKind.INT128: "c_int128",  # FIXME
        TypeKind.FLOAT: "c_float",
        TypeKind.DOUBLE: "c_double",
        TypeKind.LONGDOUBLE: "c_longdouble",
        TypeKind.POINTER: "POINTER_T",
        TypeKind.NULLPTR: "c_void_p",
    }

    def __init__(self, flags):
        self.all = collections.OrderedDict()
        # a shortcut to identify registered decl in cases of records
        self.all_set = set()
        self.cpp_data = {}
        self._unhandled = []
        self.fields = {}
        self.tu = None
        self.tu_options = None
        self.flags = flags
        self.ctypes_sizes = {}
        self.init_parsing_options()
        self.make_ctypes_convertor(flags)
        self.cursorkind_handler = cursorhandler.CursorHandler(self)
        self.typekind_handler = typehandler.TypeHandler(self)
        self.__filter_location = None
        self.__processed_location = set()

    def init_parsing_options(self):
        """Set the Translation Unit to skip functions bodies per default."""
        self.tu_options = TranslationUnit.PARSE_SKIP_FUNCTION_BODIES

    def activate_macros_parsing(self):
        """Activates the detailled code parsing options in the Translation
        Unit."""
        self.tu_options |= TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD

    def activate_comment_parsing(self):
        """Activates the comment parsing options in the Translation Unit."""
        self.tu_options |= TranslationUnit.PARSE_INCLUDE_BRIEF_COMMENTS_IN_CODE_COMPLETION

    def deactivate_function_body_parsing(self):
        self.tu_options |= TranslationUnit.PARSE_SKIP_FUNCTION_BODIES

    def filter_location(self, src_files):
        self.__filter_location = [os.path.abspath(f) for f in src_files]

    def parse(self, filename):
        """
        . reads 1 file
        . if there is a compilation error, print a warning
        . get root cursor and recurse
        . for each STRUCT_DECL, register a new struct type
        . for each UNION_DECL, register a new union type
        . for each TYPEDEF_DECL, register a new alias/typdef to the underlying type
            - underlying type is cursor.type.get_declaration() for Record
        . for each VAR_DECL, register a Variable
        . for each TYPEREF ??
        """
        if os.path.abspath(filename) in self.__processed_location:
            return
        index = Index.create()
        translation_unit = index.parse(filename, self.flags, options=self.tu_options)
        if not translation_unit:
            log.warning("unable to load input")
            return
        self._parse_tu_diagnostics(translation_unit, filename)
        self.tu = translation_unit
        root = self.tu.cursor
        for node in root.get_children():
            self.start_element(node)
        return

    def parse_string(self, input_data, lang="c", all_warnings=False, flags=None):
        """Use this parser on a memory string/file, instead of a file on disk"""
        translation_unit = util.get_tu(input_data, lang, all_warnings, flags)
        self._parse_tu_diagnostics(translation_unit, "memory_input.c")
        self.tu = translation_unit
        root = self.tu.cursor
        for node in root.get_children():
            self.start_element(node)

    @staticmethod
    def _parse_tu_diagnostics(translation_unit, input_filename):
        if len(translation_unit.diagnostics) == 0:
            return
        errors = []
        for diagnostic in translation_unit.diagnostics:
            msg = (
                f"{diagnostic.spelling} ({diagnostic.location.file}:{diagnostic.location.line}:"
                f"{diagnostic.location.column}) during processing {input_filename}"
            )
            log.warning(msg)
            if diagnostic.severity > 2:
                errors.append(msg)
        if len(errors) > 0:
            log.warning("Source code has %d error. Please fix.", len(errors))
            # code.interact(local=locals())
            raise InvalidTranslationUnitException(errors[0])

    def start_element(self, node):
        """Recurses in children of this node"""
        if node is None:
            return None

        if self.__filter_location is not None:
            # dont even parse includes.
            # FIXME: go back on dependencies ?
            if node.location.file is None:
                return None
            filepath = os.path.abspath(node.location.file.name)
            if filepath not in self.__filter_location:
                if not filepath.startswith("/usr"):
                    log.debug("skipping include '%s'", filepath)
                return None
        # find and call the handler for this element
        log.debug(
            "%s:%d: Found a %s|%s|%s",
            node.location.file,
            node.location.line,
            node.kind.name,
            node.displayname,
            node.spelling,
        )
        # build stuff.
        try:
            stop_recurse = self.parse_cursor(node)
            if node.location.file is not None:
                filepath = os.path.abspath(node.location.file.name)
                self.__processed_location.add(filepath)
            # Signature of parse_cursor is:
            # if the fn returns True, do not recurse into children.
            # anything else will be ignored.
            if stop_recurse is not False:  # True:
                return None
            # if fn returns something, if this element has children, treat
            # them.
            for child in node.get_children():
                self.start_element(child)
        except InvalidDefinitionError:
            log.exception("Invalid definition")
            # if the definition is invalid
        # startElement returns None.
        return None

    def register(self, name, obj):
        """Registers an unique type description"""
        if (name, obj) in self.all_set:
            log.debug("register: %s already defined: %s", name, obj.name)
            return self.all[name]
        if name in self.all:
            if not isinstance(self.all[name], typedesc.Structure) or (self.all[name].members is not None):
                # code.interact(local=locals())
                raise DuplicateDefinitionException(
                    f"register: {name} which has a previous incompatible definition: {obj.name}"
                    f"\ndefined here: {obj.location}"
                    f"\npreviously defined here: {self.all[name].location}"
                )
            if isinstance(self.all[name], typedesc.Structure) and (self.all[name].members is None):
                return obj
        log.debug("register: %s ", name)
        self.all[name] = obj
        self.all_set.add((name, obj))
        return obj

    def get_registered(self, name):
        """Returns a registered type description"""
        return self.all[name]

    def is_registered(self, name):
        """Checks if a named type description is registered"""
        return name in self.all

    def remove_registered(self, name):
        """Removes a named type"""
        log.debug("Unregister %s", name)
        self.all_set.remove((name, self.all[name]))
        del self.all[name]

    def make_ctypes_convertor(self, _flags):
        """
        Fix clang types to ctypes conversion for this parsing instance.
        Some architecture dependent size types have to be changed if the target
        architecture is not the same as local
        """
        # NOTE: one could also use the __SIZEOF_x__ MACROs to obtain sizes.
        translation_unit = util.get_tu(
            """
typedef short short_t;
typedef int int_t;
typedef long long_t;
typedef long long longlong_t;
typedef float float_t;
typedef double double_t;
typedef long double longdouble_t;
typedef void* pointer_t;""",
            flags=_flags,
        )
        size = util.get_cursor(translation_unit, "short_t").type.get_size() * 8
        self.ctypes_typename[TypeKind.SHORT] = f"c_int{size:d}"
        self.ctypes_typename[TypeKind.USHORT] = f"c_uint{size:d}"
        self.ctypes_sizes[TypeKind.SHORT] = size
        self.ctypes_sizes[TypeKind.USHORT] = size

        size = util.get_cursor(translation_unit, "int_t").type.get_size() * 8
        self.ctypes_typename[TypeKind.INT] = f"c_int{size:d}"
        self.ctypes_typename[TypeKind.UINT] = f"c_uint{size:d}"
        self.ctypes_sizes[TypeKind.INT] = size
        self.ctypes_sizes[TypeKind.UINT] = size

        size = util.get_cursor(translation_unit, "long_t").type.get_size() * 8
        self.ctypes_typename[TypeKind.LONG] = f"c_int{size:d}"
        self.ctypes_typename[TypeKind.ULONG] = f"c_uint{size:d}"
        self.ctypes_sizes[TypeKind.LONG] = size
        self.ctypes_sizes[TypeKind.ULONG] = size

        size = util.get_cursor(translation_unit, "longlong_t").type.get_size() * 8
        self.ctypes_typename[TypeKind.LONGLONG] = f"c_int{size:d}"
        self.ctypes_typename[TypeKind.ULONGLONG] = f"c_uint{size:d}"
        self.ctypes_sizes[TypeKind.LONGLONG] = size
        self.ctypes_sizes[TypeKind.ULONGLONG] = size

        # FIXME : Float && http://en.wikipedia.org/wiki/Long_double
        size0 = util.get_cursor(translation_unit, "float_t").type.get_size() * 8
        size1 = util.get_cursor(translation_unit, "double_t").type.get_size() * 8
        size2 = util.get_cursor(translation_unit, "longdouble_t").type.get_size() * 8
        # 2014-01 stop generating crap.
        # 2015-01 reverse until better solution is found
        # the idea is that you cannot assume a c_double will be same format as a c_long_double.
        # at least this pass size TU
        if size1 != size2:
            self.ctypes_typename[TypeKind.LONGDOUBLE] = "c_long_double_t"
        else:
            self.ctypes_typename[TypeKind.LONGDOUBLE] = "c_double"

        self.ctypes_sizes[TypeKind.FLOAT] = size0
        self.ctypes_sizes[TypeKind.DOUBLE] = size1
        self.ctypes_sizes[TypeKind.LONGDOUBLE] = size2

        # save the target pointer size.
        size = util.get_cursor(translation_unit, "pointer_t").type.get_size() * 8
        self.ctypes_sizes[TypeKind.POINTER] = size
        self.ctypes_sizes[TypeKind.NULLPTR] = size

        log.debug(
            "ARCH sizes: long:%s longdouble:%s",
            self.ctypes_typename[TypeKind.LONG],
            self.ctypes_typename[TypeKind.LONGDOUBLE],
        )
        return

    def get_ctypes_name(self, typekind):
        return self.ctypes_typename[typekind]

    def get_ctypes_size(self, typekind):
        return self.ctypes_sizes[typekind]

    def parse_cursor(self, cursor):
        """Forward parsing calls to dedicated CursorKind Handlder"""
        return self.cursorkind_handler.parse_cursor(cursor)

    def parse_cursor_type(self, _cursor_type):
        """Forward parsing calls to dedicated TypeKind Handlder"""
        return self.typekind_handler.parse_cursor_type(_cursor_type)

    ###########################################################################

    ################

    def get_macros(self, text):
        if text is None:
            return
        text = "".join(text)
        # preprocessor definitions that look like macros with one or more
        # arguments
        for macro in text.splitlines():
            name, body = macro.split(None, 1)
            name, args = name.split("(", 1)
            args = f"({args}"
            self.all[name] = typedesc.Macro(name, args, body)

    def get_aliases(self, text, namespace):
        if text is None:
            return
        # preprocessor definitions that look like aliases:
        #  #define A B
        text = "".join(text)
        aliases = {}
        for alias in text.splitlines():
            name, value = alias.split(None, 1)
            alias = typedesc.Alias(name, value)
            aliases[name] = alias
            self.all[name] = alias

        for name, alias in aliases.items():
            value = alias.alias
            # the value should be either in namespace...
            if value in namespace:
                # set the type
                alias.typ = namespace[value]
            # or in aliases...
            elif value in aliases:
                alias.typ = aliases[value]
            # or unknown.
            else:
                # not known
                # print "skip %s = %s" % (name, value)
                pass

    def get_result(self):
        # all of these should register()
        interesting = (
            typedesc.Typedef,
            typedesc.Enumeration,
            typedesc.EnumValue,
            typedesc.Function,
            typedesc.Structure,
            typedesc.Union,
            typedesc.Variable,
            typedesc.Macro,
            typedesc.Alias,
            typedesc.FunctionType,
        )
        # typedesc.Field) #???

        self.get_macros(self.cpp_data.get("functions"))
        # fix all objects after that all are resolved
        remove = []
        for _id, _item in self.all.items():
            if _item is None:
                log.warning("ignoring %s", _id)
                continue
            location = getattr(_item, "location", None)
            # FIXME , why do we get different location types
            if location and hasattr(location, "file"):
                _item.location = location.file.name, location.line
                log.error("%s %s came in with a SourceLocation", _id, _item)
            elif location is None:
                # FIXME make this optional to be able to see internals
                # FIXME macro/alias are here
                log.warning("No source location in %s - ignoring", _id)
                remove.append(_id)

        for _x in remove:
            self.remove_registered(_x)

        # Now we can build the namespace.
        namespace = {}
        for i in self.all.values():
            if not isinstance(i, interesting):
                log.debug("ignoring %s", i)
                continue  # we don't want these
            name = getattr(i, "name", None)
            if name is not None:
                namespace[name] = i
        self.get_aliases(self.cpp_data.get("aliases"), namespace)

        result = []
        for i in self.all.values():
            if isinstance(i, interesting):
                result.append(i)

        log.debug("parsed items order: %s", result)
        return result
