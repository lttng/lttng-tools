"""
Create ctypes wrapper code for abstract type descriptions.
Type descriptions are collections of typedesc instances.
"""

from __future__ import print_function
from __future__ import unicode_literals

import collections
import ctypes
import logging
import os
import pkgutil
import sys
import textwrap
import io
from io import StringIO

from clang.cindex import TypeKind

from ctypeslib.codegen import clangparser
from ctypeslib.codegen import config
from ctypeslib.codegen import typedesc
from ctypeslib.codegen import util
from ctypeslib.library import Library

log = logging.getLogger("codegen")


class Generator:
    def __init__(self, output, cfg):
        self.output = output
        self.stream = StringIO()
        self.imports = StringIO()
        self.cfg = cfg
        self.generate_locations = cfg.generate_locations
        self.generate_comments = cfg.generate_comments
        self.generate_docstrings = cfg.generate_docstrings
        self.known_symbols = cfg.known_symbols or {}
        self.preloaded_dlls = cfg.preloaded_dlls or []
        if cfg.searched_dlls is None:
            self.searched_dlls = []
        else:
            self.searched_dlls = cfg.searched_dlls

        # we use collections.OrderedDict() to keep ordering
        self.done = collections.OrderedDict()  # type descriptions that have been generated
        self.names = list()  # names that have been generated
        self.more = collections.OrderedDict()
        self.macros = 0
        self.cross_arch_code_generation = cfg.cross_arch
        # what record dependency were generated
        self.head_generated = set()
        self.body_generated = set()

    # pylint: disable=method-hidden
    def enable_fundamental_type_wrappers(self):
        """
        If a type is a int128, a long_double_t or a void, some placeholders need
        to be in the generated code to be valid.
        """
        self.enable_fundamental_type_wrappers = lambda: True
        headers = pkgutil.get_data("ctypeslib", "data/fundamental_type_name.tpl").decode()
        size = str(self.parser.get_ctypes_size(TypeKind.LONGDOUBLE) // 8)
        headers = headers.replace("__LONG_DOUBLE_SIZE__", size)
        print(headers, file=self.imports)

    def enable_pointer_type(self):
        """
        If a type is a pointer, a platform-independent POINTER_T type needs
        to be in the generated code.
        """
        # only enable if cross arch mode is on
        if not self.cross_arch_code_generation:
            return "ctypes.POINTER"
        self.enable_pointer_type = lambda: "POINTER_T"
        headers = pkgutil.get_data("ctypeslib", "data/pointer_type.tpl").decode()
        # assuming a LONG also has the same sizeof than a pointer.
        word_size = self.parser.get_ctypes_size(TypeKind.POINTER) // 8
        word_type = self.parser.get_ctypes_name(TypeKind.ULONG)
        # pylint: disable=protected-access
        word_char = getattr(ctypes, word_type)._type_
        # replacing template values
        headers = headers.replace("__POINTER_SIZE__", str(word_size))
        headers = headers.replace("__REPLACEMENT_TYPE__", word_type)
        headers = headers.replace("__REPLACEMENT_TYPE_CHAR__", word_char)
        print(headers, file=self.imports)
        return "POINTER_T"

    def enable_structure_type(self):
        """
        If a structure type is used, declare our ctypes.Structure extension type
        """
        self.enable_structure_type = lambda: True
        headers = pkgutil.get_data("ctypeslib", "data/structure_type.tpl").decode()
        print(headers, file=self.imports)

    def enable_string_cast(self):
        """
        If a structure type is used, declare our ctypes.Structure extension type
        """
        self.enable_string_cast = lambda: True
        headers = pkgutil.get_data("ctypeslib", "data/string_cast.tpl").decode()
        headers = headers.replace("__POINTER_TYPE__", self.enable_pointer_type())
        print(headers, file=self.imports)

    def generate_headers(self, parser):
        # fix parser in self for later use
        self.parser = parser
        headers = pkgutil.get_data("ctypeslib", "data/headers.tpl").decode()
        # get sizes from clang library
        word_size = self.parser.get_ctypes_size(TypeKind.LONG) // 8
        pointer_size = self.parser.get_ctypes_size(TypeKind.POINTER) // 8
        longdouble_size = self.parser.get_ctypes_size(TypeKind.LONGDOUBLE) // 8
        # replacing template values
        headers = headers.replace("__FLAGS__", str(self.parser.flags))
        headers = headers.replace("__WORD_SIZE__", str(word_size))
        headers = headers.replace("__POINTER_SIZE__", str(pointer_size))
        headers = headers.replace("__LONGDOUBLE_SIZE__", str(longdouble_size))
        print(headers, file=self.imports)

    def type_name(self, t, generate=True):
        """
        Returns a string containing an expression that can be used to
        refer to the type. Assumes the 'from ctypes import *'
        namespace is available.
        """
        # no Test case for these
        # elif isinstance(t, typedesc.Argument):
        # elif isinstance(t, typedesc.CvQualifiedType):
        # elif isinstance(t, typedesc.Variable):
        #   return "%s" % self.type_name(t.typ, generate)
        # elif isinstance(t, typedesc.Enumeration):
        #   return t.name

        if isinstance(t, typedesc.FundamentalType):
            return self.FundamentalType(t)
        if isinstance(t, typedesc.ArrayType):
            # C99 feature called the flexible array member feature.
            # changing this to a pointer is incorrect.
            # if t.size == 0:
            #     pointer_class = self.enable_pointer_type()
            #     return "%s(%s)" % (pointer_class, self.type_name(t.typ, generate))
            # else:
            return "%s * %s" % (self.type_name(t.typ, generate), t.size)
        if isinstance(t, typedesc.PointerType) and isinstance(t.typ, typedesc.FunctionType):
            return self.type_name(t.typ, generate)
        if isinstance(t, typedesc.PointerType):
            pointer_class = self.enable_pointer_type()
            if t.typ.name in ["c_ubyte", "c_char"]:
                self.enable_string_cast()
            return "%s(%s)" % (pointer_class, self.type_name(t.typ, generate))
        if isinstance(t, typedesc.FunctionType):
            args = [self.type_name(x, generate) for x in [t.returns] + list(t.iterArgTypes())]
            if "__stdcall__" in t.attributes:
                return "ctypes.WINFUNCTYPE(%s)" % ", ".join(args)
            else:
                return "ctypes.CFUNCTYPE(%s)" % ", ".join(args)
        # elif isinstance(t, typedesc.Structure):
        # elif isinstance(t, typedesc.Typedef):
        # elif isinstance(t, typedesc.Union):
        return t.name
        # All typedesc typedefs should be handled
        # raise TypeError('This typedesc should be handled %s'%(t))

    ################################################################

    _aliases = 0

    def Alias(self, alias):
        """Handles Aliases. No test cases yet"""
        # FIXME
        if self.generate_comments:
            self.print_comment(alias)
        print("%s = %s # alias" % (alias.name, alias.alias), file=self.stream)
        self._aliases += 1
        return

    _macros = 0

    def Macro(self, macro):
        """
        Handles macro. No test cases else that #defines.

        Clang will first give us the macro definition,
        and then later, the macro reference in code will be replaced by teh macro body.
        So really, there is nothing to actually generate.
        Just push the macro in comment, and let the rest work away

        """
        if macro.location is None:
            log.info("Ignoring %s with no location", macro.name)
            return
        if self.generate_locations:
            print("# %s:%s" % macro.location, file=self.stream)
        if self.generate_comments:
            self.print_comment(macro)

        # get tokens types all the way to here ?
        # 1. clang makes the decision on type casting and validity of data.
        # let's not try to be clever.
        # only ignore, undefined references, macro functions...
        # 2. or get a flag in macro that tells us if something contains undefinedIdentifier
        # is not code-generable ?
        # codegen should decide what codegen can do.
        if macro.args:
            print("# def %s%s:  # macro" % (macro.name, macro.args), file=self.stream)
            print("#    return %s  " % macro.body, file=self.stream)
        elif util.contains_undefined_identifier(macro):
            # we can't handle that, we comment it out
            if isinstance(macro.body, typedesc.UndefinedIdentifier):
                print("# %s = %s # macro" % (macro.name, macro.body.name), file=self.stream)
            else:  # we assume it's a list
                print("# %s = %s # macro" % (macro.name, " ".join([str(_) for _ in macro.body])), file=self.stream)
        elif isinstance(macro.body, bool):
            print("%s = %s # macro" % (macro.name, macro.body), file=self.stream)
            self.macros += 1
            self.names.append(macro.name)
        elif isinstance(macro.body, str):
            if macro.body == "":
                print("# %s = %s # macro" % (macro.name, macro.body), file=self.stream)
            else:
                body = macro.body
                float_value = util.from_c_float_literal(body)
                if float_value is not None:
                    body = float_value
                # what about integers you ask ? body token that represents token are Integer here.
                # either it's just a thing we gonna print, or we need to have a registered item
                if sum(x=='(' for x in body) != sum(x==')' for x in body):
                    # unbalanced parens means comment
                    print("# %s = %s # macro" % (macro.name, body), file=self.stream)
                else:
                    print("%s = %s # macro" % (macro.name, body), file=self.stream)
                self.macros += 1
                self.names.append(macro.name)
        # This is why we need to have token types all the way here.
        # but at the same time, clang does not type tokens. So we might as well guess them here too
        elif util.body_is_all_string_tokens(macro.body):
            print("%s = %s # macro" % (macro.name, " ".join([str(_) for _ in macro.body])), file=self.stream)
            self.macros += 1
            self.names.append(macro.name)
        else:
            # this might be a token list of float literal
            body = macro.body
            float_value = util.from_c_float_literal(body)
            if float_value is not None:
                body = float_value
            # or anything else that might be a valid python literal...
            print("%s = %s # macro" % (macro.name, body), file=self.stream)
            self.macros += 1
            self.names.append(macro.name)
        return

    _typedefs = 0

    def Typedef(self, tp):
        if self.generate_comments:
            self.print_comment(tp)
        sized_types = {
            "uint8_t": "c_uint8",
            "uint16_t": "c_uint16",
            "uint32_t": "c_uint32",
            "uint64_t": "c_uint64",
            "int8_t": "c_int8",
            "int16_t": "c_int16",
            "int32_t": "c_int32",
            "int64_t": "c_int64",
        }
        name = self.type_name(tp)  # tp.name
        if isinstance(tp.typ, typedesc.FundamentalType) and tp.name in sized_types:
            print("%s = ctypes.%s" % (name, sized_types[tp.name]), file=self.stream)
            self.names.append(tp.name)
            return
        if tp.typ not in self.done:
            # generate only declaration code for records ?
            # if type(tp.typ) in (typedesc.Structure, typedesc.Union):
            #    self._generate(tp.typ.get_head())
            #    self.more.add(tp.typ)
            # else:
            #    self._generate(tp.typ)
            self._generate(tp.typ)
        # generate actual typedef code.
        if tp.name != self.type_name(tp.typ):
            print("%s = %s" % (name, self.type_name(tp.typ)), file=self.stream)

            if isinstance(tp.typ, typedesc.Enumeration):
                print("%s__enumvalues = %s__enumvalues" % (name, self.type_name(tp.typ)), file=self.stream)
                self.names.append("%s__enumvalues" % name)

        self.names.append(tp.name)
        self._typedefs += 1
        return

    def _get_real_type(self, tp):
        # FIXME, kinda useless really.
        if isinstance(tp, typedesc.Typedef):
            if isinstance(tp.typ, typedesc.Typedef):
                raise TypeError("Nested loop in Typedef %s" % tp.name)
            return self._get_real_type(tp.typ)
        elif isinstance(tp, typedesc.CvQualifiedType):
            return self._get_real_type(tp.typ)
        return tp

    _arraytypes = 0

    def ArrayType(self, tp):
        self._generate(self._get_real_type(tp.typ))
        self._generate(tp.typ)
        self._arraytypes += 1

    _functiontypes = 0
    _notfound_functiontypes = 0

    def FunctionType(self, tp):
        self._generate(tp.returns)
        self.generate_all(tp.arguments)
        # print >> self.stream, "%s = %s # Functiontype " % (
        # self.type_name(tp), [self.type_name(a) for a in tp.arguments])
        self._functiontypes += 1

    def Argument(self, tp):
        self._generate(tp.typ)

    _pointertypes = 0

    def PointerType(self, tp):
        # print 'generate', tp.typ
        if isinstance(tp.typ, typedesc.PointerType):
            self._generate(tp.typ)
        elif type(tp.typ) in (typedesc.Union, typedesc.Structure):
            self._generate(tp.typ.get_head())
            self.more[tp.typ] = True
        elif isinstance(tp.typ, typedesc.Typedef):
            self._generate(tp.typ)
        else:
            self._generate(tp.typ)
        self._pointertypes += 1

    def CvQualifiedType(self, tp):
        self._generate(tp.typ)

    _variables = 0
    _notfound_variables = 0

    def Variable(self, tp):
        self._variables += 1
        if self.generate_comments:
            self.print_comment(tp)

        # 2021-02 give me a test case for this. it breaks all extern variables otherwise.
        if tp.extern and self.find_library_with_func(tp):
            dll_library = self.find_library_with_func(tp)
            self._generate(tp.typ)
            # calling convention does not matter for in_dll...
            libname = self.get_sharedlib(dll_library, "cdecl")
            print("%s = (%s).in_dll(%s, '%s')" % (tp.name, self.type_name(tp.typ), libname, tp.name), file=self.stream)
            self.names.append(tp.name)
            # wtypes.h contains IID_IProcessInitControl, for example
            return

        # Hm.  The variable MAY be a #define'd symbol that we have
        # artifically created, or it may be an exported variable that
        # is not in the libraries that we search.  Anyway, if it has
        # no tp.init value we can't generate code for it anyway, so we
        # drop it.
        # if tp.init is None:
        #    self._notfound_variables += 1
        #    return
        # el
        if isinstance(tp.init, typedesc.FunctionType):
            _args = [x for x in tp.typ.iterArgNames()]
            print("%s = %s # args: %s" % (tp.name, self.type_name(tp.init), _args), file=self.stream)
            self.names.append(tp.name)
            return
        elif isinstance(tp.typ, typedesc.PointerType) or isinstance(tp.typ, typedesc.ArrayType):
            if isinstance(tp.typ.typ, typedesc.FundamentalType) and (
                tp.typ.typ.name in ["c_ubyte", "c_char", "c_wchar"]
            ):
                # string
                # FIXME a char * is not a python string.
                # we should output a cstring() construct.
                init_value = repr(tp.init)
            elif isinstance(tp.typ.typ, typedesc.FundamentalType) and (
                "int" in tp.typ.typ.name or "long" in tp.typ.typ.name
            ):
                # array of number
                # CARE: size of elements must match size of array
                # init_value = repr(tp.init)
                init_value = "[%s]" % ",".join([str(x) for x in tp.init])
                # we do NOT want Variable to be described as ctypes object
                # when we can have a python abstraction for them.
                # init_value_type = self.type_name(tp.typ, False)
                # init_value = "(%s)(%s)"%(init_value_type,init_value)
            elif isinstance(tp.typ.typ, typedesc.Structure):
                self._generate(tp.typ.typ)
                init_value = self.type_name(tp.typ, False) + "()"
            else:
                if tp.init is not None:
                    init_value = tp.init
                else:
                    init_value = self.type_name(tp.typ, False) + "()"

        elif isinstance(tp.typ, typedesc.Structure):
            init_value = self.type_name(tp.typ, False)
        elif isinstance(tp.typ, typedesc.FundamentalType) and tp.typ.name in [
            "c_ubyte",
            "c_char",
            "c_wchar",
        ]:
            if tp.init is not None:
                init_value = repr(tp.init)
            else:
                init_value = "'\\x00'"
        else:
            # we want to have FundamentalType variable use the actual
            # type default, and not be a python ctypes object
            # if init_value is None:
            #    init_value = ''; # use default ctypes object constructor
            # init_value = "%s(%s)"%(self.type_name(tp.typ, False), init_value)
            if tp.init is not None:
                # TODO, check that if tp.init is a string literal
                #  and that there is a definition for it ?
                init_value = tp.init
            elif tp.typ.name in ["c_float", "c_double", "c_longdouble"]:
                init_value = 0.0
            else:
                # integers
                init_value = 0
        #
        # print it out
        print("%s = %s # Variable %s" % (tp.name, init_value, self.type_name(tp.typ, False)), file=self.stream)
        #
        self.names.append(tp.name)

    _enumvalues = 0

    def EnumValue(self, tp):
        # FIXME should be in parser
        value = int(tp.value)
        print("%s = %d" % (tp.name, value), file=self.stream)
        self.names.append(tp.name)
        self._enumvalues += 1

    _enumtypes = 0

    def Enumeration(self, tp):
        if self.generate_comments:
            self.print_comment(tp)
        print("", file=self.stream)
        if tp.name:
            print("# values for enumeration '%s'" % tp.name, file=self.stream)
        else:
            print("# values for unnamed enumeration", file=self.stream)
        print("%s__enumvalues = {" % tp.name, file=self.stream)
        for item in tp.values:
            print("    %s: '%s'," % (int(item.value), item.name), file=self.stream)
        print("}", file=self.stream)

        # Some enumerations have the same name for the enum type
        # and an enum value.  Excel's XlDisplayShapes is such an example.
        # Since we don't have separate namespaces for the type and the values,
        # we generate the TYPE last, overwriting the value. XXX
        for item in tp.values:
            self._generate(item)
        if tp.name:
            # Enums can be forced to occupy less space than an int when the compiler flag '-fshort-enums' is set.
            # The size adjustment is done when possible, depending on the values of the enum.
            # In any case, we should trust the enum size returned by the compiler.
            #
            # Furthermore, in order to obtain a correct (un)signed representation in Python,
            # the signedness of the enum is deduced from the sign of enum values.
            # If there is not any negative value in the enum, then the resulting ctype will be unsigned.
            # Sources:
            #   https://stackoverflow.com/a/54527229/1641819
            #   https://stackoverflow.com/a/56432050/1641819

            # Look for any negative value in enum
            has_negative = False
            for item in tp.values:
                if item.value < 0:
                    has_negative = True
                    break

            # Determine enum type depending on its size and signedness
            if tp.size == 1:
                enum_ctype = 'ctypes.c_int8' if has_negative else 'ctypes.c_uint8'
            elif tp.size == 2:
                enum_ctype = 'ctypes.c_int16' if has_negative else 'ctypes.c_uint16'
            elif tp.size == 4:
                enum_ctype = 'ctypes.c_int32' if has_negative else 'ctypes.c_uint32'
            elif tp.size == 8:
                enum_ctype = 'ctypes.c_int64' if has_negative else 'ctypes.c_uint64'
            else:
                enum_ctype = 'ctypes.c_int' if has_negative else 'ctypes.c_uint'

            print("%s = %s # enum" % (tp.name, enum_ctype), file=self.stream)
            self.names.append(tp.name)
        self._enumtypes += 1

    def get_undeclared_type(self, item):
        """
        Checks if a typed has already been declared in the python output
        or is a builtin python type.
        """
        if item.name in self.head_generated:
            return None
        if item in self.done:
            return None
        if isinstance(item, typedesc.FundamentalType):
            return None
        if isinstance(item, typedesc.PointerType):
            return self.get_undeclared_type(item.typ)
        if isinstance(item, typedesc.ArrayType):
            return self.get_undeclared_type(item.typ)
        # else its an undeclared structure.
        return item

    def _get_undefined_head_dependencies(self, struct):
        """Return head dependencies on other record types.
        Head dependencies is exclusive of body dependency. It's one or the other.
        """
        r = dict()
        for m in struct.members:
            if isinstance(m.type, typedesc.PointerType) and typedesc.is_record(m.type.typ):
                r[m.type] = None
        # remove all already defined heads
        r = [_ for _ in r if _.name not in self.head_generated]
        return r

    def _get_undefined_body_dependencies(self, struct):
        """Return head dependencies on other record types.
        Head dependencies is exclusive of body dependency. It's one or the other.
        """
        r = dict()
        for m in struct.members:
            if isinstance(m.type, typedesc.ArrayType) and typedesc.is_record(m.type.typ):
                r[m.type.typ] = None
            elif typedesc.is_record(m.type):
                r[m.type] = None
            elif m.type not in self.done:
                r[m.type] = None
        # remove all already defined bodies
        r = [_ for _ in r if _.name not in self.body_generated]
        return r

    _structures = 0

    def Structure(self, struct):
        if struct.name in self.head_generated and struct.name in self.body_generated:
            self.done[struct] = True
            return
        self.enable_structure_type()
        self._structures += 1
        depends = set()
        # We only print a empty struct.
        if struct.members is None:
            log.info("No members for: %s", struct.name)
            self._generate(struct.get_head(), False)
            return
        # look in bases class for dependencies
        # FIXME - need a real dependency graph maker
        # remove myself, just in case.
        if struct in self.done:
            del self.done[struct]
        # checks members dependencies in bases
        for b in struct.bases:
            depends.update([self.get_undeclared_type(m.type) for m in b.members])
        depends.discard(None)
        if len(depends) > 0:
            log.debug("Generate %s DEPENDS for Bases %s", struct.name, depends)
            for dep in depends:
                self._generate(dep)

        # checks members dependencies
        # test_record_ordering head does not mean declared. _fields_ mean declared
        # CPOINTER members just require a class definition
        # whereas members that are non pointers require a full _fields_ declaration
        # before this record body is defined fully
        # depends.update([self.get_undeclared_type(m.type)
        #                 for m in struct.members])
        # self.done[struct] = True
        # hard dependencies for members types that are not pointer but records
        # soft dependencies for members pointers to record
        undefined_head_dependencies = self._get_undefined_head_dependencies(struct)
        undefined_body_dependencies = self._get_undefined_body_dependencies(struct)

        if len(undefined_body_dependencies) == 0:
            if len(undefined_head_dependencies) == 0:
                # generate this head and body in one go
                # if struct.get_head() not in self.done:
                if struct.name not in self.head_generated:
                    self._generate(struct.get_head(), True)
                    self._generate(struct.get_body(), True)
                else:
                    self._generate(struct.get_body(), False)
            else:
                # generate this head first, to avoid recursive issue, then the dep, then this body
                self._generate(struct.get_head(), False)
                for dep in undefined_head_dependencies:
                    self._generate(dep)
                self._generate(struct.get_body(), False)
        else:
            # hard dep on defining the body of these dependencies
            # generate this head first, to avoid recursive issue, then the dep, then this body
            self._generate(struct.get_head(), False)
            for dep in undefined_head_dependencies:
                self._generate(dep)
            for dep in undefined_body_dependencies:
                self._generate(dep)
            for dep in undefined_body_dependencies:
                if isinstance(dep, typedesc.Structure):
                    self._generate(dep.get_body(), False)
            self._generate(struct.get_body(), False)
        # we defined ourselve
        self.done[struct] = True

    Union = Structure

    def StructureHead(self, head, inline=False):
        if head.name in self.head_generated:
            log.debug("Skipping - Head already generated for %s", head.name)
            return
        log.debug("Head start for %s inline:%s", head.name, inline)
        for struct in head.struct.bases:
            self._generate(struct.get_head())
            # add dependencies
            self.more[struct] = True
        basenames = [self.type_name(b) for b in head.struct.bases]
        if basenames:
            # method_names = [m.name for m in head.struct.members if type(m) is typedesc.Method]
            print(
                "class %s(%s):" % (head.struct.name, ", ".join(basenames)),
                file=self.stream,
            )
        else:
            # methods = [m for m in head.struct.members if type(m) is typedesc.Method]
            if isinstance(head.struct, typedesc.Structure):
                # Inherit from our ctypes.Structure extension
                print("class %s(Structure):" % head.struct.name, file=self.stream)
            elif isinstance(head.struct, typedesc.Union):
                print("class %s(Union):" % head.struct.name, file=self.stream)
        if not inline:
            print("    pass\n", file=self.stream)
        # special empty struct
        if inline and not head.struct.members:
            print("    pass\n", file=self.stream)
        self.names.append(head.struct.name)
        log.debug("Head finished for %s", head.name)
        self.head_generated.add(head.name)

    def StructureBody(self, body, inline=False):
        if body.name in self.body_generated:
            log.debug("Skipping - Body already generated for %s", body.name)
            return
        log.debug("Body start for %s", body.name)
        fields = []
        methods = []
        for m in body.struct.members:
            if isinstance(m, typedesc.Field):
                fields.append(m)
                # if type(m.type) is typedesc.Typedef:
                #    self._generate(get_real_type(m.type))
                # self._generate(m.type)
            elif isinstance(m, typedesc.Method):
                methods.append(m)
                # self._generate(m.returns)
                # self.generate_all(m.iterArgTypes())
            elif isinstance(m, typedesc.Ignored):
                pass
        # handled inline Vs dependent
        log.debug("body inline:%s for structure %s", inline, body.struct.name)
        if not inline:
            prefix = "%s." % body.struct.name
        else:
            prefix = "    "
        if methods:
            # XXX we have parsed the COM interface methods but should
            # we emit any code for them?
            pass
        # LXJ: we pack all the time, because clang gives a precise field offset
        # per target architecture. No need to defer to ctypes logic for that.
        if fields:
            print("%s_pack_ = 1 # source:%s" % (prefix, body.struct.packed), file=self.stream)

        if body.struct.bases:
            if len(body.struct.bases) == 1:  # its a Struct or a simple Class
                self._generate(body.struct.bases[0].get_body(), inline)
            else:  # we have a multi-parent inheritance
                for b in body.struct.bases:
                    self._generate(b.get_body(), inline)
        # field definition normally span several lines.
        # Before we generate them, we need to 'import' everything they need.
        # So, call type_name for each field once,
        for f in fields:
            self.type_name(f.type)

        # unnamed fields get autogenerated names "_0", "_1", "_2", "_3", ...
        unnamed_fields = {}
        for f in fields:
            # _anonymous_ fields are fields of type Structure or Union,
            # that have no name.
            if f.is_anonymous and isinstance(f.type, (typedesc.Structure, typedesc.Union)):
                # anonymous types can have a member name
                # un-named anonymous record come here with a name == ''
                if f.name == '':
                    unnamed_fields[f] = "_%d" % len(unnamed_fields)
                # otherwise, we want to keep that field's name
        if unnamed_fields:
            unnamed_fields_str = ", ".join("'%s'" % _ for _ in unnamed_fields.values())
            print("%s_anonymous_ = (%s,)" % (prefix, unnamed_fields_str), file=self.stream)
        if len(fields) > 0:
            print("%s_fields_ = [" % prefix, file=self.stream)
            if self.generate_locations and body.struct.location:
                print("    # %s %s" % body.struct.location, file=self.stream)
            for f in fields:
                fieldname = unnamed_fields.get(f, f.name)
                type_name = self.type_name(f.type)
                # handle "__" prefixed names by using a wrapper
                if type_name.startswith("__"):
                    type_name = "globals()['%s']" % type_name
                # a bitfield needs a triplet
                if f.is_bitfield is False:
                    print("    ('%s', %s)," % (fieldname, type_name), file=self.stream)
                else:
                    # FIXME: Python bitfield is int32 only.
                    # from clang.cindex import TypeKind
                    # print fieldname
                    # import code
                    # code.interact(local=locals())
                    print("    ('%s', %s, %s)," % (fieldname, self.type_name(f.type), f.bits), file=self.stream)
            if inline:
                print(prefix, end=" ", file=self.stream)
            print("]\n", file=self.stream)
        log.debug("Body finished for %s", body.name)
        self.body_generated.add(body.name)

    def find_library_with_func(self, func):
        if hasattr(func, "dllname"):
            return func.dllname
        name = func.name
        if os.name == "posix" and sys.platform == "darwin":
            name = "_%s" % name
        for dll in self.searched_dlls:
            try:
                getattr(dll, name)
            except AttributeError:
                pass
            else:
                return dll
        return None

    _c_libraries = None

    def need_CLibraries(self):
        # Create a '_libraries' doctionary in the generated code, if
        # it not yet exists. Will map library pathnames to loaded libs.
        if self._c_libraries is None:
            self._c_libraries = {}
            print("_libraries = {}", file=self.imports)

    _stdcall_libraries = None

    def need_WinLibraries(self):
        # Create a '_stdcall_libraries' doctionary in the generated code, if
        # it not yet exists. Will map library pathnames to loaded libs.
        if self._stdcall_libraries is None:
            self._stdcall_libraries = {}
            print("_stdcall_libraries = {}", file=self.imports)

    _dll_stub_issued = False

    def get_sharedlib(self, library, cc, stub=False):
        # deal with missing -l with a stub
        stub_comment = ""
        if stub and not self._dll_stub_issued:
            self._dll_stub_issued = True
            stub_comment = " FunctionFactoryStub() # "
            print("""class FunctionFactoryStub:
    def __getattr__(self, _):
      return ctypes.CFUNCTYPE(lambda y:y)
""", file=self.imports)
            print("# libraries['FIXME_STUB'] explanation", file=self.imports)
            print("# As you did not list (-l libraryname.so) a library that exports this function", file=self.imports)
            print("# This is a non-working stub instead. ", file=self.imports)
            print("# You can either re-run clan2py with -l /path/to/library.so",file=self.imports)
            print("# Or manually fix this by comment the ctypes.CDLL loading", file=self.imports)

        # generate windows call
        if cc == "stdcall":
            self.need_WinLibraries()
            if library._name not in self._stdcall_libraries:
                _ = "_stdcall_libraries[%r] =%s ctypes.WinDLL(%r)" % (library._name, stub_comment, library._filepath)
                print(_, file=self.imports)
                self._stdcall_libraries[library._name] = None
            return "_stdcall_libraries[%r]" % library._name

        # generate clinux call
        self.need_CLibraries()
        if self.preloaded_dlls != []:
            global_flag = ", mode=ctypes.RTLD_GLOBAL"
        else:
            global_flag = ""
        if library._name not in self._c_libraries:
            print("_libraries[%r] =%s ctypes.CDLL(%r%s)" % (library._name, stub_comment, library._filepath, global_flag),
                  file=self.imports)
            self._c_libraries[library._name] = None
        return "_libraries[%r]" % library._name

    _STRING_defined = False

    def need_STRING(self):
        if self._STRING_defined:
            return
        print("STRING = c_char_p", file=self.imports)
        self._STRING_defined = True
        return

    _WSTRING_defined = False

    def need_WSTRING(self):
        if self._WSTRING_defined:
            return
        print("WSTRING = c_wchar_p", file=self.imports)
        self._WSTRING_defined = True
        return

    def Function(self, func):
        # FIXME: why do we call this ? it does nothing
        if self.generate_comments:
            self.print_comment(func)
        self._generate(func.returns)
        self.generate_all(func.iterArgTypes())

        # useful code
        args = [self.type_name(a) for a in func.iterArgTypes()]
        cc = "cdecl"
        if "__stdcall__" in func.attributes:
            cc = "stdcall"

        #
        library = self.find_library_with_func(func)
        if library:
            libname = self.get_sharedlib(library, cc)
        else:

            class LibraryStub:
                _filepath = "FIXME_STUB"
                _name = "FIXME_STUB"

            libname = self.get_sharedlib(LibraryStub(), cc, stub=True)

        argnames = [a or "p%d" % (i + 1) for i, a in enumerate(func.iterArgNames())]

        if self.generate_locations and func.location:
            print("# %s %s" % func.location, file=self.stream)
        # Generate the function decl code
        print("try:", file=self.stream)
        print("    %s = %s.%s" % (func.name, libname, func.name), file=self.stream)
        print("    %s.restype = %s" % (func.name, self.type_name(func.returns)), file=self.stream)
        if self.generate_comments:
            print("# %s(%s)" % (func.name, ", ".join(argnames)), file=self.stream)
        print("    %s.argtypes = [%s]" % (func.name, ", ".join(args)), file=self.stream)
        print("except AttributeError:", file=self.stream)
        print("    pass", file=self.stream)

        if self.generate_docstrings:

            def typeString(typ):
                if hasattr(typ, "name"):
                    return typ.name
                elif hasattr(typ, "typ") and isinstance(typ, typedesc.PointerType):
                    return typeString(typ.typ) + " *"
                else:
                    return "unknown"

            argsAndTypes = zip([typeString(t) for t in func.iterArgTypes()], argnames)
            print(
                '{funcname}.__doc__ = """{ret} {funcname}({args})\n'
                '    {file}:{line}"""'.format(
                    funcname=func.name,
                    args=", ".join(["%s %s" % i for i in argsAndTypes]),
                    file=func.location[0],
                    line=func.location[1],
                    ret=typeString(func.returns),
                ),
                file=self.stream,
            )

        self.names.append(func.name)
        self._functiontypes += 1
        return

    def FundamentalType(self, _type):
        """Returns the proper ctypes class name for a fundamental type

        1) activates generation of appropriate headers for
        ## int128_t
        ## c_long_double_t
        2) return appropriate name for type
        """
        log.debug("HERE in FundamentalType for %s %s", _type, _type.name)
        if _type.name in ["None", "c_long_double_t", "c_uint128", "c_int128"]:
            self.enable_fundamental_type_wrappers()
            return _type.name
        return "ctypes.%s" % _type.name

    ########

    def _generate(self, item, *args):
        """ wraps execution of specific methods."""
        if item in self.done:
            return
        # verbose output with location.
        if self.generate_locations and item.location:
            print("# %s:%d" % item.location, file=self.stream)
        if self.generate_comments:
            self.print_comment(item)
        log.debug("generate %s, %s", item.__class__.__name__, item.name)
        # to avoid infinite recursion, we have to mark it as done
        # before actually generating the code.
        self.done[item] = True
        # go to specific treatment
        mth = getattr(self, type(item).__name__)
        mth(item, *args)
        return

    def print_comment(self, item):
        if item.comment is None:
            return
        for _ in textwrap.wrap(item.comment, 78):
            print("# %s" % _, file=self.stream)
        return

    def generate_all(self, items):
        for item in items:
            self._generate(item)
        return

    def generate_items(self, items):
        # items = set(items)
        loops = 0
        while items:
            loops += 1
            self.more = collections.OrderedDict()
            self.generate_all(items)

            # items |= self.more , but keeping ordering
            _s = set(items)
            [items.append(k) for k in self.more.keys() if k not in _s]

            # items -= self.done, but keep ordering
            _done = self.done.keys()
            for i in list(items):
                if i in _done:
                    items.remove(i)

        return loops

    def generate(self, parser, items):
        self.generate_headers(parser)
        return self.generate_code(items)

    def generate_code(self, items):
        print(
            "\n".join(
                ["ctypes.CDLL('%s', ctypes.RTLD_GLOBAL)" % preloaded_dll for preloaded_dll in self.preloaded_dlls]
            ),
            file=self.imports,
        )
        loops = self.generate_items(items)

        self.output.write(self.imports.getvalue())
        self.output.write("\n\n")
        self.output.write(self.stream.getvalue())

        text = "__all__ = \\"
        # text Wrapper doesn't work for the first line in certain cases.
        print(text, file=self.output)
        # doesn't work for the first line in certain cases.
        wrapper = textwrap.TextWrapper(break_long_words=False, initial_indent="    ", subsequent_indent="    ")
        text = "[%s]" % ", ".join([repr(str(n)) for n in sorted(self.names)])
        for line in wrapper.wrap(text):
            print(line, file=self.output)

        return loops

    def print_stats(self, stream):
        total = (
            self._structures
            + self._functiontypes
            + self._enumtypes
            + self._typedefs
            + self._pointertypes
            + self._arraytypes
        )
        print("###########################", file=stream)
        print("# Symbols defined:", file=stream)
        print("#", file=stream)
        print("# Variables:          %5d" % self._variables, file=stream)
        print("# Struct/Unions:      %5d" % self._structures, file=stream)
        print("# Functions:          %5d" % self._functiontypes, file=stream)
        print("# Enums:              %5d" % self._enumtypes, file=stream)
        print("# Enum values:        %5d" % self._enumvalues, file=stream)
        print("# Typedefs:           %5d" % self._typedefs, file=stream)
        print("# Pointertypes:       %5d" % self._pointertypes, file=stream)
        print("# Arraytypes:         %5d" % self._arraytypes, file=stream)
        print("# unknown functions:  %5d" % self._notfound_functiontypes, file=stream)
        print("# unknown variables:  %5d" % self._notfound_variables, file=stream)
        print("#", file=stream)
        print("# Total symbols: %5d" % total, file=stream)
        print("###########################", file=stream)
        return


################################################################

class CodeTranslator:
    """
    Organiser class to take C files in input, and produce python code in a standard fashion
    """
    def __init__(self, cfg: config.CodegenConfig):
        self.cfg = cfg
        self.parser = None
        self.generator = None
        self.items = []
        self.filtered_items = []

    def preload_dlls(self):
        # FIXME
        self.cfg.preloaded_dlls = [Library(name, nm="nm") for name in self.cfg.preloaded_dlls]

    def make_clang_parser(self):
        self.parser = clangparser.Clang_Parser(self.cfg.clang_opts)
        if typedesc.Macro in self.cfg.types:
            self.parser.activate_macros_parsing()
        if self.cfg.generate_comments:
            self.parser.activate_comment_parsing()
        # FIXME
        # if self.cfg.filter_location:
        #     parser.filter_location(srcfiles)
        return self.parser

    def parse_input_string(self, input_io):
        if self.parser is None:
            self.make_clang_parser()
        self.parser.parse_string(input_io)
        # get the typedesc C types items
        self.items.extend(self.parser.get_result())

    def parse_input_file(self, src_file):
        if self.parser is None:
            self.make_clang_parser()
        self.parser.parse(src_file)
        # get the typedesc C types items
        self.items.extend(self.parser.get_result())

    def parse_input_files(self, src_files: list):
        if self.parser is None:
            self.make_clang_parser()
        # filter location with clang.
        if self.cfg.filter_location:
            self.parser.filter_location(src_files)
        #
        for srcfile in src_files:
            # verifying that is really a file we can open
            with open(srcfile):
                pass
            log.debug("Parsing input file %s", srcfile)
            self.parser.parse(srcfile)
        # get the typedesc C types items
        self.items.extend(self.parser.get_result())

    def make_code_generator(self, output):
        self.generator = Generator(output, cfg=self.cfg)
        return self.generator

    def generate_code(self, output):
        if self.generator is None:
            self.make_code_generator(output)
        self.filtered_items = list(self.items)
        log.debug("%d items before filtering", len(self.filtered_items))
        self.filter_types()
        self.filter_symbols()
        self.filter_expressions()
        log.debug("Left with %d items after filtering", len(self.filtered_items))
        loops = self.generator.generate(self.parser, self.filtered_items)
        if self.cfg.verbose:
            self.generator.print_stats(sys.stderr)
            log.info("needed %d loop(s)", loops)

    def filter_types(self):
        self.filtered_items = [i for i in self.filtered_items if i.__class__ in self.cfg.types]

    def filter_symbols(self):
        if len(self.cfg.symbols) == 0:
            return
        todo = []
        syms = set(self.cfg.symbols)
        for i in self.filtered_items:
            if i.name in syms:
                todo.append(i)
                syms.remove(i.name)
            else:
                log.debug("not generating {}: not a symbol".format(i.name))
        if syms:
            log.warning("symbols not found %s", [str(x) for x in list(syms)])
        self.filtered_items = todo

    def filter_expressions(self):
        if len(self.cfg.expressions) == 0:
            return
        todo = []
        for s in self.cfg.expressions:
            log.debug("regexp: looking for %s", s.pattern)
            for i in self.filtered_items:
                log.debug("regexp: i.name is %s", i.name)
                if i.name is None:
                    continue
                match = s.match(i.name)
                # if we only want complete matches:
                if match and match.group() == i.name:
                    todo.append(i)
                    continue
                # if we follow our own documentation,
                # allow regular expression match of any part of name:
                match = s.search(i.name)
                if match:
                    todo.append(i)
                    continue
        self.filtered_items = todo


# easy to use API.

def translate(input_io, outfile=None, cfg=None):
    """
        Take a readable C like input readable and translate it to python.
    """
    cfg = cfg or config.CodegenConfig()
    translator = CodeTranslator(cfg)
    translator.preload_dlls()
    translator.parse_input_string(input_io)
    # gen python code
    if outfile:
        return translator.generate_code(outfile)
    # otherwise return python
    output = io.StringIO()
    translator.generate_code(output)
    output.seek(0)
    # inject generated code in python namespace
    ignore_coding = output.readline()
    # exec ofi.getvalue() in namespace
    output = ''.join(output.readlines())
    namespace = {}
    exec(output, namespace)
    return util.ADict(namespace)


def translate_files(source_files, outfile=None, cfg: config.CodegenConfig=None):
    """
    Translate the content of source_files in python code in outfile

    source_files: list of filenames or single filename
    """
    cfg = cfg or config.CodegenConfig()
    translator = CodeTranslator(cfg)
    translator.preload_dlls()
    if isinstance(source_files, list):
        translator.parse_input_files(source_files)
    else:
        translator.parse_input_file(source_files)
    log.debug("Input was parsed")
    if outfile:
        return translator.generate_code(outfile)
    # otherwise return python
    output = io.StringIO()
    translator.generate_code(output)
    output.seek(0)
    # inject generated code in python namespace
    ignore_coding = output.readline()
    # exec ofi.getvalue() in namespace
    output = ''.join(output.readlines())
    namespace = {}
    exec(output, namespace)
    return util.ADict(namespace)

