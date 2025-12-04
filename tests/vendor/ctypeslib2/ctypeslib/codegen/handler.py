"""Abstract Handler with helper methods."""

from clang.cindex import CursorKind, TypeKind, Cursor

from ctypeslib.codegen import typedesc
from ctypeslib.codegen.util import log_entity

import logging
import re
log = logging.getLogger('handler')


class CursorKindException(TypeError):

    """When a child node of a VAR_DECL is parsed as an initialization value,
    when its not actually part of that initiwlization value."""
    pass


class InvalidDefinitionError(TypeError):

    """When a structure is invalid in the source code,  sizeof, alignof returns
    negatives value. We detect it and do our best."""
    pass


class InvalidTranslationUnitException(TypeError):

    """When a translation unit is invalid"""
    pass


class DuplicateDefinitionException(KeyError):

    """When we encounter a duplicate declaration/definition name."""
    pass


################################################################

class ClangHandler(object):

    """
    Abstract class for handlers.
    """

    def __init__(self, parser):
        self.parser = parser
        self._unhandled = []

    def register(self, name, obj):
        return self.parser.register(name, obj)

    def get_registered(self, name):
        return self.parser.get_registered(name)

    def is_registered(self, name):
        return self.parser.is_registered(name)

    def remove_registered(self, name):
        return self.parser.remove_registered(name)

    def set_location(self, obj, cursor):
        """ Location is also used for codegeneration ordering."""
        if (hasattr(cursor, 'location') and cursor.location is not None and
                cursor.location.file is not None):
            obj.location = (cursor.location.file.name, cursor.location.line)
        return

    def set_comment(self, obj, cursor):
        """ If a comment is available, add it to the typedesc."""
        if isinstance(obj, typedesc.T):
            obj.comment = cursor.brief_comment
        return

    def make_python_name(self, name):
        """Transforms an USR into a valid python name."""
        # FIXME see cindex.SpellingCache
        for k, v in [('<', '_'), ('>', '_'), ('::', '__'), (',', ''), (' ', ''),
                     ("$", "DOLLAR"), (".", "DOT"), ("@", "_"), (":", "_"),
                     ('-', '_')]:
            if k in name:  # template
                name = name.replace(k, v)
            # FIXME: test case ? I want this func to be neutral on C valid
            # names.
            if name.startswith("__"):
                return "_X" + name
        if len(name) == 0:
            pass
        elif name[0] in "01234567879":
            return "_" + name
        return name

    def _make_unknown_name(self, cursor, field_name):
        """Creates a name for unnamed type """
        parent = cursor.lexical_parent
        pname = self.get_unique_name(parent)
        log.debug('_make_unknown_name: Got parent get_unique_name %s',pname)
        # we only look at types declarations
        _cursor_decl = cursor.type.get_declaration()
        # we had the field index from the parent record, as to differenciate
        # between unnamed siblings of a same struct
        _i = 0
        found = False
        # Look at the parent fields to find myself
        for m in parent.get_children():
            # FIXME: make the good indices for fields
            log.debug('_make_unknown_name child %d %s %s %s',_i,m.kind, m.type.kind,m.location)
            if m.kind not in [CursorKind.STRUCT_DECL,CursorKind.UNION_DECL,
                              CursorKind.CLASS_DECL]:#,
                              #CursorKind.FIELD_DECL]:
                continue
            if m == _cursor_decl:
                found = True
                break
            _i+=1
        if not found:
            raise NotImplementedError("_make_unknown_name BUG %s" % cursor.location)
        # truncate parent name to remove the first part (union or struct)
        _premainer = '_'.join(pname.split('_')[1:])
        # name the anonymous record with the field name if it has one
        if field_name:
            name = '%s_%s' % (_premainer, field_name)
        else:
            name = '%s_%d' % (_premainer, _i)
        return name

    def get_unique_name(self, cursor, field_name=None):
        """get the spelling or create a unique name for a cursor"""
        # this gets called for both cursors and types!
        # so cursor.kind can be a CursorKind or a TypeKind
        if cursor.kind in [CursorKind.UNEXPOSED_DECL]:
            return ''
        # covers most cases
        name = cursor.spelling
        if cursor.kind == CursorKind.CXX_BASE_SPECIFIER:
            name = cursor.type.spelling
        # if it's a record decl or field decl and its type is anonymous
        # clang > 16 changes anonymous names to have a parenthetical name
        # so force it to have blank name like it did in earlier clang versions
        # only cursors, not types have .is_anonymous()
        if (isinstance(cursor.kind, CursorKind) and
                cursor.is_anonymous() and '(' in name):
            name = ''
        if name == '':
            # if cursor.is_anonymous():
            # a unnamed object at the root TU
            if (cursor.semantic_parent
                and cursor.semantic_parent.kind == CursorKind.TRANSLATION_UNIT):
                name = self.make_python_name(cursor.get_usr())
                log.debug('get_unique_name: root unnamed type kind %s',cursor.kind)
            elif cursor.kind in [CursorKind.STRUCT_DECL,CursorKind.UNION_DECL,
                                 CursorKind.CLASS_DECL,CursorKind.FIELD_DECL]:
                name = self._make_unknown_name(cursor, field_name)
                log.debug('Unnamed cursor type, got name %s',name)
            else:
                log.debug('Unnamed cursor, No idea what to do')
                #import code
                #code.interact(local=locals())
                return ''
        if cursor.kind in [CursorKind.STRUCT_DECL,CursorKind.UNION_DECL,
                                 CursorKind.CLASS_DECL, CursorKind.CXX_BASE_SPECIFIER]:
            names= {CursorKind.STRUCT_DECL: 'struct',
                    CursorKind.UNION_DECL: 'union',
                    CursorKind.CLASS_DECL: 'class',
                    CursorKind.TYPE_REF: '',
                    CursorKind.CXX_BASE_SPECIFIER: 'class'
                    }
            if 'unnamed at' in name:
                name = re.sub('[^a-zA-Z0-9]', '_', name)
            name = '%s_%s'%(names[cursor.kind],name)
        log.debug('get_unique_name: name "%s"',name)
        return name

    def is_fundamental_type(self, t):
        return (not self.is_pointer_type(t) and
                t.kind in self.parser.ctypes_typename.keys())

    def is_pointer_type(self, t):
        return t.kind == TypeKind.POINTER

    def is_array_type(self, t):
        return (t.kind == TypeKind.CONSTANTARRAY or
                t.kind == TypeKind.INCOMPLETEARRAY or
                t.kind == TypeKind.VARIABLEARRAY or
                t.kind == TypeKind.DEPENDENTSIZEDARRAY)

    def is_unexposed_type(self, t):
        return t.kind == TypeKind.UNEXPOSED

    def is_literal_cursor(self, t):
        return (t.kind == CursorKind.INTEGER_LITERAL or
                t.kind == CursorKind.FLOATING_LITERAL or
                t.kind == CursorKind.IMAGINARY_LITERAL or
                t.kind == CursorKind.STRING_LITERAL or
                t.kind == CursorKind.CHARACTER_LITERAL)

    def get_literal_kind_affinity(self, literal_kind):
        ''' return the list of fundamental types that are adequate for which
        this literal_kind is adequate'''
        if literal_kind == CursorKind.INTEGER_LITERAL:
            return [TypeKind.USHORT, TypeKind.UINT, TypeKind.ULONG,
                    TypeKind.ULONGLONG, TypeKind.UINT128,
                    TypeKind.SHORT, TypeKind.INT, TypeKind.LONG,
                    TypeKind.LONGLONG, TypeKind.INT128, ]
        elif literal_kind == CursorKind.STRING_LITERAL:
            return [TypeKind.CHAR16, TypeKind.CHAR32, TypeKind.CHAR_S,
                    TypeKind.SCHAR, TypeKind.WCHAR]  # DEBUG
        elif literal_kind == CursorKind.CHARACTER_LITERAL:
            return [TypeKind.CHAR_U, TypeKind.UCHAR]
        elif literal_kind == CursorKind.FLOATING_LITERAL:
            return [TypeKind.FLOAT, TypeKind.DOUBLE, TypeKind.LONGDOUBLE]
        elif literal_kind == CursorKind.IMAGINARY_LITERAL:
            return []
        return []

    def get_ctypes_name(self, typekind):
        return self.parser.get_ctypes_name(typekind)

    def get_ctypes_size(self, typekind):
        return self.parser.get_ctypes_size(typekind)

    def parse_cursor(self, cursor):
        return self.parser.parse_cursor(cursor)

    def parse_cursor_type(self, _cursor_type):
        return self.parser.parse_cursor_type(_cursor_type)

    ################################
    # do-nothing element handlers

    @log_entity
    def _pass_through_children(self, node, **args):
        for child in node.get_children():
            self.parser.start_element(child)
        return True

    def _do_nothing(self, node, **args):
        name = self.get_unique_name(node)
        #import code
        # code.interact(local=locals())
        log.warning('_do_nothing for %s/%s',node.kind.name, name)
        return True

    ###########################################
    # TODO FIXME: 100% cursor/type Kind coverage
    def __getattr__(self, name, **args):
        if name not in self._unhandled:
            log.warning('%s is not handled',name)
            self._unhandled.append(name)
        return self._do_nothing
