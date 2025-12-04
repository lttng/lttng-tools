import unittest
import ctypes

from test.util import ClangTest


class CompareSizes(ClangTest):

    """Compare python sizes with the clang framework.
    """

    #@unittest.skip('')
    def test_basic_types_size(self):
        """Test sizes of pod."""
        targets = ['_char', '_short', '_int', '_uint', '_long', '_ulong',
                   '_double', '_longdouble', '_float', '_ptr']
        for flags in [['-target', 'i386-linux'], ['-target', 'x86_64-linux']]:
            self.gen('test/data/test-basic-types.c', flags)
            for name in targets:
                self.assertSizes(name)

    #@unittest.skip('')
    #@unittest.expectedFailure # packed attribute
    def test_records_size(self):
        """Test sizes of records."""
        targets = ['struct_Name', 'struct_Name2', 'struct_Node', 'struct_Node2', 'myEnum',
                   'struct_Node3', 'struct_Node4', 'my__quad_t', 'my_bitfield',
                   'mystruct']
        for flags in [['-target', 'i386-linux'], ['-target', 'x86_64-linux']]:
            self.gen('test/data/test-records.c', flags)
            for name in targets:
                self.assertSizes(name)

    def test_records_fields_offset(self):
        """Test offset of records fields."""
        targets = ['struct_Name', 'struct_Name2', 'struct_Node', 'struct_Node2',
                   'struct_Node3', 'struct_Node4', 'my__quad_t', 'my_bitfield',
                   'mystruct']
        for flags in [['-target', 'i386-linux'], ['-target', 'x86_64-linux']]:
            self.gen('test/data/test-records.c', flags)
            for name in targets:
                self.assertOffsets(name)

    @unittest.expectedFailure
    def test_includes_x32(self):
        """Test sizes of pod with std include."""
        # 2025 FIXME
        # ctypeslib.codegen.handler.InvalidTranslationUnitException: 'bits/libc-header-start.h' file not found (/usr/include/stdint.h:26:10) during processing test/data/test-stdint.cpp
        targets = ['int8_t', 'intptr_t', 'intmax_t']
        # no size here ['a','b','c','d','e','f','g','h']
        # will fail with IncorrectWordSizeError
        self.gen('test/data/test-stdint.cpp', ['-target', 'i386-linux'])
        for name in targets:
            self.assertSizes(name)

    def test_includes(self):
        """Test sizes of pod with std include."""
        targets = ['int8_t', 'intptr_t', 'intmax_t']
        # no size here ['a','b','c','d','e','f','g','h']
        # Todo: struct__IO_FILE is used in gen in POINTER before typedef
        self.gen('test/data/test-stdint.cpp', ['-target', 'x86_64-linux'])
        for name in targets:
            self.assertSizes(name)

    def test_record_complex(self):
        """Test sizes of complex record fields."""
        targets = ['complex1', 'complex2', 'complex3', 'complex4', 'complex5',
                   'complex6']
        for flags in [['-target', 'i386-linux'], ['-target', 'x86_64-linux']]:
            self.gen('test/data/test-records-complex.c', flags)
            for name in targets:
                self.assertSizes(name)
                self.assertOffsets(name)


import logging
import sys
if __name__ == "__main__":
    #logging.basicConfig( stream=sys.stderr, level=logging.DEBUG )
    unittest.main()
