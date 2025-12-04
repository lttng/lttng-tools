import unittest
import ctypes
import logging
import sys

from test.util import ClangTest


class RecordTest(ClangTest):

    """Test if records are correctly generated for different target archictecture.
    """

    def _check_sizes(self):
        self.assertSizes("struct_byte1")
        self.assertSizes("struct_byte1b")
        self.assertSizes("struct_bytes2")
        self.assertSizes("struct_bytes2b")
        self.assertSizes("struct_bytes3b")
        self.assertSizes("struct_bytes3c")
        self.assertSizes("struct_bytes4")
        self.assertSizes("struct_bytes4b")
        self.assertSizes("struct_complex")
        self.assertSizes("struct_complex1")
        self.assertSizes("struct_complex2")
        self.assertSizes("struct_complex3")
        self.assertSizes("struct_anonfield")

    def _check_offsets(self):
        self.assertOffsets("struct_byte1")
        self.assertOffsets("struct_byte1b")
        self.assertOffsets("struct_bytes2")
        self.assertOffsets("struct_bytes2b")
        self.assertOffsets("struct_bytes3b")
        self.assertOffsets("struct_bytes3c")
        self.assertOffsets("struct_bytes4")
        self.assertOffsets("struct_bytes4b")
        self.assertOffsets("struct_complex")
        self.assertOffsets("struct_complex1")
        self.assertOffsets("struct_complex2")
        self.assertOffsets("struct_complex3")
        self.assertOffsets("struct_anonfield")

    #@unittest.skip('')
    def test_simple_x32(self):
        """Test sizes for simple POD types on i386.
        """
        flags = ['-target', 'i386-linux']
        self.gen('test/data/test-bitfield.c', flags)
        self._check_sizes()
        self._check_offsets()

    #@unittest.skip('')
    def test_simple_x64(self):
        """Test sizes for simple POD types on x64.
        """
        flags = ['-target', 'x86_64-linux']
        self.gen('test/data/test-bitfield.c', flags)
        self._check_sizes()
        self._check_offsets()

    # ('TODO, fix the codegen because python doesnt like that')
    #@unittest.expectedFailure
    def test_char_bitfield(self):
        ''' "bit fields not allowed for type c_char" '''
        flags = ['-target', 'x86_64-linux']
        self.convert('''struct bytes3 { // should be 8 bytes
    unsigned int a1; // 0-31
    unsigned int b1:23; // 32-55
    char a2; // 56-64 but python says 64-72
};
''', flags)
        # self.assertSizes("struct_bytes3")
        # self.assertOffsets("struct_bytes3")


def p(s):
    import ctypes
    print('sizeof', ctypes.sizeof(s))
    for x in s._fields_:
        if len(x) == 2:
            f, t = x
            print(f, getattr(s, f))
        else:
            f, t, o = x
            print(f, getattr(s, f))

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    # logging.getLogger('codegen').setLevel(logging.INFO)
    unittest.main(verbosity=2)
