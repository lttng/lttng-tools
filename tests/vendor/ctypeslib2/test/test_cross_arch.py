import os
import subprocess
import sys
import unittest

from test.util import ClangTest


class CrossArchSimplerCode(ClangTest):
    """Tests we output simpler headers when there is no request from cross arch
    """

    # assertSize for structs
    # self.assertSizes("_char")

    def test_cross_arch_pointer(self):
        flags = ['-target', 'i386-linux']
        self.convert('''typedef int* A;''', flags)
        self.assertIn('POINTER_SIZE is: 4', self.text_output)
        self.assertIn('POINTER_T', self.text_output)
        # print(self.text_output)

    def test_same_arch_pointer(self):
        self.convert('''typedef int* A;''')
        self.assertNotIn('POINTER_T', self.text_output)
        # print(self.text_output)




if __name__ == "__main__":
    unittest.main()
