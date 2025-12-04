import unittest
import ctypes

from test.util import ClangTest

'''Test if pointers are correctly generated in structures for different target
archictecture.
'''


class Pointer(ClangTest):
    #@unittest.skip('')

    def test_x32_pointer(self):
        flags = ['-target', 'i386-linux']
        self.convert('''typedef int* A;''', flags)
        self.assertEqual(ctypes.sizeof(self.namespace.A), 4)

    def test_x64_pointer(self):
        flags = ['-target', 'x86_64-linux']
        self.convert('''typedef int* A;''', flags)
        self.assertEqual(ctypes.sizeof(self.namespace.A), 8)

    @unittest.expectedFailure
    def test_member_pointer(self):
        flags = ['-target', 'x86_64-linux', '-x', 'c++']
        self.convert('''
        struct Blob {
          int i;
        };
        int Blob::*member_pointer;
        ''', flags)
        self.assertEqual(self.namespace.struct_Blob.i.size, 4)
        # FIXME
        self.fail('member pointer')
        #self.assertTrue(isinstance(self.namespace.member_pointer,POINTER_T) )

    def test_same_arch_pointer(self):
        self.convert('''
        typedef char*  PCHAR;
        typedef void*  PVOID;
        ''')
        # print(self.text_output)
        self.assertNotIn('POINTER_T', self.text_output)
        # self.assertIn('POINTER_T', self.text_output)


if __name__ == "__main__":
    unittest.main()
