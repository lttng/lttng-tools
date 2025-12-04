import unittest

from test.util import ClangTest


class BasicTypes(ClangTest):

    """Tests the basic types for size.
Because we might (*) generate Fundamental types variable as python variable,
we can't ctypes.sizeof a python object. So we used typedef to verify types sizes
because we can ctypes.sizeof a type name. Just not a variable.

(*) Decision pending review
    """
    code = '''
typedef char _char;
typedef unsigned int _uint;
typedef unsigned long _ulong;
typedef double _double;
typedef long double _longdouble;
typedef float _float;
        '''

    def _check(self):
        """assertSizes compares the python sizeof with the clang sizeof
        This _check is reusable for every arch."""
        self.assertSizes("_char")
        self.assertSizes("_uint")
        self.assertSizes("_ulong")
        self.assertSizes("_double")
        self.assertSizes("_longdouble")
        self.assertSizes("_float")

    def test_x32(self):
        flags = ['-target', 'i386-linux']
        self.convert(self.code, flags)
        self._check()

    def test_x64(self):
        flags = ['-target', 'x86_64-linux']
        self.convert(self.code, flags)
        self._check()

    def test_win32(self):
        flags = ['-target', 'i386-win32']
        self.convert(self.code, flags)
        self._check()

    def test_win64(self):
        flags = ['-target', 'x86_64-win64']
        self.convert(self.code, flags)
        self._check()


class Types(ClangTest):

    """Tests if the codegeneration return the proper types."""
    code = '''
        struct __X {
            int a;
        };
        typedef struct __X __Y;
        __Y v1;
        '''

    def test_double_underscore(self):
        flags = ['-target', 'i386-linux']
        self.convert(self.code, flags)
        self.assertSizes("struct___X")
        # works here, but doesnt work below
        self.assertSizes("__Y")
        self.assertSizes("v1")

    def test_double_underscore_field(self):
        # cant load in namespace with exec and expect to work.
        # Double underscore is a special private field in python
        flags = ['-target', 'i386-linux']
        self.convert(
            '''
        struct __X {
            int a;
        };
        typedef struct __X __Y;
        __Y v1;
        struct Z{
            __Y b;
            };
        ''', flags)
        self.assertSizes("__Y")


class CompareTypes(ClangTest):

    def test_typedef(self):
        flags = ['-target', 'i386-linux']
        self.convert(
            '''
        typedef int A;
        typedef A B;
        typedef B C;
        typedef int* PA;
        typedef PA PB;
        typedef PB* PC;
        typedef PC PD;
        ''', flags)
        self.assertEqual(self.namespace.A, self.namespace.B)
        self.assertEqual(self.namespace.A, self.namespace.C)
        self.assertEqual(self.namespace.PA, self.namespace.PB)
        self.assertEqual(self.namespace.PC, self.namespace.PD)


if __name__ == "__main__":
    unittest.main()
