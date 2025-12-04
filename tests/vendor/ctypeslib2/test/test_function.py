import unittest
import ctypes

from ctypeslib.codegen.util import get_cursor
from ctypeslib.codegen.util import get_tu
from test.util import ClangTest

"""Test if functions are correctly generated.
"""


class TestFunction(ClangTest):
    """
    ctypes.CFUNCTYPE a function type declaration in python code
    Usage:
    - a python function can be used as a callback from C library
    - a function member of struct that we need python code to generate

    When clang2py encounter a function declaration, it should generate code that allows
    the python dev to use the function name to call the C function.
    That means the python code should be as close as possible to
    1. load the library that actually defines the function
    2. setup all function object in python to declare a python CFUNCTYPE.
        fn_name = _libraries['library.so'].fn_name
        fn_name.restype = ctypes.c_int32
        fn_name.argtypes = [ctypes.c_int32]

    Two possible cases:
        a. The library is loaded wih -l, we find the export in the library, and add the library name that works.
            fn_name = _libraries['library.so'].fn_name
        b. The library is not loaded with -l, we put a placeholder with the name of the source file.
            fn_name = _libraries['source_file.c.so'].fn_name


    """

    def setUp(self):
        # we need to generate macro. Which is very long for some reasons.
        self.full_parsing_options = False

    def test_simple_function(self):
        self.convert('''int get_one(int a);''')
        # de facto success in exec()
        self.assertIn('get_one', self.namespace)
        self.assertIn('FIXME_STUB', self.text_output)
        # print(self.text_output)

    def test_simple_function_with_dll(self):
        self.convert('''int twice(int i);''', dlls=['test/data/test-callbacks.so'])
        # print(self.text_output)
        # de facto success in exec()
        self.assertIn('twice', self.namespace)
        self.assertNotIn('FIXME_STUB', self.text_output)

    def test_two_stub_functions(self):
        self.convert('''
        int get_one(int a);
        int get_two(int a, int b);
        ''')
        # de facto success in exec()
        self.assertIn('get_one', self.namespace)
        self.assertIn('get_two', self.namespace)
        self.assertIn('FIXME_STUB', self.text_output)
        # print(self.text_output)

    def test_variadic_function_decl(self):
        self.convert('''
void    log_print(const char * module, int options, int severity, const char * color, int output, const char * fmt, ...);
''')
        self.assertIn('log_print', self.namespace)
        self.assertIn('log_print', self.text_output)

#     def test_function_return_enum(self):
#         flags = ['-target', 'i386-linux']
#         self.convert('''
# enum NUM {
#     ZERO = 0,
#     ONE
# };
# enum NUM get_one();''', flags)


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
