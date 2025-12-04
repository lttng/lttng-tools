import unittest
import ctypes

from test.util import ClangTest, clang2py

from test.util import ClangTest
from ctypeslib.codegen import clangparser
from ctypeslib.codegen.handler import InvalidTranslationUnitException


class TestCPPBaseFeatures(ClangTest):

    def test_namespace(self):
        """check the location comment"""
        p, output, stderr = clang2py(['-i', 'test/data/test-cpp.cpp', '--debug'])
        self.assertEqual(0, p.returncode)
        self.assertNotIn("NAMESPACE is not handled", stderr)

    def test_class(self):
        """check the location comment"""
        p, output, stderr = clang2py(['-i', 'test/data/test-cpp.cpp', '--debug'])
        self.assertEqual(0, p.returncode)
        self.assertIn("class class_Base(", output)


class TestCPP(ClangTest):


    def test_class_base(self):
        self.gen('test/data/test-cpp.cpp')
        self.assertTrue(self.parser.is_registered('class_Base'))
        self.assertTrue(self.parser.is_registered('class_Extended'))

        self.assertHasFieldNamed(self.namespace.class_Base, 'MyPrivateInt')
        self.assertHasFieldNamed(self.namespace.class_Base, 'MyProtectedInt')
        self.assertHasFieldNamed(self.namespace.class_Base, 'MyPublicInt')
        # inheritance
        self.assertHasFieldNamed(self.namespace.class_Extended, 'MyPrivateInt', )
        self.assertHasFieldNamed(self.namespace.class_Extended, 'MyProtectedInt')
        self.assertHasFieldNamed(self.namespace.class_Extended, 'MyPublicInt')
        self.assertHasFieldNamed(self.namespace.class_Extended, 'MyInt')

    # DEBUG:cursorhandler:Unhandled field CursorKind.CXX_ACCESS_SPEC_DECL in record class_Classy
    # DEBUG:cursorhandler:Unhandled field CursorKind.CXX_METHOD in record class_Classy
    # DEBUG:cursorhandler:Unhandled field CursorKind.CONSTRUCTOR in record class_Shape


if __name__ == "__main__":
    # logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    # logging.getLogger('codegen').setLevel(logging.INFO)
    unittest.main()
