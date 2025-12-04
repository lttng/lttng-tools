import io

from test.util import ClangTest
from ctypeslib.codegen import clangparser
from ctypeslib.codegen.handler import InvalidTranslationUnitException

class TestClang_Parser(ClangTest):

    def setUp(self) -> None:
        # Create a clang parser instance, no flags
        self.parser = clangparser.Clang_Parser([])

    def test_parse(self):
        self.parser.parse('test/data/test-records.c')
        self.assertTrue(self.parser.is_registered('struct_Name'))
        self.assertTrue(self.parser.is_registered('struct_Name2'))
        self.assertFalse(self.parser.is_registered('struct_whatever'))

    def test_parse_string(self):
        source_code = """
struct example_detail {
    int first;
    int last;
};

struct example {
    int args;
    int flags;
    int count;
    struct example_detail details[2];
};
"""
        self.parser.parse_string(source_code)
        self.assertTrue(self.parser.is_registered('struct_example_detail'))
        self.assertTrue(self.parser.is_registered('struct_example'))
        self.assertFalse(self.parser.is_registered('struct_whatever'))
        return

    def test_error_translationunit_does_not_exist(self):
        import clang
        with self.assertRaises(clang.cindex.TranslationUnitLoadError):
            self.parser.parse('what/ever/path/test-error2.c')

    def test_error_translationunit(self):
        with self.assertRaises(InvalidTranslationUnitException):
            self.parser.parse('test/data/test-error2.c')

    def test_error_translationunit_include(self):
        with self.assertRaises(InvalidTranslationUnitException):
            self.parser.parse('test/data/test-error1.c')

