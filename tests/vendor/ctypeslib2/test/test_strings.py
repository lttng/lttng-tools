import logging
import unittest

from test.util import ClangTest

# logging.basicConfig(level=logging.DEBUG)


class StringConstantsTest(ClangTest):
    """Tests some string variations.
    """

    def test_char(self):
        self.convert("""
        char x = 'x';
        char zero = 0;
        """)
        self.assertEqual(self.namespace.x, 'x')
        self.assertEqual(type(self.namespace.x), str)
        self.assertEqual(self.namespace.zero, 0)

    def test_char_cpp(self):
        self.convert("""
        char x = 'x';
        char zero = 0;
        """, ['-x', 'c++'])
        self.assertEqual(self.namespace.x, 'x')
        self.assertEqual(type(self.namespace.x), str)
        self.assertEqual(self.namespace.zero, 0)

    def test_char_p(self):
        self.convert("""
        char x[10];
        char s[] = {'1',']'};
        char *p = "abcde";
        """)
        self.assertEqual(self.namespace.x, [])
        self.assertEqual(self.namespace.s, ['1', ']'])
        self.assertEqual(self.namespace.p, "abcde")

    def test_wchar_cpp(self):
        """WCHAR (or wchar_t on Visual C++ compiler) is used for Unicode UTF-16 strings."""
        self.convert("""
        wchar_t X = L'X';
        wchar_t w_zero = 0;
        """, ['-x', 'c++'])  # force c++ lang for wchar
        # print(self.text_output)
        self.assertEqual(self.namespace.X, 'X')
        self.assertEqual(type(self.namespace.X), str)
        self.assertEqual(self.namespace.w_zero, 0)
        # type cast will not work.
        # self.assertEqual(type(self.namespace.w_zero), unicode)

    @unittest.expectedFailure
    def test_wchar(self):
        # fails because wchar is an int here.
        self.convert("""
        #include <wchar.h>
        wchar_t X = L'X';
        wchar_t w_zero = 0;
        """, ['-x', 'c'])  # force c lang for wchar
        # wchar_t in c is a c_int32. So type casting to a char type, not so much.
        # print(self.text_output)
        self.assertEqual(self.namespace.X, 'X')
        # self.assertEqual(type(self.namespace.X), unicode)
        self.assertEqual(type(self.namespace.X), str)
        self.assertEqual(self.namespace.w_zero, 0)
        # type cast will not work.
        # self.assertEqual(type(self.namespace.w_zero), unicode)

    def test_raw_prefix_cpp(self):
        self.convert("""
        char X[] = R"abc(This test string)is)abc";
        """, ['-x', 'c++'])  # force c lang for wchar
        # print(self.text_output)
        self.assertEqual('This test string)is', self.namespace.X)

    @unittest.skip
    def test_raw_prefix_cpp_s_suffix(self):
        self.convert("""
        #include <string>
        using namespace std::string_literals;
        
        auto X = R"abc(This test string)is)abc";
        auto X2 = R"abc(This test string)is)abc"s;
        """, ['-x', 'c++'])  # force c lang for wchar
        # print(self.text_output)
        self.assertEqual(self.namespace.X, 'This test string)is')
        self.assertEqual(self.namespace.X2, 'This test string)is')

    def test_unicode(self):
        """ unicode conversion test from unittest in clang"""
        self.gen('test/data/test-strings.cpp', ['-x', 'c++'])
        # force c++ lang for wchar
        # self.assertEqual(self.namespace.aa, '\xc0\xe9\xee\xf5\xfc')  # "Àéîõü")
        self.assertEqual(self.namespace.a, "Кошка")
        # NULL terminated
        #self.assertEqual(len(self.namespace.aa), 6 * 8 // 8 - 1)
        #self.assertEqual(len(self.namespace.a), 11 * 8 // 8 - 1)

    # @unittest.expectedFailure  # succeed in py27
    @unittest.skip("Fails in py3, succeeds in py2")
    def test_iso8859_1(self):
        """ conversion test from unittest in clang"""
        self.gen('test/data/test-strings-8859-1.cpp', ['-x', 'c++'])
        # force c++ lang for wchar
        self.assertEqual(self.namespace.aa, '\xc0\xe9\xee\xf5\xfc')  # "Àéîõü")

    @unittest.expectedFailure
    def test_unicode_wchar(self):
        """ unicode conversion test from unittest in clang"""
        self.gen('test/data/test-strings.cpp', ['-x', 'c++'])
        # should be 10 or 20
        self.assertEqual(len(self.namespace.b.encode("utf-8")), 10)
        # utf-32, not supported. Should be 6 or 12
        self.assertEqual(len(self.namespace.b2.encode("utf-8")), 6)

    # TODO
    # @unittest.expectedFailure # succeed in py27
    @unittest.skip("Fails in py3, succeeds in py2")
    def test_unicode_cpp11(self):
        """ unicode conversion test from unittest in clang"""
        self.gen('test/data/test-strings.cpp', ['-x', 'c++', '--std=c++11'])
        # force c++ lang for wchar
        # source code failures , wchar_16_t, u8 and u8R not recognised
        #self.assertEqual(len(self.namespace.c), 12 * 8 // 8 - 1)
        #self.assertEqual(len(self.namespace.d), 12 * 8 // 8 - 1)
        # should be 6*16/8
        #self.assertEqual(len(self.namespace.e), 11)
        # should be 6*32/8
        self.assertEqual(len(self.namespace.f), 11)
        # should be 6*16/8
        self.assertEqual(len(self.namespace.g), 11)
        # should be 6*32/8
        self.assertEqual(len(self.namespace.h), 11)
        # should be 6*16/8
        self.assertEqual(len(self.namespace.i), 11)




if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
