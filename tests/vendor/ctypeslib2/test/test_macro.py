import unittest
import datetime

from test.util import ClangTest

'''Test if macro are correctly generated.
'''

import logging

# logging.basicConfig(level=logging.DEBUG)


class Macro(ClangTest):
    # @unittest.skip('')

    def setUp(self):
        # we need to generate macro. Which is very long for some reasons.
        self.full_parsing_options = True

    def test_simple_integer_literal(self):
        self.convert('''#define MY_VAL 1''')
        self.assertEqual(self.namespace.MY_VAL, 1)
        self.convert('''#define __MY_VAL 1''')
        self.assertEqual(getattr(self.namespace, "__MY_VAL"), 1)

    def test_long(self):
        self.convert('''#define BIG_NUM_L 1000000L''')
        self.assertEqual(getattr(self.namespace, "BIG_NUM_L"), 1000000)

    def test_signed(self):
        self.convert('''
        #define ZERO 0
        #define POSITIVE 1
        #define NEGATIVE -1
        ''')
        self.assertIn("ZERO", self.namespace)
        self.assertEqual(self.namespace.ZERO, 0)
        self.assertIn("POSITIVE", self.namespace)
        self.assertEqual(self.namespace.POSITIVE, 1)
        self.assertIn("NEGATIVE", self.namespace)
        self.assertEqual(self.namespace.NEGATIVE, -1)

    def test_signed_long_long(self):
        self.convert('''
        #define ZERO 0x0000000000000000LL
        #define POSITIVE 0x0000000080000000LL
        #define NEGATIVE -0x0000000080000000LL
        ''')
        self.assertIn("ZERO", self.namespace)
        self.assertEqual(self.namespace.ZERO, 0)
        self.assertIn("POSITIVE", self.namespace)
        self.assertIn("NEGATIVE", self.namespace)
        self.assertEqual(self.namespace.POSITIVE, 0x0000000080000000)
        self.assertEqual(self.namespace.NEGATIVE, -0x0000000080000000)

    def test_signed_long(self):
        self.convert('''
        #define ZERO 0x0000000000000000L
        #define POSITIVE 0x0000000080000000L
        #define NEGATIVE -0x0000000080000000L
        ''')
        self.assertIn("ZERO", self.namespace)
        self.assertEqual(self.namespace.ZERO, 0)
        self.assertIn("POSITIVE", self.namespace)
        self.assertIn("NEGATIVE", self.namespace)
        self.assertEqual(self.namespace.POSITIVE, 0x0000000080000000)
        self.assertEqual(self.namespace.NEGATIVE, -0x0000000080000000)

    def test_unsigned_long_long(self):
        self.convert('''
        #define ZERO 0x0000000000000000ULL
        #define POSITIVE 0x0000000080000000ULL
        #define NEGATIVE -0x0000000080000000ULL
        ''')
        self.assertIn("ZERO", self.namespace)
        self.assertEqual(self.namespace.ZERO, 0)
        self.assertIn("POSITIVE", self.namespace)
        self.assertIn("NEGATIVE", self.namespace)
        self.assertEqual(self.namespace.POSITIVE, 0x0000000080000000)
        self.assertEqual(self.namespace.NEGATIVE, -0x0000000080000000)

    def test_decimals_typicals(self):
        self.convert('''
        #define ONE_TWO_THREE 1.2e3
        #define FOUR_SIX_SEVEN .4e67
        #define EIGHT_NIGNT_TEN 89.10
        #define ELEVEN +11.f
        ''')
        self.assertIn("ONE_TWO_THREE", self.namespace)
        self.assertIn("FOUR_SIX_SEVEN", self.namespace)
        self.assertIn("EIGHT_NIGNT_TEN", self.namespace)
        self.assertIn("ELEVEN", self.namespace)
        self.assertEqual(self.namespace.ONE_TWO_THREE, 1.2e3)
        self.assertEqual(self.namespace.FOUR_SIX_SEVEN, .4e67)
        self.assertEqual(self.namespace.EIGHT_NIGNT_TEN, 89.10)
        self.assertEqual(self.namespace.ELEVEN, 11.)

    def test_not_decimals(self):
        self.convert('''
        #define ONE_BILLION "1000000000.0"
        ''')
        self.assertIn("ONE_BILLION", self.namespace)
        self.assertEqual(self.namespace.ONE_BILLION, "1000000000.0")

    def test_decimals_dot_ones(self):
        self.convert('''
        #define one1 .1
        #define one2 .1f
        #define one3 .1l
        #define one4 .1L
        #define one5 .1F
        #define one6 +.1
        #define one7 +.1f
        #define one8 +.1l
        #define one9 +.1L
        #define one10 +.1F
        #define one11 -.1
        #define one12 -.1f
        #define one13 -.1l
        #define one14 -.1L
        #define one15 -.1F

        #define one16 .1e0
        #define one17 .1e0f
        #define one18 .1e0l
        #define one19 .1e0L
        #define one20 .1e0F
        #define one21 +.1e0
        #define one22 +.1e0f
        #define one23 +.1e0l
        #define one24 +.1e0L
        #define one25 +.1e0F
        #define one26 -.1e0
        #define one27 -.1e0f
        #define one28 -.1e0l
        #define one29 -.1e0L
        #define one30 -.1e0F

        #define one31 .1E0
        #define one32 .1E0f
        #define one33 .1E0l
        #define one34 .1E0L
        #define one35 .1E0F
        #define one36 +.1E0
        #define one37 +.1E0f
        #define one38 +.1E0l
        #define one39 +.1E0L
        #define one40 +.1E0F
        #define one41 -.1E0
        #define one42 -.1E0f
        #define one43 -.1E0l
        #define one44 -.1E0L
        #define one45 -.1E0F
        ''')
        for name, value in self.namespace.items():
            if not name.startswith("one"):
                continue
            self.assertIn(
                value, (-0.1, 0.1), msg="%s: %s != +/-0.1" % (name, value))

    def test_decimals_ones(self):
        self.convert('''
        #define one1 1.0
        #define one2 1.f
        #define one3 1.l
        #define one4 1.L
        #define one5 1.F
        #define one6 1.0
        #define one7 +1.f
        #define one8 +1.l
        #define one9 +1.L
        #define one10 +1.F
        #define one11 +1.0
        #define one12 -1.f
        #define one13 -1.l
        #define one14 -1.L
        #define one15 -1.F
        #define one16 -1.0


        #define one17 1e0
        #define one18 1.e0
        #define one19 1.0e0
        #define one20 1e+0
        #define one21 1.e+0
        #define one22 1.0e+0
        #define one23 1e-0
        #define one24 1.e-0
        #define one25 1.0e-0

        #define one26 +1e0
        #define one27 +1.e0
        #define one28 +1.0e0
        #define one29 +1e+0
        #define one30 +1.e+0
        #define one31 +1.0e+0
        #define one32 +1e-0
        #define one33 +1.e-0
        #define one34 +1.0e-0
        #define one35 -1e0
        #define one36 -1.e0
        #define one37 -1.0e0
        #define one38 -1e+0
        #define one39 -1.e+0
        #define one40 -1.0e+0
        #define one41 -1e-0
        #define one42 -1.e-0
        #define one43 -1.0e-0

        #define one44 +1e0f
        #define one45 +1.e0f
        #define one46 +1.0e0f
        #define one47 +1e+0f
        #define one48 +1.e+0f
        #define one49 +1.0e+0f
        #define one50 +1e-0f
        #define one51 +1.e-0f
        #define one52 +1.0e-0f
        #define one53 -1e0f
        #define one54 -1.e0f
        #define one55 -1.0e0f
        #define one56 -1e+0f
        #define one57 -1.e+0f
        #define one58 -1.0e+0f
        #define one59 -1e-0f
        #define one60 -1.e-0f
        #define one61 -1.0e-0f

        #define one62 +1e0F
        #define one63 +1.e0F
        #define one64 +1.0e0F
        #define one65 +1e+0F
        #define one66 +1.e+0F
        #define one67 +1.0e+0F
        #define one68 +1e-0F
        #define one69 +1.e-0F
        #define one70 +1.0e-0F
        #define one71 -1e0F
        #define one72 -1.e0F
        #define one73 -1.0e0F
        #define one74 -1e+0F
        #define one75 -1.e+0F
        #define one76 -1.0e+0F
        #define one78 -1e-0F
        #define one79 -1.e-0F
        #define one80 -1.0e-0F

        #define one81 +1e0l
        #define one82 +1.e0l
        #define one83 +1.0e0l
        #define one84 +1e+0l
        #define one85 +1.e+0l
        #define one86 +1.0e+0l
        #define one87 +1e-0l
        #define one88 +1.e-0l
        #define one89 +1.0e-0l
        #define one90 -1e0l
        #define one91 -1.e0l
        #define one92 -1.0e0l
        #define one93 -1e+0l
        #define one94 -1.e+0l
        #define one95 -1.0e+0l
        #define one96 -1e-0l
        #define one97 -1.e-0l
        #define one98 -1.0e-0l

        #define one99 +1e0L
        #define one100 +1.e0L
        #define one101 +1.0e0L
        #define one102 +1e+0L
        #define one103 +1.e+0L
        #define one104 +1.0e+0L
        #define one105 +1e-0L
        #define one106 +1.e-0L
        #define one107 +1.0e-0L
        #define one108 -1e0L
        #define one109 -1.e0L
        #define one110 -1.0e0L
        #define one111 -1e+0L
        #define one112 -1.e+0L
        #define one113 -1.0e+0L
        #define one114 -1e-0L
        #define one115 -1.e-0L
        #define one116 -1.0e-0L

        #define one117 1E0
        #define one118 1.E0
        #define one119 1.0E0
        #define one120 1E+0
        #define one121 1.E+0
        #define one122 1.0E+0
        #define one123 1E-0
        #define one124 1.E-0
        #define one125 1.0E-0
        #define one126 +1E0
        #define one127 +1.E0
        #define one128 +1.0E0
        #define one129 +1E+0
        #define one130 +1.E+0
        #define one131 +1.0E+0
        #define one132 +1E-0
        #define one133 +1.E-0
        #define one134 +1.0E-0
        #define one135 -1E0
        #define one136 -1.E0
        #define one137 -1.0E0
        #define one138 -1E+0
        #define one139 -1.E+0
        #define one140 -1.0E+0
        #define one141 -1E-0
        #define one142 -1.E-0
        #define one143 -1.0E-0

        #define one144 +1E0f
        #define one145 +1.E0f
        #define one146 +1.0E0f
        #define one147 +1E+0f
        #define one148 +1.E+0f
        #define one149 +1.0E+0f
        #define one150 +1E-0f
        #define one151 +1.E-0f
        #define one152 +1.0E-0f
        #define one153 -1E0f
        #define one154 -1.E0f
        #define one155 -1.0E0f
        #define one156 -1E+0f
        #define one157 -1.E+0f
        #define one158 -1.0E+0f
        #define one159 -1E-0f
        #define one160 -1.E-0f
        #define one161 -1.0E-0f

        #define one162 +1E0F
        #define one163 +1.E0F
        #define one164 +1.0E0F
        #define one165 +1E+0F
        #define one166 +1.E+0F
        #define one167 +1.0E+0F
        #define one168 +1E-0F
        #define one169 +1.E-0F
        #define one170 +1.0E-0F
        #define one171 -1E0F
        #define one172 -1.E0F
        #define one173 -1.0E0F
        #define one174 -1E+0F
        #define one175 -1.E+0F
        #define one176 -1.0E+0F
        #define one177 -1E-0F
        #define one178 -1.E-0F
        #define one180 -1.0E-0F

        #define one181 +1E0l
        #define one182 +1.E0l
        #define one183 +1.0E0l
        #define one184 +1E+0l
        #define one185 +1.E+0l
        #define one186 +1.0E+0l
        #define one187 +1E-0l
        #define one188 +1.E-0l
        #define one189 +1.0E-0l
        #define one190 -1E0l
        #define one191 -1.E0l
        #define one192 -1.0E0l
        #define one193 -1E+0l
        #define one194 -1.E+0l
        #define one195 -1.0E+0l
        #define one196 -1E-0l
        #define one197 -1.E-0l
        #define one198 -1.0E-0l

        #define one199 +1E0L
        #define one200 +1.E0L
        #define one201 +1.0E0L
        #define one202 +1E+0L
        #define one203 +1.E+0L
        #define one204 +1.0E+0L
        #define one205 +1E-0L
        #define one206 +1.E-0L
        #define one207 +1.0E-0L
        #define one208 -1E0L
        #define one209 -1.E0L
        #define one210 -1.0E0L
        #define one211 -1E+0L
        #define one212 -1.E+0L
        #define one213 -1.0E+0L
        #define one214 -1E-0L
        #define one215 -1.E-0L
        #define one216 -1.0E-0L
        ''')
        for name, value in self.namespace.items():
            if not name.startswith("one"):
                continue
            self.assertIn(
                value, (-1.0, 1.0), msg="%s: %s != +/- 1.0" % (name, value))

    def test_char_arrays(self):
        self.convert('''
#define PRE "before"
#define POST " after"
#define APREPOST PRE POST

char a[] = "what";
char b[] = "why" " though";
char c[] = PRE POST;
char d[] = APREPOST;''')
        self.assertEqual(self.namespace.a, "what")
        self.assertEqual(self.namespace.b, "why though")
        self.assertEqual(self.namespace.c, 'before after')
        self.assertEqual(self.namespace.d, 'before after')
        # print(self.text_output)

    def test_char_arrays_arm_linux(self):
        """c_char is c_ubyte on arm-linux-gnueabihf"""
        self.convert('''
    #define PRE "before"
    #define POST " after"
    #define APREPOST PRE POST

    char a[] = "what";
    char b[] = "why" " though";
    char c[] = PRE POST;
    char d[] = APREPOST;''', ['-target', 'arm-linux-gnueabihf'])
        self.assertEqual(self.namespace.a, "what")
        self.assertEqual(self.namespace.b, "why though")
        self.assertEqual(self.namespace.c, 'before after')
        self.assertEqual(self.namespace.d, 'before after')
        # print(self.text_output)

    @unittest.expectedFailure
    def test_define_wchar_t(self):
        """'L' means wchar_t"""
        # currently this fails because of wchar being an int on this arch.
        # 2025 FIXME
        #  exec(output, namespace)
        #      File "<string>", line 259
        #     __REDIRECT_FORTIFY_NTH = nameproto__asm__(__ASMNAME(#alias))[UndefinedIdentifier(name=__attribute__), '(', '(', UndefinedIdentifier(name=__nothrow__), True, ')', ')'] # macro
        #                                                        ^
        # SyntaxError: '(' was never closed
        self.convert("""
        #define SPAM "spam"
        #define STRING_NULL "NULL"
        #define FOO L"foo"
        
        #include <wchar.h>
        wchar_t * my_foo = FOO;
        """)
        # print(self.text_output)
        self.assertEqual(self.namespace.SPAM, "spam")
        self.assertEqual(self.namespace.STRING_NULL, "NULL")
        self.assertEqual(self.namespace.FOO, "foo")
        self.assertEqual(self.namespace.my_foo, "foo")

    def test_simple_replace_typedef(self):
        """When macro are used as typedef, it's transparent to us. """
        # Python does not have typedef so who care what type name is a variable ?
        self.convert('''
            #define macro_type int
            macro_type i = 10;
            ''')
        # macro_type = int # macro
        # i = 10 # Variable ctypes.c_int32
        # very little
        self.assertIn("i", self.namespace)
        self.assertEqual(self.namespace.i, 10)
        # print(self.text_output)

    def test_simple_replace_function(self):
        """When macro are used as typedef, it's transparent to us. """
        # Python does not have typedef so who care what type name is a variable ?
        self.convert('''
            #define macro_type int
            macro_type fn(int a, int b) {return a+b} ;
            ''', )
        # macro_type = int # macro
        # i = 10 # Variable ctypes.c_int32
        # very little
        # print(self.text_output)
        self.assertIn("fn", self.namespace)
        # self.assertIn("fn", self.text_output)
        # self.assertEqual(self.namespace.i, 10)

    def test_function(self):
        self.convert('''
#define fn_type void
#define fn_name(a,b) real_name(a,b)
fn_type fn_name(int a, int b);
''')
        self.assertIn("real_name", self.namespace)

    def test_simple_macro_function(self):
        self.convert('''
    #define HI(x) x
    HI(int) y;
    ''')
        # print(self.text_output)
        self.assertIn("y", self.namespace)
        self.assertEqual(self.namespace.y, 0)
        self.assertIn("HI", self.text_output)
        # only comments for functions
        self.assertNotIn("HI", self.namespace)

    def test_example(self):
        self.convert('''
#define DEBUG
#define PROD 1
#define MACRO_EXAMPLE(x,y) {x,y}
// #define MY 1 2 3 4 5 6

int tab1[] = MACRO_EXAMPLE(1,2); 
''')
        # print(self.text_output)
        self.assertIn("tab1", self.namespace)
        self.assertEqual(self.namespace.tab1, [1, 2])
        self.assertEqual(self.namespace.DEBUG, True)
        self.assertEqual(self.namespace.PROD, 1)
        # we don't gen macro functions
        self.assertNotIn('MACRO_EXAMPLE', self.namespace)
        # self.assertEqual(self.namespace.MY, 123456)
        # that is not a thing that compiles

    def test_macro_to_variable(self):
        """Test which macros are going to be defined """
        self.convert('''
        #define SPAM "spam"
        #define NO "no"
        #define SPACE " "
        #define FOO L"foo"
        #define NOSPAM NO SPAM
        #define NO_SPAM NO SPACE SPAM
        #define NO_SPAM_FOO NO SPACE SPAM SPACE FOO
        ''')
        # print(self.text_output)
        self.assertIn('SPAM', self.namespace)
        self.assertEqual('spam', self.namespace.SPAM)
        self.assertIn('NO', self.namespace)
        self.assertEqual('no', self.namespace.NO)
        self.assertIn('SPACE', self.namespace)
        self.assertEqual(' ', self.namespace.SPACE)
        self.assertIn('NO_SPAM', self.namespace)
        self.assertEqual('no spam', self.namespace.NO_SPAM)
        self.assertIn('NO_SPAM_FOO', self.namespace)
        self.assertEqual('no spam foo', self.namespace.NO_SPAM_FOO)

    def test_all(self):
        """Test which macros are going to be defined """
        self.convert('''
        #define DATE __DATE__
        #define DEBUG
        #define PROD 1
        #define MACRO_STRING "abcde"
        #define MACRO_FUNC(x,y) {x,y}
        // #define MACRO_LIST 1 2 3 4 5 6

        int tab1[] = MACRO_FUNC(1,2);
        char date[] = DATE; 
        ''')
        # print(self.text_output)
        self.assertIn('DEBUG', self.namespace.__all__)
        self.assertIn('PROD', self.namespace.__all__)
        self.assertIn('MACRO_STRING', self.namespace.__all__)
        self.assertNotIn('DATE', self.namespace.__all__)
        self.assertNotIn('__DATE__', self.namespace.__all__)
        self.assertNotIn('MACRO_FUNC', self.namespace.__all__)
        # self.assertIn('MACRO_LIST', self.namespace.__all__)

    """
    Bug #77
    2021-03
    Both compiler's Predefined Macros and standard's Preprocessor Macros handling works for string values.
    But predef macros for INTEGER_LITERAL do NOT work.
    https://gcc.gnu.org/onlinedocs/cpp/Standard-Predefined-Macros.html
    https://blog.kowalczyk.info/article/j/guide-to-predefined-macros-in-c-compilers-gcc-clang-msvc-etc..html
    """

    def test_macro_value_with_parenthesis(self):
        self.convert('''
#define CPU_DEF_SET   (-1)
#define another_one   (2)
#define a_tuple   (2,3)
#define HI(x) x
        ''')
        print(self.text_output)
        # we want to allow for macro substitution of (int)
        self.assertIn("CPU_DEF_SET", self.namespace)
        self.assertIn("another_one", self.namespace)
        self.assertIn("a_tuple", self.namespace)
        self.assertEqual(self.namespace.CPU_DEF_SET, -1)
        self.assertEqual(self.namespace.another_one, (2))
        self.assertEqual(self.namespace.a_tuple, (2, 3))
        # but not functions.
        self.assertNotIn("HI", self.namespace)

    def test_defines_predefined(self):
        self.convert('''
#define DATE __DATE__
char c1[] = DATE;
char f[] = __FILE__;
char v2[] = __clang_version__;
''')
        # print(self.text_output)
        self.assertIn("c1", self.namespace)
        # replace leading 0 in day by a whitespace.
        this_date = datetime.datetime.now().strftime("%b %d %Y").replace(" 0", "  ")
        self.assertEqual(self.namespace.c1, this_date)
        self.assertIn("# DATE = __DATE__", self.text_output)
        self.assertIn("f", self.namespace)
        self.assertIn("v2", self.namespace)
        # v2 = '11.0.0' for example
        self.assertIn("v2 = '", self.text_output)

    @unittest.expectedFailure
    def test_defines_predefined_failing(self):
        self.convert('''
// this fails for now
int v = __STDC_VERSION__;
''')
        self.assertIn("v", self.namespace)
        # this is the current limit
        self.assertNotEqual(self.namespace.v, [])

    def test_internal_defines_recursive(self):
        self.convert('''
    #define DATE __DATE__
    #define DATE2 DATE
    char c1[] = DATE2;
        ''')
        # print(self.text_output)
        self.assertIn("c1", self.namespace)
        # replace leading 0 in day by a whitespace.
        this_date = datetime.datetime.now().strftime("%b %d %Y").replace(" 0", "  ")
        self.assertIn("# DATE = __DATE__", self.text_output)
        self.assertIn("# DATE2 = __DATE__", self.text_output)

    @unittest.skip
    def test_internal_defines_recursive_with_operation(self):
        self.convert('''
    #define VERSION __clang_major__
    #define VPLUS (VERSION+1)
    int version = VERSION;
    int vplus = VPLUS;
        ''')
        # print(self.text_output)
        self.assertIn("version", self.namespace)
        self.assertIn("vplus", self.namespace)
        self.assertIn("# VERSION = __clang_major__", self.text_output)
        self.assertIn("# VPLUS = ", self.text_output)

    def test_internal_defines_identifier(self):
        self.convert('''
    #define DATE "now"
    #define DATE2 DATE
    char c1[] = DATE2;
    ''')
        # print(self.text_output)
        self.assertIn("c1", self.namespace)
        self.assertEqual(self.namespace.c1, 'now')
        self.assertIn("DATE", self.namespace)
        self.assertEqual(self.namespace.DATE, 'now')
        self.assertIn("DATE2", self.namespace)
        self.assertEqual(self.namespace.DATE2, 'now')

    def test_pack_attribute(self):
        self.convert('''
    #define PACK __attribute__((aligned(2)))
    #define PACKTO __attribute__((packed))
    
    int x PACK = 0;
    struct foo {
        char a;
        int x[2] PACKTO;
    };
    ''')
        # print(self.text_output)
        self.assertIn("# PACK = __attribute__", self.text_output)
        self.assertIn("# PACKTO = __attribute__", self.text_output)
        self.assertIn("struct_foo", self.namespace)

    def test_enum_macro(self):
        from ctypeslib import translate
        self.namespace = translate('''
        #include <stdint.h>
        enum myEnum {
            MIN=INT32_MIN, 
            MAX=INT32_MAX
        };
        ''')

        # Expect enum stored as 1 byte
        import ctypes
        self.assertEqual(ctypes.sizeof(self.namespace.myEnum), 4)
        self.assertEqual(self.namespace.MIN, -2147483648)
        self.assertEqual(self.namespace.MAX, 2147483647)

    def test_enum_stringize(self):
        """     Stringizing operator (#)
        https://www.geeksforgeeks.org/and-operators-in-c/# """
        self.convert('''
#define mkstr(s) #s
char * ret = mkstr(mytext value);
        ''')
        print(self.text_output)
        self.assertIn("ret", self.namespace)
        self.assertEqual(self.namespace.ret, "mytext value")

    @unittest.expectedFailure
    def test_enum_token_pasting(self):
        """
        Token-pasting operator (##)
        https://www.geeksforgeeks.org/and-operators-in-c/# """
        from ctypeslib import translate
        self.namespace = translate('''
#define concat(a, b) a##b
// char * ret = concat("mytext", "value");
int add = concat(1, 2);
        ''')
        print(self.text_output)
        self.assertIn("add", self.namespace)
        # expected failure, see bug #77
        # "Bug #77 - integer literal from macros don't work"
        self.assertEqual(self.namespace.add, 12)
        self.assertIn("ret", self.namespace)
        self.assertEqual(self.namespace.ret, "mytextvalue")


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
