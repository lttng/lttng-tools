# -*- coding: utf-8 -*-
import ctypes
import sys
import logging
import unittest

from test.util import ClangTest


class ConstantsTest(ClangTest):
    """Tests from the original ctypeslib.
    """

    def test_var(self):
        """Basic POD test variable declaration'
        """
        self.convert("""
        int i1;
        static const long i2;
        long double f1;
        static float f2;
        char c;
        """)
        self.assertEqual(self.namespace.i1, 0)
        self.assertEqual(self.namespace.i2, 0)
        self.assertEqual(self.namespace.f1, 0.0)
        self.assertEqual(self.namespace.f2, 0.0)
        self.assertEqual(self.namespace.c, '\x00')

    def test_longlong(self):
        """Basic POD test variable on longlong values
        """
        self.convert("""
        long long int i1 = 0x7FFFFFFFFFFFFFFFLL;
        long long int i2 = -1;
        unsigned long long ui3 = 0xFFFFFFFFFFFFFFFFULL;
        unsigned long long ui2 = 0x8000000000000000ULL;
        unsigned long long ui1 = 0x7FFFFFFFFFFFFFFFULL;
        """, flags=['-target', 'x86_64'])
        self.assertEqual(self.namespace.i1, 0x7FFFFFFFFFFFFFFF)
        self.assertEqual(self.namespace.i2, -1)
        self.assertEqual(self.namespace.ui1, 0x7FFFFFFFFFFFFFFF)
        self.assertEqual(self.namespace.ui3, 0xFFFFFFFFFFFFFFFF)
        self.assertEqual(self.namespace.ui2, 0x8000000000000000)

    def test_int(self):
        self.convert("""
        int zero = 0;
        int one = 1;
        int minusone = -1;
        int maxint = 2147483647;
        int minint = -2147483648;
        """)
        # print(self.text_output)
        self.assertEqual(self.namespace.zero, 0)
        self.assertEqual(self.namespace.one, 1)
        self.assertEqual(self.namespace.minusone, -1)
        self.assertEqual(self.namespace.maxint, 2147483647)
        self.assertEqual(self.namespace.minint, -2147483648)

    def test_uint(self):
        self.convert("""
        unsigned int zero = 0;
        unsigned int one = 1;
        unsigned int maxuint = 0xFFFFFFFF;
        """)
        self.assertEqual(self.namespace.zero, 0)
        self.assertEqual(self.namespace.one, 1)
        self.assertEqual(self.namespace.maxuint, 0xFFFFFFFF)

    def test_doubles(self):
        self.convert("""
        double d = 0.0036;
        float f = 2.5;
        """)
        self.assertAlmostEqual(self.namespace.d, 0.0036)
        self.assertAlmostEqual(self.namespace.f, 2.5)

    def test_typedef(self):
        self.convert("""
        typedef char char_t;
        typedef int array_t[16];
        typedef union u {
            int a;
            int b;
        } u;
        """)
        self.assertEqual(ctypes.sizeof(self.namespace.array_t), 64)
        self.assertEqual(ctypes.sizeof(self.namespace.union_u), 4)
        self.assertSizes("array_t")
        self.assertSizes("union_u")

    def test_array(self):
        self.convert("""
        #include <stdint.h>
        char c1[];
        char c2[3] = {'a','b','c'};
        char c3[] = {'a','b','c'};
        int tab1[];
        int tab2[3] = {1,2,3};
        int tab3[] = {1,2,3};
        uint8_t buf[2048];
        """)
        self.assertEqual(self.namespace.c1, [])
        self.assertEqual(self.namespace.c2, ['a', 'b', 'c'])
        self.assertEqual(self.namespace.c3, ['a', 'b', 'c'])
        self.assertEqual(self.namespace.tab1, [])
        self.assertEqual(self.namespace.tab2, [1, 2, 3])
        self.assertEqual(self.namespace.tab3, [1, 2, 3])
        self.assertEqual(self.namespace.buf, [])

    def test_incomplete_array(self):
        """C99 feature called the flexible array member feature."""
        self.convert("""
        typedef char array[];
        struct blah {
            int N;
            char varsize[];
        };
        struct bar {
            int N;
            char * varsize[];
        };
        """)
        # ctypes returns -2, because this is an incomplete type
        # self.assertSizes("array")
        self.assertSizes("struct_blah")
        self.assertSizes("struct_bar")
        # self brewn size modification
        # we make it an array of size 0 (ctypes.c_char * 0)
        self.assertEqual(ctypes.sizeof(self.namespace.array), 0)

    def test_emptystruct(self):
        self.convert("""
        typedef struct tagEMPTY {
        } EMPTY;
        """)
        self.assertEqual(ctypes.sizeof(self.namespace.struct_tagEMPTY), 0)
        self.assertEqual(ctypes.sizeof(self.namespace.EMPTY), 0)
        self.assertSizes("struct_tagEMPTY")

    def test_struct_named_twice(self):
        self.convert("""
        typedef struct xyz {
            int a;
        } xyz;
        """)
        self.assertEqual(ctypes.sizeof(self.namespace.struct_xyz), 4)
        self.assertEqual(ctypes.sizeof(self.namespace.xyz), 4)
        self.assertSizes('xyz')
        self.assertSizes("struct_xyz")

    def test_struct_with_pointer(self):
        self.convert("""
        struct x {
            int y;
        };
        typedef struct x *x_n_t;

        typedef struct p {
            x_n_t g[1];
        } *p_t;
        """, flags=['-target', 'x86_64'])
        self.assertEqual(ctypes.sizeof(self.namespace.struct_x), 4)
        self.assertEqual(ctypes.sizeof(self.namespace.x_n_t), 8)
        self.assertEqual(ctypes.sizeof(self.namespace.struct_p), 8)
        self.assertEqual(ctypes.sizeof(self.namespace.p_t), 8)
        self.assertSizes('x_n_t')
        self.assertSizes('p_t')

    def test_struct_with_struct_array_member_type(self):
        self.convert("""
        struct foo {
             int bar;
        };
        typedef struct foo foo_t[256];
        typedef struct {
            foo_t baz;
        } somestruct;
        """, flags=['-target', 'i386-linux'])
        self.assertEqual(ctypes.sizeof(self.namespace.struct_foo), 4)
        self.assertEqual(ctypes.sizeof(self.namespace.foo_t), 4 * 256)
        self.assertEqual(ctypes.sizeof(self.namespace.somestruct), 4 * 256)
        self.assertSizes("struct_foo")
        self.assertSizes("foo_t")
        self.assertSizes("somestruct")

    def test_struct_with_struct_array_member(self):
        self.convert("""
        typedef struct A {
            int x
        } structA_t;
        struct B {
            structA_t x[8];
        };
        """, flags=['-target', 'i386-linux'])
        self.assertEqual(ctypes.sizeof(self.namespace.struct_A), 4)
        self.assertEqual(ctypes.sizeof(self.namespace.structA_t), 4)
        self.assertEqual(ctypes.sizeof(self.namespace.struct_B), 4 * 8)
        self.assertSizes("struct_A")
        self.assertSizes("structA_t")
        self.assertSizes("struct_B")

    def test_var_decl_and_scope(self):
        self.convert("""
        int zig;
        inline void foo() {
          int zig;
        };
        """)
        # FIXME: TranslationUnit PARSE_SKIP_FUNCTION_BODIES
        self.assertEqual(self.namespace.zig, 0)
        # self.assertEqual(type(self.namespace.foo), None)

    def test_extern_function_pointer(self):
        self.convert("""
        extern int (*func_ptr)(const char *arg);
        """)
        self.assertEqual(self.namespace.func_ptr._restype_, ctypes.c_int)
        self.assertEqual(
            self.namespace.func_ptr._argtypes_[0].__name__,
            'LP_c_char')

    def test_extern_function_pointer_multiarg(self):
        self.convert("""
        extern int (*func_ptr)(const char *arg, int c);
        """)
        self.assertEqual(self.namespace.func_ptr._restype_, ctypes.c_int)
        self.assertEqual(
            self.namespace.func_ptr._argtypes_[0].__name__,
            'LP_c_char')
        self.assertEqual(
            self.namespace.func_ptr._argtypes_[1].__name__,
            'c_int')

    def test_operation(self):
        self.convert("""
        const int i = -1;
        const int i2 = -1+2*3/2-3;
        const int i3 = -((1-2)*(1-2));
        const int j = -i;
        """)
        self.assertEqual(self.namespace.i, -1)
        self.assertEqual(self.namespace.i2, -1)
        self.assertEqual(self.namespace.i3, -1)
        self.assertEqual(self.namespace.j, 1)

    # @unittest.expectedFailure
    def test_array_operation(self):
        self.convert("""
        const int i = 1;
        const int a[2] = {1,-2};
        const int b[2] = {+1,-2-2+2};
        // const int c[2] = {+i,-i*2};
        const float f[3] = {1,-2, 2.0};
        const long double d[3] = {1.1,-2.1, 3.3};
        const long l[6] = {1,-2, 0x44, 1, 2, -0x02};
        """)
        self.assertEqual(self.namespace.i, 1)
        self.assertEqual(self.namespace.a, [1, -2])
        self.assertEqual(self.namespace.b, [1, -2])
        # self.assertEqual(self.namespace.c, [1, -2])  # unsuported ref_expr
        self.assertEqual(self.namespace.f, [1, -2, 2.0])
        self.assertEqual(self.namespace.d, [1.1, -2.1, 3.3])
        self.assertEqual(self.namespace.l, [1, -2, 0x44, 1, 2, -0x02])

    def test_uint_minus_one(self):
        self.convert("""
        unsigned int minusone = -1;
        """)
        # self.assertEqual(self.namespace.minusone, 4294967295)
        self.assertEqual(self.namespace.minusone, -1)

    def test_macro(self):
        # no macro support yet
        # @unittest.expectedFailure
        self.full_parsing_options = True
        self.convert("""
        #define A  0.9642
        #define B  1.0
        #define C  0.8249
        """)
        self.assertAlmostEqual(self.namespace.A, 0.9642)
        self.assertAlmostEqual(self.namespace.B, 1.0)
        self.assertAlmostEqual(self.namespace.C, 0.8249)

    def test_anonymous_struct(self):
        flags = ['-target', 'i386-linux']
        self.convert(
            """
        struct X {
            struct {
                long cancel_jmp_buf[8];
                int mask_was_saved;
            } cancel_jmp_buf[8];
            void * pad[4];
        };
        """, flags)
        # import code
        # code.interact(local=locals())
        self.assertEqual(ctypes.sizeof(self.namespace.struct_X), 304)
        self.assertSizes("struct_X")

    def test_anonymous_struct_extended(self):
        flags = ['-target', 'x86_64-linux']
        self.convert(
            """
typedef unsigned long int uint64_t;
typedef uint64_t ULONGLONG;
typedef union MY_ROOT_UNION {
 struct {
  ULONGLONG Alignment;
  ULONGLONG Region;
 };
 struct {
     struct {
        ULONGLONG Depth : 16;
        ULONGLONG Sequence : 9;
        ULONGLONG NextEntry : 39;
        ULONGLONG HeaderType : 1;
        ULONGLONG Init : 1;
        ULONGLONG Reserved : 59;
        ULONGLONG Region : 3;
    };
} Header8; // struct_MY_ROOT_UNION_1
 struct {
     struct {
        ULONGLONG Depth : 16;
        ULONGLONG Sequence : 48;
        ULONGLONG HeaderType : 1;
        ULONGLONG Init : 1;
        ULONGLONG Reserved : 2;
        ULONGLONG NextEntry : 60;
    };
} Header16; // struct_MY_ROOT_UNION_2
 struct {
  struct {
     struct {
        ULONGLONG Depth : 16;
        ULONGLONG Sequence : 48;
        ULONGLONG HeaderType : 1;
        ULONGLONG Reserved : 3;
        ULONGLONG NextEntry : 60;
    };
  } HeaderX64; // struct_MY_ROOT_UNION_3_0
 };
} __attribute__((packed)) MY_ROOT_UNION, *PMY_ROOT_UNION, **PPMY_ROOT_UNION ;
        """, flags)
        self.assertIn("MY_ROOT_UNION", self.namespace.keys())
        self.assertIn("struct_MY_ROOT_UNION_0", self.namespace.keys())
        self.assertNotIn("struct_MY_ROOT_UNION_1", self.namespace.keys())
        self.assertIn("struct_MY_ROOT_UNION_Header8", self.namespace.keys())
        self.assertNotIn("struct_MY_ROOT_UNION_2", self.namespace.keys())
        self.assertIn("struct_MY_ROOT_UNION_Header16", self.namespace.keys())
        self.assertIn("struct_MY_ROOT_UNION_3", self.namespace.keys())
        self.assertNotIn("struct_MY_ROOT_UNION_3_0", self.namespace.keys())
        self.assertIn("struct_MY_ROOT_UNION_3_HeaderX64", self.namespace.keys())
        self.assertIn("struct_MY_ROOT_UNION_3_0_0", self.namespace.keys())
        self.assertIn("struct_MY_ROOT_UNION_1_0", self.namespace.keys())
        self.assertEqual(ctypes.sizeof(self.namespace.union_MY_ROOT_UNION), 16)
        self.assertSizes("union_MY_ROOT_UNION")

    @unittest.skip('find a good test for docstring')
    def test_docstring(self):
        import os
        from ctypes import CDLL
        from ctypes.util import find_library
        if os.name == "nt":
            libc = CDLL("msvcrt")
        else:
            libc = CDLL(find_library("c"))
        self.convert("""
        #include <malloc.h>
        """,
                     #               generate_docstrings=True,
                     #               searched_dlls=[libc]
                     )
        prototype = "void * malloc(size_t".replace(" ", "")
        docstring = self.namespace.malloc.__doc__.replace(" ", "")
        self.assertEqual(docstring[:len(prototype)], prototype)
        self.failUnless("malloc.h" in self.namespace.malloc.__doc__)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
