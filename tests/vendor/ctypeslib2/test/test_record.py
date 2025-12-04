import ctypes
import unittest

from test.util import ClangTest

import logging

# logging.basicConfig(level=logging.DEBUG)


class RecordTest(ClangTest):

    """Test if records are correctly generated for different target archictecture.
    """
    def test_records_x32(self):
        """Test sizes for simple records on i386.
        """
        # others size tests are in test_fast_clang
        flags = ['-target', 'i386-linux']
        self.gen('test/data/test-records.c', flags)
        self.assertEqual(ctypes.sizeof(self.namespace.struct_Name), 18)
        self.assertEqual(ctypes.sizeof(self.namespace.struct_Name2), 20)
        self.assertEqual(ctypes.sizeof(self.namespace.struct_Node), 16)
        self.assertEqual(ctypes.sizeof(self.namespace.struct_Node2), 8)
        self.assertEqual(ctypes.sizeof(self.namespace.myEnum), 4)
        self.assertEqual(ctypes.sizeof(self.namespace.my__quad_t), 8)
        self.assertEqual(ctypes.sizeof(self.namespace.my_bitfield), 4)
        self.assertEqual(ctypes.sizeof(self.namespace.mystruct), 5)

    def test_records_x64(self):
        """Test sizes for simple records on x64.
        """
        # others size tests are in test_fast_clang
        flags = ['-target', 'x86_64-linux']
        self.gen('test/data/test-records.c', flags)
        self.assertEqual(ctypes.sizeof(self.namespace.struct_Name), 18)
        self.assertEqual(ctypes.sizeof(self.namespace.struct_Name2), 20)
        self.assertEqual(ctypes.sizeof(self.namespace.struct_Node), 32)
        self.assertEqual(ctypes.sizeof(self.namespace.struct_Node2), 16)
        self.assertEqual(ctypes.sizeof(self.namespace.myEnum), 4)
        self.assertEqual(ctypes.sizeof(self.namespace.my__quad_t), 16)
        self.assertEqual(ctypes.sizeof(self.namespace.my_bitfield), 8)
        self.assertEqual(ctypes.sizeof(self.namespace.mystruct), 5)

    def test_padding_x32(self):
        """Test padding for simple records on i386.
        """
        flags = ['-target', 'i386-linux']
        self.gen('test/data/test-padding.c', flags)
        self.assertEqual(self.namespace.struct_Name2.PADDING_0.offset, 2)
        self.assertEqual(self.namespace.struct_Name2.PADDING_0.size, 2)
        self.assertEqual(self.namespace.struct_Name4.PADDING_0.offset, 2)
        self.assertEqual(self.namespace.struct_Name4.PADDING_0.size, 2)
        self.assertEqual(self.namespace.struct_Name4.PADDING_1.offset, 10)
        self.assertEqual(self.namespace.struct_Name4.PADDING_1.size, 2)
        self.assertEqual(self.namespace.struct_Name4.PADDING_2.offset, 18)
        self.assertEqual(self.namespace.struct_Name4.PADDING_2.size, 2)
        self.assertEqual(self.namespace.struct_Node.PADDING_0.offset, 13)
        self.assertEqual(self.namespace.struct_Node.PADDING_0.size, 3)
        self.assertEqual(self.namespace.struct_Node2.PADDING_0.offset, 1)
        self.assertEqual(self.namespace.struct_Node2.PADDING_0.size, 3)
        self.assertEqual(self.namespace.struct_Node3.PADDING_0.offset, 1)
        self.assertEqual(self.namespace.struct_Node3.PADDING_0.size, 3)
        self.assertEqual(self.namespace.struct_Node3.PADDING_1.offset, 21)
        self.assertEqual(self.namespace.struct_Node3.PADDING_1.size, 3)
        self.assertEqual(self.namespace.struct_Node4.PADDING_0.offset, 1)
        self.assertEqual(self.namespace.struct_Node4.PADDING_0.size, 1)
        self.assertEqual(self.namespace.struct_Node5.PADDING_0.offset, 6)
        self.assertEqual(self.namespace.struct_Node5.PADDING_0.size, 2)

    def test_padding_x64(self):
        """Test padding for simple records on x64.
        """
        flags = ['-target', 'x86_64-linux']
        self.gen('test/data/test-padding.c', flags)
        self.assertEqual(self.namespace.struct_Name2.PADDING_0.offset, 2)
        self.assertEqual(self.namespace.struct_Name2.PADDING_0.size, 2)
        self.assertEqual(self.namespace.struct_Name4.PADDING_0.offset, 2)
        self.assertEqual(self.namespace.struct_Name4.PADDING_0.size, 6)
        self.assertEqual(self.namespace.struct_Name4.PADDING_1.offset, 18)
        self.assertEqual(self.namespace.struct_Name4.PADDING_1.size, 6)
        self.assertEqual(self.namespace.struct_Name4.PADDING_2.offset, 34)
        self.assertEqual(self.namespace.struct_Name4.PADDING_2.size, 6)
        self.assertEqual(self.namespace.struct_Node.PADDING_0.offset, 4)
        self.assertEqual(self.namespace.struct_Node.PADDING_0.size, 4)
        self.assertEqual(self.namespace.struct_Node.PADDING_1.offset, 25)
        self.assertEqual(self.namespace.struct_Node.PADDING_1.size, 7)
        self.assertEqual(self.namespace.struct_Node2.PADDING_0.offset, 1)
        self.assertEqual(self.namespace.struct_Node2.PADDING_0.size, 7)
        self.assertEqual(self.namespace.struct_Node3.PADDING_0.offset, 1)
        self.assertEqual(self.namespace.struct_Node3.PADDING_0.size, 7)
        self.assertEqual(self.namespace.struct_Node3.PADDING_1.offset, 41)
        self.assertEqual(self.namespace.struct_Node3.PADDING_1.size, 7)
        self.assertEqual(self.namespace.struct_Node4.PADDING_0.offset, 1)
        self.assertEqual(self.namespace.struct_Node4.PADDING_0.size, 1)
        self.assertEqual(self.namespace.struct_Node4.PADDING_1.offset, 4)
        self.assertEqual(self.namespace.struct_Node4.PADDING_1.size, 4)
        self.assertEqual(self.namespace.struct_Node5.PADDING_0.offset, 6)
        self.assertEqual(self.namespace.struct_Node5.PADDING_0.size, 2)

    def test_record_in_record(self):
        self.convert('''
typedef struct _complex {
    struct {
        int a;
    };
} complex, *pcomplex;
        ''', ['-target', 'x86_64-linux'])
        self.assertEqual(ctypes.sizeof(self.namespace.complex), 4)

    def test_record_in_record_2(self):
        self.convert('''
typedef struct _complex {
    struct {
        int a;
    };
    struct {
        long b;
    };
} complex, *pcomplex;
        ''', ['-target', 'x86_64-linux'])
        self.assertEqual(ctypes.sizeof(self.namespace.complex), 16)

    def test_record_in_record_3_x32(self):
        self.convert('''
typedef struct _complex {
    union {
        struct {
            int a;
        };
        struct {
            long b;
            union {
                int c;
                struct {
                    long long d;
                    char e;
                };
            };
        };
        struct {
            long f;
        };
        int g;
    };
} complex, *pcomplex;
        ''', ['-target', 'i386-linux'])
        self.assertEqual(ctypes.sizeof(self.namespace.complex), 16)

    def test_record_in_record_3(self):
        self.convert('''
typedef struct _complex {
    union {
        struct {
            int a;
        };
        struct {
            long b;
            union {
                int c;
                struct {
                    long long d;
                    char e;
                };
            };
        };
        struct {
            long f;
        };
        int g;
    };
} complex, *pcomplex;
        ''', ['-target', 'x86_64-linux'])
        self.assertEqual(ctypes.sizeof(self.namespace.complex), 24)

    def test_record_in_record_packed(self):
        self.convert('''
typedef struct _complex {
    struct {
        char a;
    };
    struct __attribute__((packed)) {
        char b;
    };
} complex, *pcomplex;
        ''', ['-target', 'x86_64-linux'])
        self.assertEqual(ctypes.sizeof(self.namespace.complex), 2)

    def test_forward_decl_x32(self):
        self.convert('''
typedef struct entry Entry;
struct entry {
  Entry * flink;
  Entry * blink;
};
        ''', ['-target', 'i386-linux'])
        self.assertEqual(ctypes.sizeof(self.namespace.struct_entry), 8)

    def test_forward_decl(self):
        self.convert('''
typedef struct entry Entry;
struct entry {
  Entry * flink;
  Entry * blink;
};
        ''', ['-target', 'x86_64-linux'])
        self.assertEqual(ctypes.sizeof(self.namespace.struct_entry), 16)

    def test_zero_length_array(self):
        """C99 feature called the flexible array member feature."""
        flags = ['-target', 'x86_64-linux']
        self.gen('test/data/test-zero-length-array.c', flags)
        self.assertEqual(self.namespace.struct_example_detail.first.offset, 0)
        self.assertEqual(self.namespace.struct_example_detail.last.offset, 4)
        # FIXME 201801 - Clang still returns members offset as -2 , see bug #28
        self.assertEqual(self.namespace.struct_example.argsz.offset, 0)
        self.assertEqual(self.namespace.struct_example.flags.offset, 4)
        self.assertEqual(self.namespace.struct_example.count.offset, 8)
        self.assertEqual(ctypes.sizeof(self.namespace.struct_example_detail), 8)
        self.assertEqual(ctypes.sizeof(self.namespace.struct_example), 12)

    def test_incomplete_struct(self):
        self.convert('''
struct Foo;
void do_something(struct Foo* foo);
        ''')
        self.assertTrue(hasattr(self.namespace, 'struct_Foo'))
        self.assertEqual(ctypes.sizeof(self.namespace.struct_Foo), 0)

    def test_record_ordering(self):
        """Raises _fields_ is final if incorrect"""
        self.convert('''
struct A;

struct B {
        struct A* a;
};
struct A {
        struct B b;
};        ''')
        # print(self.text_output)
        self.assertIn('struct_A', self.namespace)
        self.assertIn('struct_B', self.namespace)

    def test_record_anonymous_union(self):
        """use _anonymous_"""
        self.convert('''
struct s {
    int i;
    union {
        long l;
    };
};

// struct s _s;
 //_s.i = 0;
''')
        # print(self.text_output)
        self.assertIn("struct_s._anonymous_", self.text_output)
        self.assertIn('struct_s', self.namespace)

    def test_record_named_union(self):
        """Anonymous types with a named field"""
        self.convert('''
struct s {
    int i;
    // anonymous type with no name
    union {
        long l1;
        float f1;
    };
    // anonymous type with a name
    union {
        long l2;
        float f2;
    } u;

    union {
        long x1;
        float y1;
    };
};

// we want the first union to be an anonymous field in struct_s (s_0)
// we want u to be a field in struct_s

''')
        # print(self.text_output)
        self.assertIn('struct_s', self.namespace)
        self.assertHasFieldNamed(self.namespace.struct_s, 'i')
        # we named the unamed anonymous union. .. maybe not the best idea
        self.assertHasFieldNamed(self.namespace.struct_s, '_0')
        self.assertIn('union_s_0', self.namespace)
        # python ctypes properly merges anonymous union and exposes members
        self.assertHasFieldNamed(self.namespace.struct_s, 'f1')
        self.assertHasFieldNamed(self.namespace.struct_s, 'l1')
        # and not for unamed anonymous union
        self.assertNotHasFieldNamed(self.namespace.struct_s, 'l2')
        self.assertNotHasFieldNamed(self.namespace.struct_s, 'f2')
        # and we have a named union
        self.assertHasFieldNamed(self.namespace.struct_s, 'u')
        # Issue #117
        self.assertNotIn('union_s_1', self.namespace)
        self.assertIn('union_s_u', self.namespace)
        self.assertHasFieldNamed(self.namespace.union_s_u, 'l2')
        self.assertHasFieldNamed(self.namespace.union_s_u, 'f2')


if __name__ == "__main__":
    # logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    # logging.getLogger('codegen').setLevel(logging.INFO)
    unittest.main()
