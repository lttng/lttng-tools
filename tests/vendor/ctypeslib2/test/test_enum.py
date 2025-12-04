import unittest
import ctypes

from test.util import ClangTest


class EnumTest(ClangTest):

    """Test if Enum are correctly generated.
    """

    def test_enum(self):
        """
        Test simple values
        """
        self.gen('test/data/test-enum.c')
        # print(self.text_output)
        self.assertEqual(ctypes.sizeof(self.namespace.myEnum), 4)
        self.assertEqual(self.namespace.ZERO, 0)
        self.assertEqual(self.namespace.ONE, 1)
        self.assertEqual(self.namespace.FOUR, 4)

    def test_enum_nameless(self):
        """
        Test nameless and typedef
        """
        self.gen('test/data/test-enum.c')
        self.assertEqual(self.namespace.NAMELESS_ENUM_ONE, 0)
        self.assertEqual(self.namespace.NAMELESS_ENUM_TWO, 1)
        self.assertEqual(self.namespace.NAMELESS_ENUM_THREE, 2)
        self.assertEqual(self.namespace.TD_NAMELESS_ENUM_A, 0)
        self.assertEqual(self.namespace.TD_NAMELESS_ENUM_B, 1)
        self.assertEqual(self.namespace.TD_NAMELESS_ENUM_C, 2)
        self.assertEqual(ctypes.sizeof(self.namespace.nameless_enum_type), 4)

    def test_enum_short_option_uint8(self):
        """
        Test the enum size when compiler flag '-fshort-enums' is used.
        Test the signedness of the enum, based on the sign of the values it contains.
        """
        flags = ['-fshort-enums']
        self.convert(
            '''
        enum myEnum {
            MIN = 0,   /* UINT8_MIN */
            MAX = 0xFF /* UINT8_MAX */
        };
        ''', flags)

        self.assertEqual(ctypes.sizeof(self.namespace.myEnum), 1)
        self.assertEqual(self.namespace.myEnum, ctypes.c_uint8)
        self.assertEqual(self.namespace.MIN, 0)
        self.assertEqual(self.namespace.MAX, 0xFF)

    def test_enum_short_option_uint16(self):
        """
        Test the enum size when compiler flag '-fshort-enums' is used.
        Test the signedness of the enum, based on the sign of the values it contains.
        """
        flags = ['-fshort-enums']
        self.convert(
            '''
        enum myEnum {
            MIN = 0,      /* UINT16_MIN */
            MAX = 0xFFFF  /* UINT16_MAX */
        };
        ''', flags)

        self.assertEqual(ctypes.sizeof(self.namespace.myEnum), 2)
        self.assertEqual(self.namespace.myEnum, ctypes.c_uint16)
        self.assertEqual(self.namespace.MIN, 0)
        self.assertEqual(self.namespace.MAX, 0xFFFF)

    def test_enum_short_option_uint32(self):
        """
        Test the enum size when compiler flag '-fshort-enums' is used.
        Test the signedness of the enum, based on the sign of the values it contains.
        """
        flags = ['-fshort-enums']
        self.convert(
            '''
        enum myEnum {
            MIN = 0,          /* UINT32_MIN */
            MAX = 0xFFFFFFFF  /* UINT32_MAX */
        };
        ''', flags)

        self.assertEqual(ctypes.sizeof(self.namespace.myEnum), 4)
        self.assertEqual(self.namespace.myEnum, ctypes.c_uint32)
        self.assertEqual(self.namespace.MIN, 0)
        self.assertEqual(self.namespace.MAX, 0xFFFFFFFF)

    def test_enum_short_option_uint64(self):
        """
        Test the enum size when compiler flag '-fshort-enums' is used.
        Test the signedness of the enum, based on the sign of the values it contains.
        """
        flags = ['-fshort-enums']
        self.convert(
            '''
        enum myEnum {
            MIN = 0,                  /* UINT64_MIN */
            MAX = 0xFFFFFFFFFFFFFFFF  /* UINT64_MAX*/
        };
        ''', flags)

        self.assertEqual(ctypes.sizeof(self.namespace.myEnum), 8)
        self.assertEqual(self.namespace.myEnum, ctypes.c_uint64)
        self.assertEqual(self.namespace.MIN, 0)
        self.assertEqual(self.namespace.MAX, 0xFFFFFFFFFFFFFFFF)

    def test_enum_short_option_int8(self):
        """
        Test the enum size when compiler flag '-fshort-enums' is used.
        Test the signedness of the enum, based on the sign of the values it contains.
        """
        flags = ['-fshort-enums']
        self.convert(
            '''
        enum myEnum {
            MIN = (-0x7F - 1), /* INT8_MIN */
            MAX =   0x7F       /* INT8_MAX */
        };
        ''', flags)

        self.assertEqual(ctypes.sizeof(self.namespace.myEnum), 1)
        self.assertEqual(self.namespace.myEnum, ctypes.c_int8)
        self.assertEqual(self.namespace.MIN, (-0x7F - 1))
        self.assertEqual(self.namespace.MAX,   0x7F)

    def test_enum_short_option_int16(self):
        """
        Test the enum size when compiler flag '-fshort-enums' is used.
        Test the signedness of the enum, based on the sign of the values it contains.
        """
        flags = ['-fshort-enums']
        self.convert(
            '''
        enum myEnum {
            MIN = (-0x7FFF - 1), /* INT16_MIN */
            MAX =   0x7FFF       /* INT16_MAX*/
        };
        ''', flags)

        self.assertEqual(ctypes.sizeof(self.namespace.myEnum), 2)
        self.assertEqual(self.namespace.myEnum, ctypes.c_int16)
        self.assertEqual(self.namespace.MIN, (-0x7FFF - 1))
        self.assertEqual(self.namespace.MAX,   0x7FFF)

    def test_enum_short_option_int32(self):
        """
        Test the enum size when compiler flag '-fshort-enums' is used.
        Test the signedness of the enum, based on the sign of the values it contains.
        """
        flags = ['-fshort-enums']
        self.convert(
            '''
        enum myEnum {
            MIN = (-0x7FFFFFFF - 1), /* INT32_MIN */
            MAX =   0x7FFFFFFF       /* INT32_MAX*/
        };
        ''', flags)

        self.assertEqual(ctypes.sizeof(self.namespace.myEnum), 4)
        self.assertEqual(self.namespace.myEnum, ctypes.c_int32)
        self.assertEqual(self.namespace.MIN, (-0x7FFFFFFF - 1))
        self.assertEqual(self.namespace.MAX,   0x7FFFFFFF)

    def test_enum_short_option_int64(self):
        """
        Test the enum size when compiler flag '-fshort-enums' is used.
        Test the signedness of the enum, based on the sign of the values it contains.
        """
        flags = ['-fshort-enums']
        self.convert(
            '''
        enum myEnum {
            MIN =(-0x7FFFFFFFFFFFFFFF - 1), /* INT64_MIN */
            MAX =  0x7FFFFFFFFFFFFFFF       /* INT64_MAX*/
        };
        ''', flags)

        self.assertEqual(ctypes.sizeof(self.namespace.myEnum), 8)
        self.assertEqual(self.namespace.myEnum, ctypes.c_int64)
        self.assertEqual(self.namespace.MIN, (-0x7FFFFFFFFFFFFFFF - 1))
        self.assertEqual(self.namespace.MAX,   0x7FFFFFFFFFFFFFFF)

    def test_enum_default_size_unsigned(self):
        """
        Test the enum size when compiler flag '-fshort-enums' is NOT used.
        Test the signedness of the enum, based on the sign of the values it contains.
        """
        self.convert(
            '''
        enum myEnum {
            MIN = 0,
            MAX =  0xFFFFFFFF  /* UINT32_MAX */
        };
        ''')

        self.assertEqual(ctypes.sizeof(self.namespace.myEnum), 4)
        self.assertEqual(self.namespace.myEnum, ctypes.c_uint)
        self.assertEqual(self.namespace.MIN, 0)
        self.assertEqual(self.namespace.MAX, 0xFFFFFFFF)
        self.assertTrue(self.namespace.MAX > 0)

    def test_enum_default_size_signed(self):
        """
        Test the enum size when compiler flag '-fshort-enums' is NOT used.
        Test the signedness of the enum, based on the sign of the values it contains.
        """
        self.convert(
            '''
        enum myEnum {
            MIN = (-0x7FFFFFFF - 1), /* INT32_MIN */
            MAX =   0x7FFFFFFF       /* INT32_MAX*/
        };
        ''')

        self.assertEqual(ctypes.sizeof(self.namespace.myEnum), 4)
        self.assertEqual(self.namespace.myEnum, ctypes.c_int)
        self.assertEqual(self.namespace.MIN, (-0x7FFFFFFF - 1))
        self.assertEqual(self.namespace.MAX,   0x7FFFFFFF)

    def test_enum_unsigned_signedness(self):
        """
        Test enum signedness, based on the size and sign of the values it contains.
        Test with/without setting compiler flag '-fshort-enums'.
        Test for unsigned enum (contain only positive or null values).
        """
        flags = [None, ['-fshort-enums']]
        enum_sizes = [1, 2, 4, 8]
        enum_types = [ctypes.c_uint8, ctypes.c_uint16, ctypes.c_uint32, ctypes.c_uint64]
        enum_values = [0xFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF]

        for flag in flags:
            for (enum_size, enum_type, enum_value) in zip(enum_sizes, enum_types, enum_values):
                with self.subTest(flag=flag, enum_size=enum_size, enum_value=enum_value):

                    # Declare an enum, holding one entry of value arbitrary set to enum_value//2.
                    self.convert(f'enum myEnum {{ FOO = {enum_value//2:#x}U}};', flag)

                    if flag is None:
                        # Without compiler flag '-fshort-enums'
                        self.assertEqual(ctypes.sizeof(self.namespace.myEnum), max(4, enum_size))
                        self.assertEqual(self.namespace.myEnum, ctypes.c_uint32 if enum_size <= 4 else enum_type)
                    else:
                        # With compiler flag '-fshort-enums'
                        self.assertEqual(ctypes.sizeof(self.namespace.myEnum), enum_size)
                        self.assertEqual(self.namespace.myEnum, enum_type)

                    self.assertEqual(self.namespace.FOO, enum_value//2, msg=
                                     'Test value used to define the enum size (arbitrary set to enum_value//2).')

                    my_enum = self.namespace.myEnum()
                    # Set a value with the most significant bit set (positive unsigned integer).
                    my_enum.value = enum_value

                    self.assertTrue(my_enum.value > 0, msg=
                                    'We expect that the enum is interpreted as an positive unsigned integer.')

    def test_enum_signed_signedness(self):
        """
        Test enum signedness, based on the size and sign of the values it contains.
        Test with/without setting compiler flag '-fshort-enums'.
        Test for signed enum (contain at least one negative value)
        """
        flags = [None, ['-fshort-enums']]
        enum_sizes = [1, 2, 4, 8]
        enum_types = [ctypes.c_int8, ctypes.c_int16, ctypes.c_int32, ctypes.c_int64]
        enum_values = [0x7F, 0x7FFF, 0x7FFFFFFF, 0x7FFFFFFFFFFFFFFF]

        for flag in flags:
            for (enum_size, enum_type, enum_value) in zip(enum_sizes, enum_types, enum_values):
                with self.subTest(flag=flag, enum_size=enum_size, enum_value=enum_value):

                    # Declare an enum, holding one entry of value arbitrary set to -enum_value//2.
                    self.convert(f'enum myEnum {{ FOO = {-enum_value//2:#x}}};', flag)

                    if flag is None:
                        # Without compiler flag '-fshort-enums'
                        self.assertEqual(ctypes.sizeof(self.namespace.myEnum), max(4, enum_size))
                        self.assertEqual(self.namespace.myEnum, ctypes.c_int32 if enum_size <= 4 else enum_type)
                    else:
                        # With compiler flag '-fshort-enums'
                        self.assertEqual(ctypes.sizeof(self.namespace.myEnum), enum_size)
                        self.assertEqual(self.namespace.myEnum, enum_type)

                    self.assertEqual(self.namespace.FOO, -enum_value//2, msg=
                                     'Test value used to define the enum size (arbitrary set to -enum_value//2).')

                    my_enum = self.namespace.myEnum()
                    # Set a value with the most significant bit cleared (positive signed integer).
                    my_enum.value = enum_value

                    self.assertTrue(my_enum.value > 0, msg=
                                    'We expect that the enum is interpreted as an positive unsigned integer.')

                    # Set a value with the most significant cleared (negative signed integer).
                    my_enum.value = (-enum_value - 1)

                    self.assertTrue(my_enum.value < 0, msg=
                                    'We expect that the enum is interpreted as an negative unsigned integer.')

    def test_enum_struct_ordering(self):
        self.convert("""
typedef enum {
        ENUM
} E;

typedef struct S {
        E e;
} SS;""")
        # print(self.text_output)
        self.assertIn("struct_S", self.namespace)
        self.assertIn("SS", self.namespace)
        self.assertIn("E", self.namespace)


if __name__ == "__main__":
    # logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    # logging.getLogger('codegen').setLevel(logging.INFO)
    unittest.main()
