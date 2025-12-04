import tempfile
import unittest
import io

import ctypeslib
from ctypeslib.codegen import config
from ctypeslib.codegen import typedesc


class ApiTest(unittest.TestCase):
    def test_basic_use_string(self):
        py_namespace = ctypeslib.translate('''
int i = 12;
char c2[3] = {'a','b','c'};
struct example_detail {
    int first;
    int last;
};

struct example {
    int argsz;
    int flags;
    int count;
    struct example_detail details[2];
};        
        ''')
        self.assertIn("i", py_namespace)
        self.assertIn("c2", py_namespace)
        self.assertIn("struct_example_detail", py_namespace)
        self.assertIn("struct_example", py_namespace)
        self.assertEqual(py_namespace.i, 12)
        self.assertEqual(py_namespace.c2, ['a', 'b', 'c'])
        # import pprint
        # pprint.pprint(py_namespace)

    def test_basic_use_io(self):
        input_io = io.StringIO('''
int i = 12;
char c2[3] = {'a','b','c'};
struct example_detail {
    int first;
    int last;
};

struct example {
    int argsz;
    int flags;
    int count;
    struct example_detail details[2];
};        
        ''')
        py_namespace = ctypeslib.translate(input_io)
        self.assertIn("i", py_namespace)
        self.assertIn("c2", py_namespace)
        self.assertIn("struct_example_detail", py_namespace)
        self.assertIn("struct_example", py_namespace)
        self.assertEqual(py_namespace.i, 12)
        self.assertEqual(py_namespace.c2, ['a', 'b', 'c'])

    def test_basic_file_io(self):
        py_namespace = ctypeslib.translate_files('test/data/test-library.c')
        self.assertIn("a", py_namespace)
        self.assertEqual(py_namespace.a, 0)

    def test_advanced_file_io(self):
        cfg = config.CodegenConfig()
        cfg.clang_opts.append('-I/home/jal/Code/ctypeslib/test/data/')
        py_namespace = ctypeslib.translate_files('test/data/test-enum.c', cfg=cfg)
        self.assertIn("ZERO", py_namespace)
        self.assertIn("myEnum", py_namespace)
        self.assertEqual(py_namespace.ZERO, 0)

    def test_advanced_file_io_to_file(self):
        cfg = config.CodegenConfig()
        cfg.clang_opts.extend(['-I./test/data/', '-target', 'arm-gnu-linux'])
        with tempfile.NamedTemporaryFile(suffix=".py", mode='w+') as tmpfile:
            ctypeslib.translate_files('test/data/test-enum.c', outfile=tmpfile, cfg=cfg)
            tmpfile.seek(0)
            output = tmpfile.read()
        self.assertIn("ZERO = 0", output)
        self.assertIn("myEnum", output)
        self.assertIn("WORD_SIZE is: 4", output)


class ConfigTest(unittest.TestCase):
    def setUp(self) -> None:
        self.input_io = io.StringIO('''
        struct example_1 {
            int first;
            int last;
        };

        union example_2 {
            int a;
            float f;
        };''')

    def test_no_config(self):
        py_namespace = ctypeslib.translate(self.input_io)
        self.assertIn("struct_example_1", py_namespace)
        self.assertIn("union_example_2", py_namespace)

    def test_config_default(self):
        cfg = config.CodegenConfig()
        py_namespace = ctypeslib.translate(self.input_io, cfg=cfg)
        self.assertIn("struct_example_1", py_namespace)
        self.assertIn("union_example_2", py_namespace)

    def test_filter_types(self):
        cfg = config.CodegenConfig()
        cfg._init_types("u")
        py_namespace = ctypeslib.translate(self.input_io, cfg=cfg)
        self.assertNotIn("struct_example_1", py_namespace)
        self.assertIn("union_example_2", py_namespace)


if __name__ == '__main__':
    unittest.main()
