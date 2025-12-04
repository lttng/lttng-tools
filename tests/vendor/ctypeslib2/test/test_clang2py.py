import os.path
import sys
import tempfile
import unittest

from test.util import ClangTest, clang2py, run
import ctypeslib


class InputOutput(ClangTest):

    def test_stdout_default(self):
        """run clang2py test/data/test-includes.h"""
        p, output, stderr = clang2py(['test/data/test-includes.h'])
        self.assertEqual(0, p.returncode)
        self.assertIn("WORD_SIZE is:", output)

    def test_stdout_with_minus_sign(self):
        """run clang2py test/data/test-includes.h -o -"""
        p, output, stderr = clang2py(['test/data/test-includes.h', '-o', '-'])
        self.assertEqual(0, p.returncode)
        self.assertIn("WORD_SIZE is:", output)

    def test_stdout_with_filename(self):
        """run clang2py test/data/test-includes.h -o filename"""
        with tempfile.NamedTemporaryFile("w", prefix='output', suffix='.c') as fout:
            fout.close()
            p, output, stderr = clang2py(['test/data/test-includes.h', '-o', fout.name])
            self.assertEqual(0, p.returncode)
            self.assertNotIn("WORD_SIZE is:", output)
            with open(fout.name, 'r') as fin:
                fileoutput = fin.read()
            self.assertIn("WORD_SIZE is:", fileoutput)
            self.assertTrue(os.path.exists(fout.name))

    def test_stdin_succeed(self):
        """Support of stdin is done """
        # run cat  test/data/test-includes.h | clang2py -
        p, output, stderr = clang2py(['-'])
        self.assertEqual(0, p.returncode)
        self.assertIn("__all__", output)

    def test_no_files(self):
        """run cat  test/data/test-includes.h | clang2py"""
        p, output, stderr = clang2py(['-o', '/dev/null'])
        self.assertEqual(p.returncode, 2)
        if sys.version_info[0] < 3:
            self.assertIn("error: too few arguments", stderr)  # py2
        else:
            self.assertIn("error: the following arguments are required", stderr)

    def test_multiple_source_files(self):
        """run clang2py -i test/data/test-basic-types.c test/data/test-bitfield.c"""
        p, output, stderr = run(['clang2py', '-i', 'test/data/test-basic-types.c', 'test/data/test-bitfield.c'])
        self.assertEqual(0, p.returncode)
        self.assertIn("WORD_SIZE is:", output)
        self.assertIn("_long = ", output)
        self.assertIn("my__quad_t ", output)
        self.assertIn("class struct_bytes4(", output)

    def test_error_translationunit(self):
        """run clang2py with error in source files"""
        p, output, stderr = run(['clang2py', 'test/data/test-error2.c'])
        self.assertEqual(1, p.returncode)
        self.assertIn("unknown type name 'SS' (test/data/test-error2.c:3:1) during processing test/data/test-error2.c", stderr)

    def test_error_translationunit_include(self):
        """run clang2py with error in included source files"""
        p, output, stderr = run(['clang2py', '-i', 'test/data/test-error1.c'])
        self.assertEqual(1, p.returncode)
        self.assertIn("unknown type name 'axasxas' (test/data/test-error1.h:5:1) during processing test/data/test-error1.c", stderr)



class ArgumentInclude(ClangTest):

    def test_include_with(self):
        """run clang2py -i test/data/test-includes.h"""
        p, output, stderr = clang2py(['-i', 'test/data/test-includes.h'])
        # print(output)
        # print(stderr)
        self.assertEqual(0, p.returncode)
        # struct_name are defined in another include file
        self.assertIn("struct_Name", output)
        self.assertIn("struct_Name2", output)
        self.assertIn("struct_Name3", output)

    def test_include_without(self):
        """run clang2py test/data/test-includes.h"""
        p, output, stderr = clang2py(['test/data/test-includes.h'])
        self.assertEqual(0, p.returncode)
        # struct_Name is a dependency. Name2 is not.
        self.assertIn("struct_Name", output)
        self.assertIn("struct_Name3", output)
        self.assertNotIn("struct_Name2", output)


class ArgumentHelper(ClangTest):

    def test_helper(self):
        """run clang2py -h"""
        p, output, stderr = clang2py(['-h', 'test/data/test-includes.h'])
        self.assertEqual(0, p.returncode)
        self.assertIn("Cross-architecture:", output)
        self.assertIn("usage:", output)
        # self.assertIn("optional arguments", output)
        # py310
        self.assertRegex(output, r"\noption.*:")


class ArgumentTypeKind(ClangTest):

    @unittest.skip('find a good test for aliases')
    def test_alias(self):
        """run clang2py -k a test/data/test-stdint.cpp"""
        p, output, stderr = clang2py(['-k', 'a', 'test/data/test-stdint.cpp'])
        self.assertEqual(0, p.returncode)
        # TODO: nothing is outputed. Bad test.
        self.assertIn("ctypes", output)
        # TODO: find a good test

    def test_class(self):
        """run clang2py -k c test/data/test-stdint.cpp"""
        p, output, stderr = clang2py(['-k', 'c', 'test/data/test-stdint.cpp'])
        self.assertEqual(0, p.returncode)
        self.assertIn("struct_b", output)

    def test_variable(self):
        """run clang2py -k d test/data/test-strings.cpp"""
        p, output, stderr = clang2py(['-k', 'd', 'test/data/test-strings.cpp'])
        self.assertEqual(0, p.returncode)
        self.assertIn("a =", output)
        self.assertIn("b =", output)

    def test_enumeration(self):
        """run clang2py -k e test/data/test-records.c"""
        p, output, stderr = clang2py(['-k', 'e', 'test/data/test-records.c'])
        self.assertEqual(0, p.returncode)
        self.assertIn("myEnum =", output)

    @unittest.skip('find a good test for function')
    def test_function(self):
        """run clang2py -k f test/data/test-stdint.cpp"""
        p, output, stderr = clang2py(['-k', 'f', 'test/data/test-stdint.cpp'])
        self.assertEqual(0, p.returncode)
        # TODO: find a good test

    def test_macro(self):
        """run clang2py -k m test/data/test-macros.h"""
        p, output, stderr = clang2py(['-k', 'm', 'test/data/test-macros.h'])
        self.assertEqual(0, p.returncode)

    def test_structure(self):
        """run clang2py -k s test/data/test-records-complex.c"""
        p, output, stderr = clang2py(['-k', 's', 'test/data/test-records-complex.c'])
        self.assertEqual(0, p.returncode)
        self.assertIn("struct__complex6", output)
        self.assertIn("struct__complex6_0", output)
        self.assertIn("struct__complex6_1", output)

    def test_typedef(self):
        """run clang2py -k t test/data/test-basic-types.c"""
        p, output, stderr = clang2py(['-k', 't', 'test/data/test-basic-types.c'])
        self.assertEqual(0, p.returncode)
        self.assertIn("_char = ", output)
        self.assertIn("_short = ", output)
        self.assertIn("_uint = ", output)

    def test_union(self):
        """run clang2py -k u test/data/test-records-complex.c"""
        # FIXME, this test case is kinda screwy.
        # trying to generate only union, but looking at incomplete definition.
        p, output, stderr = clang2py(['-k', 'u', 'test/data/test-records-complex.c'])
        self.assertEqual(0, p.returncode)
        # only unions are generated
        self.assertNotIn("struct__complex3(", output)
        self.assertIn("union__complex3_0(", output)
        self.assertIn("struct__complex3_0_2(", output)
        self.assertIn("struct__complex3_0_0(", output)
        self.assertIn("struct__complex3_0_1(", output)
        # not in root
        self.assertNotIn("union__complex3_0_1_1(", output)


class ArgumentVersion(ClangTest):

    def test_version(self):
        """run clang2py --version"""
        p, output, stderr = clang2py(['--version'])
        self.assertEqual(0, p.returncode)
        self.assertIn(str(ctypeslib.__version__), output)
        self.assertIn("libclang", output)

    def test_version(self):
        """run clang2py -V"""
        p, output, stderr = clang2py(['-V', 'XXXXX'])
        self.assertEqual(0, p.returncode)
        if sys.version_info[0] < 3:
            self.assertIn("versions - clang2py", stderr)
        else:
            self.assertIn("versions - clang2py", output)


class ArgumentVerbose(ClangTest):

    def test_verbose(self):
        """run clang2py --verbose test/data/test-records.c"""
        p, output, stderr = clang2py(['--verbose', 'test/data/test-records.c'])
        self.assertEqual(0, p.returncode, stderr)
        self.assertNotIn("DEBUG:", stderr)
        self.assertNotIn("DEBUG:", output)
        self.assertIn("# Total symbols:", stderr)

    def test_debug(self):
        """run clang2py --verbose test/data/test-records.c"""
        p, output, stderr = clang2py(['--verbose', 'test/data/test-records.c', '--debug'])
        self.assertEqual(0, p.returncode)
        self.assertIn("DEBUG:", stderr)
        self.assertNotIn("DEBUG:", output)
        self.assertIn("# Total symbols:", stderr)


from io import StringIO
from unittest.mock import patch


class ModuleTesting(ClangTest):
    def test_version(self):
        """run clang2py -v"""
        from ctypeslib import clang2py as cli
        with patch('sys.stdout', new=StringIO()) as fake_out:
            with self.assertRaises(SystemExit):
                cli.main(['--version'])
            self.assertIn(str(ctypeslib.__version__), fake_out.getvalue())

    def test_arg_file(self):
        """run clang2py test/data/test-basic-types.c"""
        from ctypeslib import clang2py as cli
        with patch('sys.stdout', new=StringIO()) as fake_out:
            cli.main(['test/data/test-basic-types.c'])
            self.assertIn("_int = ctypes.c_int", fake_out.getvalue())

    def test_arg_input_stdin(self):
        """run echo | clang2py - """
        from ctypeslib import clang2py as cli
        with patch('sys.stdin', StringIO('int i = 0;')) as stdin, patch('sys.stdout', new=StringIO()) as fake_out:
            cli.main(['-'])
            self.assertIn("__all__ =", fake_out.getvalue())
            self.assertIn("# TARGET arch is: []", fake_out.getvalue())

    @unittest.skip('2023-03 temporary CI bypass')
    def test_arg_debug(self):
        """run clang2py --debug test/data/test-basic-types.c"""
        # FIXME maybe the CI doesn't like the stderr patching.
        from ctypeslib import clang2py as cli
        with patch('sys.stdout', new=StringIO()) as fake_out, patch('sys.stderr', new=StringIO()) as fake_err:
            cli.main(['--debug', 'test/data/test-basic-types.c'])
            self.assertIn("_int = ctypes.c_int", fake_out.getvalue())
            self.assertIn("DEBUG:clangparser:ARCH sizes:", fake_err.getvalue())
            self.assertNotIn("ERROR", fake_err.getvalue())

    def test_arg_target(self):
        """run clang2py --target x86_64-Linux test/data/test-basic-types.c """
        from ctypeslib import clang2py as cli
        with patch('sys.stdout', new=StringIO()) as fake_out:
            cli.main(['--target', 'x86_64-Linux', 'test/data/test-basic-types.c'])
            self.assertIn("# TARGET arch is: ['-target', 'x86_64-Linux']", fake_out.getvalue())
            self.assertIn("_int = ctypes.c_int", fake_out.getvalue())
            self.assertIn("_long = ctypes.c_int64", fake_out.getvalue())

            cli.main(['--target', 'i586-Linux', 'test/data/test-basic-types.c'])
            self.assertIn("# TARGET arch is: ['-target', 'i586-Linux']", fake_out.getvalue())
            self.assertIn("_int = ctypes.c_int", fake_out.getvalue())
            self.assertIn("_long = ctypes.c_int32", fake_out.getvalue())

    # TODO
    @unittest.skip
    def test_arg_clang_args(self):
        """run clang2py test/data/test-basic-types.c --clang-args="-DDEBUG=2" """
        from ctypeslib import clang2py as cli
        with patch('sys.stdin', StringIO('int i = DEBUG;')) as stdin, patch('sys.stdout', new=StringIO()) as fake_out:
            cli.main(['', '--clang-args="-DDEBUG=2"', '-'])
            self.assertIn("# TARGET arch is: []", fake_out.getvalue())
            self.assertIn("i = 2", fake_out.getvalue())


class OrderingTest(ClangTest):

    def test_brute(self):
        """run 20 times clang2py to identify ordering differences"""
        outputs = []
        for i in range(20):
            p, output, stderr = clang2py(['./test/data/test-include-order2.h'])
            outputs.append(output)
            var = output.index("f = struct_foo_s")
            decl = output.index("class struct_foo_s(Structure)")
            self.assertGreater(var, decl, "Generated incorrect ordering")

        set_outputs = set(outputs)
        self.assertEqual(len(set_outputs), 1)

    def test_enum_struct(self):
        """run clang2py on a ordering issue involving enum and struct"""
        p, output, stderr = clang2py(['./test/data/test-enum.c'])
        # decl = output.index("('e', c__EA_E),")  # Fixed in clang 19
        # enum = output.index("c__EA_E = ctypes.c_uint32")
        decl = output.index("('e', E),")  # Fixed in clang 19
        enum = output.index("E = ctypes.c_uint32")
        self.assertGreater(decl, enum, "Generated incorrect ordering")


class TestLocation(ClangTest):

    def test_location(self):
        """check the location comment"""
        p, output, stderr = clang2py(['--show-definition-location', 'test/data/test-includes.h'])
        self.assertEqual(0, p.returncode)
        self.assertIn("# test/data/test-includes.h:3\nclass struct_Name3(", output)
        self.assertIn("# test/data/test-records.c:3\nclass struct_Name(", output)


class TestIncludeRegex(ClangTest):

    def test_re(self):
        """check that the -r flag works"""
        p, output, stderr = clang2py(['-k', 'emstu', '-r', 'API_[NV].*', 'test/data/test-macros.h'])
        self.assertEqual(0, p.returncode)
        self.assertIn("API_NAME", output)
        self.assertIn("API_VER_MAJOR", output)
        self.assertIn("API_VER_MINOR", output)
        self.assertIn("API_VER_PATCH", output)
        self.assertNotIn("ANOTHER", output)
        self.assertNotIn("APREPOST", output)


if __name__ == "__main__":
    unittest.main()
