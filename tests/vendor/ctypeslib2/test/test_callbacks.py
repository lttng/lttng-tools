import unittest
import ctypes
import logging

from test.util import ClangTest


class Callback(ClangTest):

    """
    Test Python and C callbacks (C from python and python from C
    """

    def _foo_cb(self, foo_arg):
        return foo_arg * 2

    def _bar_cb(self, bar_arg):
        return bar_arg * 3

    def test_callbacks(self):
        # should be run on the same arch, so we can skip flags
        self.gen('test/data/test-callbacks.c', dlls=['test/data/test-callbacks.so'])

        # call C from python
        self.assertEqual(self.namespace['twice'](2), 4)
        self.assertEqual(self.namespace['ptwice'](2), 4)
        self.assertEqual(self.namespace['get_func_ptr']()(2), 4)

        # call python from C
        self.assertEqual(
            self.namespace['call_func'](
                self.namespace['func_type'](self._foo_cb),
                5
            ),
            10
        )
        cbs = self.namespace['struct_cbs'].bind({
            'foo': self._foo_cb,
            'bar': self._bar_cb,
        })
        self.assertEqual(
            self.namespace['call_cbs'](ctypes.pointer(cbs), 5, 7),
            31
        )



if __name__ == "__main__":
    # logging.basicConfig(level=logging.INFO)
    unittest.main(verbosity=2)
