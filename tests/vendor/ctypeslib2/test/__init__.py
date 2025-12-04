#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Unit test module.

Unit Tests in this module will often compare size and offset between the
libclang version and the ctypeslib-processed python version the types.

Because the objective of this framework is not to verify if libclang or the
python bindings work, there will be no testing of specific results of libclang.
E.g., ig libclang says a long is 4 bytes, we trust libclang.

"""

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2013 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

import sys
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest


def alltests():
    ret = unittest.TestLoader().discover('test/')
    return ret

if __name__ == '__main__':
    unittest.main(verbosity=0)
