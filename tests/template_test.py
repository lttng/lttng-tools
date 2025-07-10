#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: XXXX Name <email@example.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Describe what the test is validating.
"""

import pathlib
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest
import bt2

if __name__ == "__main__":
    tap = lttngtest.TapGenerator(1)
    with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
        pass
    sys.exit(0 if tap.is_successful else 1)
