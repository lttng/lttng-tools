#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Execute vermin on the tests/ directory
"""

import logging
import pathlib
import sys
import shutil
import subprocess

# Import in-tree test utils
# Modify this depending on where the test file is in the tree
test_utils_import_path = pathlib.Path(__file__).absolute().parents[1] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format=lttngtest.utils.get_logging_format())
    project_root = pathlib.Path(__file__).absolute().parents[2]
    config_path = project_root / "pyproject.toml"
    directories = [
        'tests/'
    ]
    tap = lttngtest.TapGenerator(1)
    if shutil.which('vermin') is None:
        tap.skip("vermin not found in path")
        sys.exit(0)

    args = ['vermin', '-c', str(config_path)] + directories
    p = subprocess.Popen(args, cwd=str(project_root))
    p.wait()
    tap.test(p.returncode == 0, "Vermin exited without error")
    sys.exit(0 if tap.is_successful else 1)
