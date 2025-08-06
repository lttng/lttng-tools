#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Validate that the python source files (*.py) and those with python3
in the file shebang pass black formatting.
"""

import logging
import os
import pathlib
import re
import shutil
import subprocess
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[1] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest


def list_files_with_python_shebang(path):
    matches = list()
    shebang_match = re.compile("^#!.*python3")
    for child in path.iterdir():
        if child.is_file():
            try:
                with open(str(child), "rt", encoding="utf-8") as f:
                    line = f.readline()
                    if shebang_match.match(line):
                        matches.append(child)
            except UnicodeDecodeError:
                continue

        if child.is_dir() and not child.is_symlink():
            matches.extend(list_files_with_python_shebang(child))

    return set(matches)


def list_files_ending_with_dotpy(path):
    return set(path.glob("**/*.py"))


def is_black_usable(root):
    process = subprocess.run(
        ["black", "--check", "--code", ""],
        cwd=str(root),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return process.returncode == 0, process.stdout.decode("utf-8").strip()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format=lttngtest.utils.get_logging_format())

    # LTTNG_TEST_ABS_TOP_SRCDIR is set by the test driver. Otherwise, fallback to
    # assuming the test is running from the source tree (not an out of tree build).
    root = pathlib.Path(
        os.environ.get(
            "LTTNG_TEST_ABS_TOP_SRCDIR", pathlib.Path(__file__).absolute().parents[2]
        )
    )

    # This is done since "black ./" doesn't match certain files without the ".py" suffix
    files = list_files_ending_with_dotpy(root)
    files = files.union(list_files_with_python_shebang(root))

    # Filter-out hidden directories
    files = set(
        f
        for f in files
        if not any(part.startswith(".") for part in f.relative_to(root).parts)
    )

    tap = lttngtest.TapGenerator(1)
    if not shutil.which("black"):
        tap.skip_all_remaining("black is not available")
        sys.exit(0)

    usable, reason = is_black_usable(root)
    if not usable:
        tap.skip_all_remaining("black is not usable: {}".format(reason))
        sys.exit(0)

    process = subprocess.Popen(["black", "--check"] + list(files), cwd=str(root))
    tap.test(process.wait() == 0, "black check passed")
    sys.exit(0 if tap.is_successful else 1)
