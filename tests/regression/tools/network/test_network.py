#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Kienan Stewart <kstewart@efficios.com>
#

import logging
import pathlib
import sys

# Import in-tree test utils
# Modify this depending on where the test file is in the tree
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest

import tests

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format=lttngtest.utils.get_logging_format())
    tests = [
        # S-2677
        {
            "function": tests.test_session_creation_with_relayd_interruption,
            "kwargs": dict(),
        },
        # S-2677 no channels have a complete set
        {
            "function": tests.test_session_creation_with_relayd_interruption,
            "kwargs": {
                "channel_success_count": 0,
            },
        },
    ]

    tap = lttngtest.TapGenerator(len(tests))
    for test in tests:
        try:
            test_function = test["function"]
            kwargs = test["kwargs"] if "kwargs" in test else dict()
            with lttngtest.test_environment(
                log=tap.diagnostic, with_sessiond=True
            ) as test_env:
                logging.info(
                    "Starting test: {} with args: {}".format(
                        test_function.__name__, kwargs
                    )
                )
                test_function(tap, test_env, **kwargs)
        except Exception as e:
            logging.exception("Unhandled exception")
            tap.fail("Unhandled exception: {}".format(e))
