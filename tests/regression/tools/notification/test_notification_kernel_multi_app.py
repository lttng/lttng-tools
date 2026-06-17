#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Validate kernel buffer usage trigger events with multiple subscribed notification clients
"""

import logging
import pathlib
import sys

# Import in-tree test utils
# Modify this depending on where the test file is in the tree
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import bt2

import tests

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format=lttngtest.utils.get_logging_format())
    tests = [
        {
            "function": tests.test_on_register_evaluation,
            "skip": (
                "test_kernel_notifier_discarded_count must be run as root"
                if not lttngtest._Environment.run_kernel_tests()
                else False
            ),
            "kwargs": {
                "domain": lttngtest.lttngctl.TracingDomain.Kernel,
            },
            "sessiond_extra_args": ["--spawn-consumers"],
        },
        {
            "function": tests.test_multi_app,
            "skip": (
                "test_kernel_notifier_discarded_count must be run as root"
                if not lttngtest._Environment.run_kernel_tests()
                else False
            ),
            "kwargs": {
                "domain": lttngtest.lttngctl.TracingDomain.Kernel,
            },
            "sessiond_extra_args": ["--spawn-consumers"],
        },
    ]

    tap = lttngtest.TapGenerator(len(tests))
    if not lttngtest.utils.gdb_exists():
        tap.missing_platform_requirement("Need gdb")
        sys.exit(0)

    for test in tests:
        sessiond_extra_args = (
            test["sessiond_extra_args"] if "sessiond_extra_args" in test else list()
        )
        skip = test["skip"] if "skip" in test else False
        if skip:
            tap.skip(skip)
            continue
        with lttngtest.test_environment(
            with_sessiond=True,
            log=tap.diagnostic,
            enable_kernel_domain=True,
            sessiond_extra_args=sessiond_extra_args,
        ) as test_env:
            with lttngtest.kernel_module("lttng-test"):
                kwargs = test["kwargs"] if "kwargs" in test else dict()
                test["function"](tap, test_env, **kwargs)

    sys.exit(0 if tap.is_successful else 1)
