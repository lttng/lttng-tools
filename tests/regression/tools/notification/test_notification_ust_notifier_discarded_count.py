#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Validate trigger events discards in the UST domain.
"""

import os
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
    tests = [
        {
            "function": tests.test_notifier_discarded_count,
            "kwargs": {
                "domain": lttngtest.lttngctl.TracingDomain.User,
            },
            "sessiond_extra_args": ["--spawn-consumers"],
        },
        {
            "function": tests.test_notifier_discarded_count_max_bucket,
            "sessiond_extra_args": ["--event-notifier-error-buffer-size-userspace=3"],
            "kwargs": {
                "max_bucket_size": 3,
                "domain": lttngtest.lttngctl.TracingDomain.User,
            },
        },
        {
            "function": tests.test_ust_notifier_discarded_count_multi_uid,
            "skip": (
                "test_ust_notifier_discarded_count_multi_uid must be run as root with destructive tests enabled"
                if not lttngtest._Environment.allows_destructive() or os.getuid() != 0
                else False
            ),
            "sessiond_extra_args": ["--spawn-consumers"],
        },
        {
            "function": tests.test_ust_notifier_discarded_regardless_trigger_owner,
            "skip": (
                "test_ust_notifier_discarded_regardless_trigger_owner must be run as root with destructive tests enabled"
                if not lttngtest._Environment.allows_destructive() or os.getuid() != 0
                else False
            ),
            "sessiond_extra_args": ["--spawn-consumers"],
        },
    ]

    tap = lttngtest.TapGenerator(len(tests))
    if not lttngtest.utils.gdb_exists():
        tap.missing_platform_requirements("Need gdb")
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
            sessiond_extra_args=sessiond_extra_args,
        ) as test_env:
            kwargs = test["kwargs"] if "kwargs" in test else dict()

            test["function"](tap, test_env, **kwargs)

    sys.exit(0 if tap.is_successful else 1)
