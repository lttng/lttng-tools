#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Validate buffer_usage triggers in the kernel domain.
"""

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
            "function": tests.test_notification_channel_subscription_twice,
            "kwargs": {
                "domain": lttngtest.lttngctl.TracingDomain.Kernel,
                "condition_type": lttngtest.lttngctl.ConditionType.BufferUsageLow,
            },
        },
        {
            "function": tests.test_notification_channel_subscription_twice,
            "kwargs": {
                "domain": lttngtest.lttngctl.TracingDomain.Kernel,
                "condition_type": lttngtest.lttngctl.ConditionType.BufferUsageHigh,
            },
        },
        {
            "function": tests.test_triggers_buffer_usage_condition,
            "kwargs": {
                "domain": lttngtest.lttngctl.TracingDomain.Kernel,
                "condition_type": lttngtest.lttngctl.ConditionType.BufferUsageLow,
            },
        },
        {
            "function": tests.test_triggers_buffer_usage_condition,
            "kwargs": {
                "domain": lttngtest.lttngctl.TracingDomain.Kernel,
                "condition_type": lttngtest.lttngctl.ConditionType.BufferUsageHigh,
            },
        },
        {
            "function": tests.test_buffer_usage_notification_channel,
        },
    ]

    tap = lttngtest.TapGenerator(len(tests))
    if not lttngtest._Environment.run_kernel_tests():
        tap.skip_all_remaining("Kernel tests not enabled")
        sys.exit(0)

    for test in tests:
        with lttngtest.test_environment(
            with_sessiond=True,
            log=tap.diagnostic,
            enable_kernel_domain=True,
        ) as test_env:
            kwargs = test["kwargs"] if "kwargs" in test else dict()
            test["function"](tap, test_env, **kwargs)

    sys.exit(0 if tap.is_successful else 1)
