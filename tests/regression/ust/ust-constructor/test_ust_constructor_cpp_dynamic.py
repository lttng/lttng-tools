#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Test instrumentation coverage of C++ constructors and destructors by LTTng-UST
tracepoints with a dynamic object.

This test successively sets up a session, traces a test application, and then
reads the resulting trace to determine if all the expected events are present.
"""

import copy
import pathlib
import os
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest
import ust_constructor_common as ust

test = {
    "description": "Test user space constructor/destructor instrumentation coverage (C++ w/ dynamic object",
    "application": "tests/utils/testapp/gen-ust-events-constructor/gen-ust-events-constructor-so",
    "expected_events": copy.deepcopy(
        ust.expected_events_common
        + ust.expected_events_common_cpp
        + ust.expected_events_tp_so
        + ust.expected_events_tp_so_cpp
    ),
    # This application is not be built when `NO_SHARED` is set in the
    # configuration options.
    "skip_if_application_not_present": True,
}

tap = lttngtest.TapGenerator(7 + len(test["expected_events"]))
with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
    try:
        test["application"] = os.path.join(
            str(test_env._project_root), test["application"]
        )
        outputlocation = ust.capture_trace(
            tap, test_env, test["application"], test["description"]
        )
    except FileNotFoundError as fne:
        tap.diagnostic(fne)
        if test["skip_if_application_not_present"]:
            tap.skip(
                "Test application '{}' not found".format(test["application"]),
                tap.remaining_test_cases,
            )
            sys.exit(0)
    # Warning: validate_trace mutates test['expected_events']
    ust.validate_trace(outputlocation.path, tap, test["expected_events"])


sys.exit(0 if tap.is_successful else 1)
