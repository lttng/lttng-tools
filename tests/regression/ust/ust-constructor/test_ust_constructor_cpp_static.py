#!/usr/bin/env python3
#
# Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# Copyright (C) 2023 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only


"""
Test instrumentation coverage of C++ constructors and destructors by LTTng-UST
tracepoints with a static archive.

This test successively sets up a session, traces a test application, and then
reads the resulting trace to determine if all the expected events are present.
"""

import copy
import pathlib
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest
import ust_constructor_common as ust

test = {
    "description": "Test user space constructor/destructor instrumentation coverage (C++ w/ static archive)",
    "application": "gen-ust-events-constructor/gen-ust-events-constructor-a",
    "expected_events": copy.deepcopy(
        ust.expected_events_common
        + ust.expected_events_common_cpp
        + ust.expected_events_tp_a
        + ust.expected_events_tp_a_cpp
    ),
    "skip_if_application_not_present": False,
}

tap = lttngtest.TapGenerator(7 + len(test["expected_events"]))
with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
    try:
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
