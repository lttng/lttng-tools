#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2024 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifer: GPL-2.0-only
#

import copy
import pathlib
import sys
import os
import subprocess
from typing import Any, Callable, Type

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest
import bt2

# Determine if LTTNG_UST_ALLOCATE_COMPOUND_LITERAL_ON_HEAP is set. This will
# affect if certain events may or may not be expected when compiling with
# C++.
# @see https://github.com/lttng/lttng-ust/blob/47fa3e4ed7ab43e034dc61fc1480f919f4ee51d0/include/lttng/ust-compiler.h#L51
#
compound_literal_on_heap = False
process = subprocess.Popen(
    [
        os.path.join(
            str(test_utils_import_path),
            "testapp",
            "gen-ust-events-constructor",
            "uses_heap",
        )
    ]
)
process.wait()
if process.returncode == 0:
    compound_literal_on_heap = True

expected_events_common_cpp = [
    {
        "name": "tp:constructor_cplusplus",
        "msg": "global - across units before define",
        "count": 0,
        "may_fail": compound_literal_on_heap,
    },
    {
        "name": "tp:constructor_cplusplus",
        "msg": "global - same unit before define",
        "count": 0,
        "may_fail": compound_literal_on_heap,
    },
    {
        "name": "tp:constructor_cplusplus",
        "msg": "global - same unit after define",
        "count": 0,
        "may_fail": compound_literal_on_heap,
    },
    {
        "name": "tp:constructor_cplusplus",
        "msg": "global - across units after define",
        "count": 0,
        "may_fail": compound_literal_on_heap,
    },
    {
        "name": "tp:constructor_cplusplus",
        "msg": "global - same unit before provider",
        "count": 0,
        "may_fail": compound_literal_on_heap,
    },
    {
        "name": "tp:constructor_cplusplus",
        "msg": "global - same unit after provider",
        "count": 0,
    },
    {
        "name": "tp:constructor_cplusplus",
        "msg": "global - across units after provider",
        "count": 0,
    },
    {"name": "tp:constructor_cplusplus", "msg": "main() local", "count": 0},
    {"name": "tp:destructor_cplusplus", "msg": "main() local", "count": 0},
    {
        "name": "tp:destructor_cplusplus",
        "msg": "global - across units after provider",
        "count": 0,
    },
    {
        "name": "tp:destructor_cplusplus",
        "msg": "global - same unit after provider",
        "count": 0,
    },
    {
        "name": "tp:destructor_cplusplus",
        "msg": "global - same unit before provider",
        "count": 0,
        "may_fail": compound_literal_on_heap,
    },
    {
        "name": "tp:destructor_cplusplus",
        "msg": "global - across units after define",
        "count": 0,
        "may_fail": compound_literal_on_heap,
    },
    {
        "name": "tp:destructor_cplusplus",
        "msg": "global - same unit after define",
        "count": 0,
        "may_fail": compound_literal_on_heap,
    },
    {
        "name": "tp:destructor_cplusplus",
        "msg": "global - same unit before define",
        "count": 0,
        "may_fail": compound_literal_on_heap,
    },
    {
        "name": "tp:destructor_cplusplus",
        "msg": "global - across units before define",
        "count": 0,
        "may_fail": compound_literal_on_heap,
    },
]

expected_events_common = [
    {
        "name": "tp:constructor_c_across_units_before_define",
        "msg": None,
        "count": 0,
        "may_fail": compound_literal_on_heap,
    },
    {
        "name": "tp:constructor_c_same_unit_before_define",
        "msg": None,
        "count": 0,
        "may_fail": compound_literal_on_heap,
    },
    {
        "name": "tp:constructor_c_same_unit_after_define",
        "msg": None,
        "count": 0,
        "may_fail": compound_literal_on_heap,
    },
    {
        "name": "tp:constructor_c_across_units_after_define",
        "msg": None,
        "count": 0,
        "may_fail": compound_literal_on_heap,
    },
    {
        "name": "tp:constructor_c_same_unit_before_provider",
        "msg": None,
        "count": 0,
        "may_fail": compound_literal_on_heap,
    },
    {
        "name": "tp:constructor_c_same_unit_after_provider",
        "msg": None,
        "count": 0,
        "may_fail": compound_literal_on_heap,
    },
    {"name": "tp:constructor_c_across_units_after_provider", "msg": None, "count": 0},
    {"name": "tp:main", "msg": None, "count": 0},
    {
        "name": "tp:destructor_c_across_units_after_provider",
        "msg": None,
        "count": 0,
        "may_fail": compound_literal_on_heap,
    },
    {
        "name": "tp:destructor_c_same_unit_after_provider",
        "msg": None,
        "count": 0,
        "may_fail": compound_literal_on_heap,
    },
    {
        "name": "tp:destructor_c_same_unit_before_provider",
        "msg": None,
        "count": 0,
        "may_fail": compound_literal_on_heap,
    },
    {
        "name": "tp:destructor_c_across_units_after_define",
        "msg": None,
        "count": 0,
        "may_fail": compound_literal_on_heap,
    },
    {
        "name": "tp:destructor_c_same_unit_after_define",
        "msg": None,
        "count": 0,
        "may_fail": compound_literal_on_heap,
    },
    {
        "name": "tp:destructor_c_same_unit_before_define",
        "msg": None,
        "count": 0,
        "may_fail": compound_literal_on_heap,
    },
    {
        "name": "tp:destructor_c_across_units_before_define",
        "msg": None,
        "count": 0,
        "may_fail": compound_literal_on_heap,
    },
]

expected_events_tp_so_cpp = [
    {
        "name": "tp_so:constructor_cplusplus_provider_shared_library",
        "msg": "global - shared library define and provider",
        "count": 0,
    },
    {
        "name": "tp_so:constructor_cplusplus_provider_shared_library",
        "msg": "main() local - shared library define and provider",
        "count": 0,
    },
    {
        "name": "tp_so:destructor_cplusplus_provider_shared_library",
        "msg": "main() local - shared library define and provider",
        "count": 0,
    },
    {
        "name": "tp_so:destructor_cplusplus_provider_shared_library",
        "msg": "global - shared library define and provider",
        "count": 0,
    },
]

expected_events_tp_so = [
    {"name": "tp_so_c:constructor_c_provider_shared_library", "msg": None, "count": 0},
    {"name": "tp_so_c:destructor_c_provider_shared_library", "msg": None, "count": 0},
]

expected_events_tp_a_cpp = [
    {
        "name": "tp_a:constructor_cplusplus_provider_static_archive",
        "msg": "global - static archive define and provider",
        "count": 0,
        "may_fail": compound_literal_on_heap,
    },
    {
        "name": "tp_a:constructor_cplusplus_provider_static_archive",
        "msg": "main() local - static archive define and provider",
        "count": 0,
    },
    {
        "name": "tp_a:destructor_cplusplus_provider_static_archive",
        "msg": "main() local - static archive define and provider",
        "count": 0,
    },
    {
        "name": "tp_a:destructor_cplusplus_provider_static_archive",
        "msg": "global - static archive define and provider",
        "count": 0,
        "may_fail": compound_literal_on_heap,
    },
]

expected_events_tp_a = [
    {"name": "tp_a_c:constructor_c_provider_static_archive", "msg": None, "count": 0},
    {"name": "tp_a_c:destructor_c_provider_static_archive", "msg": None, "count": 0},
]


def capture_trace(tap, test_env, application, description):
    # type: (lttngtest.TapGenerator, lttngtest._Environment) -> lttngtest.LocalSessionOutputLocation
    tap.diagnostic(description)

    session_output_location = lttngtest.LocalSessionOutputLocation(
        test_env.create_temporary_directory("trace")
    )

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

    with tap.case("Create a session") as test_case:
        session = client.create_session(output=session_output_location)
    tap.diagnostic("Created session `{session_name}`".format(session_name=session.name))

    with tap.case(
        "Add a channel to session `{session_name}`".format(session_name=session.name)
    ) as test_case:
        channel = session.add_channel(lttngtest.TracingDomain.User)
    tap.diagnostic("Created channel `{channel_name}`".format(channel_name=channel.name))

    # Enable all user space events, the default for a user tracepoint event rule.
    channel.add_recording_rule(lttngtest.UserTracepointEventRule("tp*"))

    with tap.case(
        "Start session `{session_name}`".format(session_name=session.name)
    ) as test_case:
        session.start()

    test_app = test_env.launch_test_application(application)
    with tap.case(
        "Run test app '{}'".format(application, session_name=session.name)
    ) as test_case:
        test_app.wait_for_exit()

    with tap.case(
        "Stop session `{session_name}`".format(session_name=session.name)
    ) as test_case:
        session.stop()

    with tap.case(
        "Destroy session `{session_name}`".format(session_name=session.name)
    ) as test_case:
        session.destroy()

    return session_output_location


def validate_trace(trace_location, tap, expected_events):
    # type: (pathlib.Path, lttngtest.TapGenerator)
    unknown_event_count = 0

    for msg in bt2.TraceCollectionMessageIterator(str(trace_location)):
        if type(msg) is not bt2._EventMessageConst:
            continue

        found = False
        for event in expected_events:
            if event["name"] == msg.event.name and event["msg"] is None:
                found = True
                event["count"] = event["count"] + 1
                break
            elif (
                event["name"] == msg.event.name
                and event["msg"] is not None
                and event["msg"] == msg.event["msg"]
            ):
                found = True
                event["count"] = event["count"] + 1
                break

        if found == False:
            unknown_event_count = unknown_event_count + 1
            printmsg = None
            if "msg" in msg.event:
                printmsg = msg.event["msg"]
            tap.diagnostic(
                'Unexpected event name="{}" msg="{}" encountered'.format(
                    msg.event.name, str(printmsg)
                )
            )

    for event in expected_events:
        may_fail = "may_fail" in event.keys() and event["may_fail"]
        if not may_fail:
            tap.test(
                event["count"] == 1,
                'Found expected event name="{}" msg="{}"'.format(
                    event["name"], str(event["msg"])
                ),
            )
        else:
            tap.skip("Event '{}' may or may not be recorded".format(event["name"]))

    tap.test(unknown_event_count == 0, "Found no unexpected events")
