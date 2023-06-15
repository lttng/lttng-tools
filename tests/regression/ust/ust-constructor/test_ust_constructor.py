#!/usr/bin/env python3
#
# Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# Copyright (C) 2023 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only

import pathlib
import sys
import os
from typing import Any, Callable, Type

"""
Test instrumentation coverage of C/C++ constructors and destructors by LTTng-UST
tracepoints.

This test successively sets up a session, traces a test application, and then
reads the resulting trace to determine if all the expected events are present.
"""

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest
import bt2

expected_events = [
    {"name": "tp_so:constructor_c_provider_shared_library", "msg": None, "count": 0},
    {"name": "tp_a:constructor_c_provider_static_archive", "msg": None, "count": 0},
    {
        "name": "tp_so:constructor_cplusplus_provider_shared_library",
        "msg": "global - shared library define and provider",
        "count": 0,
    },
    {
        "name": "tp_a:constructor_cplusplus_provider_static_archive",
        "msg": "global - static archive define and provider",
        "count": 0,
    },
    {"name": "tp:constructor_c_across_units_before_define", "msg": None, "count": 0},
    {
        "name": "tp:constructor_cplusplus",
        "msg": "global - across units before define",
        "count": 0,
    },
    {"name": "tp:constructor_c_same_unit_before_define", "msg": None, "count": 0},
    {"name": "tp:constructor_c_same_unit_after_define", "msg": None, "count": 0},
    {
        "name": "tp:constructor_cplusplus",
        "msg": "global - same unit before define",
        "count": 0,
    },
    {
        "name": "tp:constructor_cplusplus",
        "msg": "global - same unit after define",
        "count": 0,
    },
    {"name": "tp:constructor_c_across_units_after_define", "msg": None, "count": 0},
    {
        "name": "tp:constructor_cplusplus",
        "msg": "global - across units after define",
        "count": 0,
    },
    {"name": "tp:constructor_c_same_unit_before_provider", "msg": None, "count": 0},
    {"name": "tp:constructor_c_same_unit_after_provider", "msg": None, "count": 0},
    {
        "name": "tp:constructor_cplusplus",
        "msg": "global - same unit before provider",
        "count": 0,
    },
    {
        "name": "tp:constructor_cplusplus",
        "msg": "global - same unit after provider",
        "count": 0,
    },
    {"name": "tp:constructor_c_across_units_after_provider", "msg": None, "count": 0},
    {
        "name": "tp:constructor_cplusplus",
        "msg": "global - across units after provider",
        "count": 0,
    },
    {"name": "tp:constructor_cplusplus", "msg": "main() local", "count": 0},
    {
        "name": "tp_so:constructor_cplusplus_provider_shared_library",
        "msg": "main() local - shared library define and provider",
        "count": 0,
    },
    {
        "name": "tp_a:constructor_cplusplus_provider_static_archive",
        "msg": "main() local - static archive define and provider",
        "count": 0,
    },
    {"name": "tp:main", "msg": None, "count": 0},
    {
        "name": "tp_a:destructor_cplusplus_provider_static_archive",
        "msg": "main() local - static archive define and provider",
        "count": 0,
    },
    {
        "name": "tp_so:destructor_cplusplus_provider_shared_library",
        "msg": "main() local - shared library define and provider",
        "count": 0,
    },
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
    },
    {
        "name": "tp:destructor_cplusplus",
        "msg": "global - across units after define",
        "count": 0,
    },
    {
        "name": "tp:destructor_cplusplus",
        "msg": "global - same unit after define",
        "count": 0,
    },
    {
        "name": "tp:destructor_cplusplus",
        "msg": "global - same unit before define",
        "count": 0,
    },
    {
        "name": "tp:destructor_cplusplus",
        "msg": "global - across units before define",
        "count": 0,
    },
    {
        "name": "tp_a:destructor_cplusplus_provider_static_archive",
        "msg": "global - static archive define and provider",
        "count": 0,
    },
    {
        "name": "tp_so:destructor_cplusplus_provider_shared_library",
        "msg": "global - shared library define and provider",
        "count": 0,
    },
    {"name": "tp:destructor_c_across_units_after_provider", "msg": None, "count": 0},
    {"name": "tp:destructor_c_same_unit_after_provider", "msg": None, "count": 0},
    {"name": "tp:destructor_c_same_unit_before_provider", "msg": None, "count": 0},
    {"name": "tp:destructor_c_across_units_after_define", "msg": None, "count": 0},
    {"name": "tp:destructor_c_same_unit_after_define", "msg": None, "count": 0},
    {"name": "tp:destructor_c_same_unit_before_define", "msg": None, "count": 0},
    {"name": "tp:destructor_c_across_units_before_define", "msg": None, "count": 0},
    {"name": "tp_a:destructor_c_provider_static_archive", "msg": None, "count": 0},
    {"name": "tp_so:destructor_c_provider_shared_library", "msg": None, "count": 0},
]

num_tests = 7 + len(expected_events)


def capture_trace(tap, test_env):
    # type: (lttngtest.TapGenerator, lttngtest._Environment) -> lttngtest.LocalSessionOutputLocation
    tap.diagnostic(
        "Capture trace from application with instrumented C/C++ constructors/destructors"
    )

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

    test_app = test_env.launch_trace_test_constructor_application()
    with tap.case("Run test app".format(session_name=session.name)) as test_case:
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


def validate_trace(trace_location, tap):
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
        tap.test(
            event["count"] == 1,
            'Found expected event name="{}" msg="{}"'.format(
                event["name"], str(event["msg"])
            ),
        )

    tap.test(unknown_event_count == 0, "Found no unexpected events")


tap = lttngtest.TapGenerator(num_tests)
tap.diagnostic("Test user space constructor/destructor instrumentation coverage")

with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
    outputlocation = capture_trace(tap, test_env)
    validate_trace(outputlocation.path, tap)

sys.exit(0 if tap.is_successful else 1)
