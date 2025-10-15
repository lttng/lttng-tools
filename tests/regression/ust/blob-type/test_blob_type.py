#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
This test validates the blob type support for applications instrumented
with LTTng-UST .
"""

import copy
import pathlib
import sys
import os
import re

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest
import bt2


def find_dir_with_filename(name, path):
    for root, dirs, files in os.walk(path):
        if name in files:
            return root
    raise FileNotFoundError("'{}' not found in '{}'".format(name, path))


query_object = "metadata-info"

expected_events = [
    {
        "name": "tp:tptest_blob_fixed_length_nomediatype",
        "field_name": "fixblobfield_nomediatype",
        "format": {
            "ctf1": {
                "field_content": [2, 3, 4, 5],
                "count": 0,
            },
            "ctf2": {
                "field_content": b"\x02\x03\x04\x05",
                "count": 0,
            },
        },
    },
    {
        "name": "tp:tptest_blob_variable_length_nomediatype",
        "field_name": "varblobfield_nomediatype",
        "format": {
            "ctf1": {
                "field_content": [2, 3, 4, 5],
                "count": 0,
            },
            "ctf2": {
                "field_content": b"\x02\x03\x04\x05",
                "count": 0,
            },
        },
    },
    {
        "name": "tp:tptest_blob_fixed_length_mediatype",
        "field_name": "fixblobfield_mediatype",
        "format": {
            "ctf1": {
                "field_content": [2, 3, 4, 5],
                "count": 0,
            },
            "ctf2": {
                "field_content": b"\x02\x03\x04\x05",
                "count": 0,
            },
        },
    },
    {
        "name": "tp:tptest_blob_variable_length_mediatype",
        "field_name": "varblobfield_mediatype",
        "format": {
            "ctf1": {
                "field_content": [2, 3, 4, 5],
                "count": 0,
            },
            "ctf2": {
                "field_content": b"\x02\x03\x04\x05",
                "count": 0,
            },
        },
    },
]

expected_metadata = {
    "format": {
        "ctf1": [
            {
                "pattern": "static length BLOB field with `lttng/testmediatype_fix` media type",
                "test_name": "static length BLOB media-type comment in CTF 1.8",
            },
            {
                "pattern": "dynamic length BLOB field with `lttng/testmediatype_var` media type",
                "test_name": "dynamic length BLOB media-type comment in CTF 1.8",
            },
        ],
        "ctf2": [
            {
                "pattern": '"media-type":\s*"lttng/testmediatype_fix"',
                "test_name": "static length BLOB media-type comment in CTF 2",
            },
            {
                "pattern": '"media-type":\s*"lttng/testmediatype_var"',
                "test_name": "dynamic length BLOB media-type comment in CTF 2",
            },
        ],
    }
}

test = {
    "description": "Test user space blob type support",
    "application": pathlib.Path(__file__).absolute().parents[3]
    / "utils"
    / "testapp"
    / "gen-ust-events",
    "expected_events": copy.deepcopy(expected_events),
    "expected_metadata": copy.deepcopy(expected_metadata),
    "skip_if_application_not_present": False,
}


def capture_trace(tap, test_env, application, description, trace_format):
    # type: (lttngtest.TapGenerator, lttngtest._Environment, pathlib.Path, str, lttngtest.TraceFormat) -> lttngtest.LocalSessionOutputLocation
    tap.diagnostic(description)

    session_output_location = lttngtest.LocalSessionOutputLocation(
        test_env.create_temporary_directory("trace")
    )

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

    session = client.create_session(
        output=session_output_location, trace_format=trace_format
    )
    tap.diagnostic("Created session `{session_name}`".format(session_name=session.name))

    channel = session.add_channel(lttngtest.TracingDomain.User)
    tap.diagnostic("Created channel `{channel_name}`".format(channel_name=channel.name))

    # Enable all user space events, the default for a user tracepoint event rule.
    channel.add_recording_rule(lttngtest.UserTracepointEventRule("tp:tptest_blob_*"))

    session.start()

    test_app = test_env.launch_test_application([application, "--emit-blob-events"])
    test_app.wait_for_exit()

    session.stop()

    session.destroy()

    return session_output_location


def validate_trace(trace_collection_location, tap, expected_events, ctf_version):
    # type: (pathlib.Path, lttngtest.TapGenerator)
    unknown_event_count = 0

    for msg in bt2.TraceCollectionMessageIterator(str(trace_collection_location)):
        if type(msg) is not bt2._EventMessageConst:
            continue

        found = False
        for event in expected_events:
            if event["name"] == msg.event.name and str(
                event["format"][ctf_version]["field_content"]
            ) == str(msg.event[event["field_name"]]):
                found = True
                event["format"][ctf_version]["count"] = (
                    event["format"][ctf_version]["count"] + 1
                )
                break

        if not found:
            unknown_event_count = unknown_event_count + 1
            tap.diagnostic(
                'Unexpected event name="{}" encountered'.format(msg.event.name)
            )

    for event in expected_events:
        may_fail = "may_fail" in event.keys() and event["may_fail"]
        if not may_fail:
            tap.test(
                event["format"][ctf_version]["count"] == 100,
                'Found expected event name="{}" field name="{}" field content="{}"'.format(
                    event["name"],
                    event["field_name"],
                    str(event["format"][ctf_version]["field_content"]),
                ),
            )
        else:
            tap.skip("Event '{}' may or may not be recorded".format(event["name"]))

    tap.test(unknown_event_count == 0, "Found no unexpected events")


def validate_metadata(trace_collection_location, tap, expected_metadata, ctf_version):
    # type: (pathlib.Path, lttngtest.TapGenerator)

    # Query requires path to a specific trace rather than a trace collection
    trace_location = str(find_dir_with_filename("metadata", trace_collection_location))
    ctf = bt2.find_plugin("ctf")
    fs = ctf.source_component_classes["fs"]
    res = bt2.QueryExecutor(
        fs,
        query_object,
        {"path": trace_location},
    ).query()
    for test in expected_metadata["format"][ctf_version]:
        regex = re.compile(r"{}".format(test["pattern"]))
        match = regex.search(str(res))
        tap.test(match, "Found {}".format(test["test_name"]))


def test_ctf(tap, trace_format, ctf_version):
    with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
        try:
            outputlocation = capture_trace(
                tap,
                test_env,
                test["application"],
                test["description"],
                trace_format,
            )
            validate_trace(
                outputlocation.path,
                tap,
                copy.deepcopy(test["expected_events"]),
                ctf_version,
            )
            validate_metadata(
                outputlocation.path, tap, test["expected_metadata"], ctf_version
            )
        except FileNotFoundError as fne:
            tap.diagnostic(fne)
            if test["skip_if_application_not_present"]:
                tap.skip(
                    "Test application '{}' not found".format(test["application"]),
                    tap.remaining_test_cases,
                )
                sys.exit(0)


if __name__ == "__main__":
    tap = lttngtest.TapGenerator(
        (
            (6 + len(test["expected_events"]))
            + len(test["expected_metadata"]["format"]["ctf1"])
            + len(test["expected_metadata"]["format"]["ctf2"])
        )
    )
    test_ctf(tap, lttngtest.TraceFormat.CTF_1_8, "ctf1")
    test_ctf(tap, lttngtest.TraceFormat.CTF_2, "ctf2")
    sys.exit(0 if tap.is_successful else 1)
