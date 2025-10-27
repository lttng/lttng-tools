#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# SPDX-FileCopyrightText: 2025 Kienan Stewart <kstewart@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only

import os
import pathlib
import shutil
import subprocess
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest
import bt2


def test(tap, test_env, test_app, expected_events):
    output_path = test_env.create_temporary_directory("trace")
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_path)
    )
    channel = session.add_channel(lttngtest.lttngctl.TracingDomain.User)
    channel.add_recording_rule(
        lttngtest.lttngctl.UserTracepointEventRule("ust_tests_demo*")
    )
    session.start()

    app = test_env.launch_test_application(test_app)
    app.wait_for_exit()
    session.stop()
    received_events = []
    try:
        for msg in bt2.TraceCollectionMessageIterator(str(output_path)):
            if type(msg) is bt2._EventMessageConst:
                received_events.append(msg.event)
    except Exception as e:
        tap.diagnostic("Exception while collecting events with bt2: {}".format(e))

    tap.test(
        len(received_events) == expected_events,
        "Received {}/{} expected events from test application '{}'".format(
            len(received_events), expected_events, test_app
        ),
    )

    # Validate received event content
    if len(received_events) == 0:
        tap.skip("No received events to validate")
        return

    event_content_valid = True
    # Events 0, 6, 7 are "fixed" known events
    event_content_valid = event_content_valid and validate_event(
        received_events[0], "ust_tests_demo:starting", "value", "123"
    )
    event_content_valid = event_content_valid and validate_event(
        received_events[6], "ust_tests_demo:done", "value", "456"
    )
    event_content_valid = event_content_valid and validate_event(
        received_events[7], "ust_tests_demo3:done", "value", "42"
    )
    # Events 1-5 are iterations
    for event_no, event in zip([str(x) for x in range(0, 5)], received_events[1:6]):
        event_content_valid = event_content_valid and validate_demo2_event(
            event, event_no
        )

    tap.test(event_content_valid, "Event content valid")


def validate_event(event, name, attribute, value):
    if event.name != name:
        tap.diagnostic(
            "Event name `{}` does not match expected name `{}`".format(event.name, name)
        )
        return False

    return validate_event_payload_field(event, attribute, value)


def validate_event_payload_field(event, attribute, value):
    if attribute not in event.payload_field:
        tap.diagnostic("Event has no payload field '{}'".format(attribute))
        return False

    if str(event.payload_field[attribute]) != value:
        tap.diagnostic(
            "Event payload field `{}`'s value of `{}` does not match expected value `{}`".format(
                attribute, event.payload_field[attribute], value
            )
        )
        return False

    return True


def validate_demo2_event(event, value):
    if not validate_event(event, "ust_tests_demo2:loop", "intfield", value):
        return False

    simple_attributes = ["longfield", "netintfield", "intfield2", "netintfieldhex"]
    for attribute in simple_attributes:
        if not validate_event_payload_field(event, attribute, value):
            return False

    if not validate_event_payload_field(event, "floatfield", "2222.0"):
        return False

    if not validate_event_payload_field(event, "doublefield", "2.0"):
        return False

    if not validate_event_payload_field(event, "seqfield1", str([116, 101, 115, 116])):
        return False

    if len(event.payload_field["seqfield1"]) != 4:
        tap.diagnostic(
            "seqfield1's length of {} is not 4".format(
                len(event.payload_field["seqfield1"])
            )
        )
        return False

    if not validate_event_payload_field(event, "arrfield1", str([1, 2, 3])):
        return False

    if not validate_event_payload_field(event, "arrfield2", "test"):
        return False

    if not validate_event_payload_field(event, "seqfield2", "test"):
        return False

    if not validate_event_payload_field(event, "stringfield", "test"):
        return False

    return True


if __name__ == "__main__":
    test_path = os.path.dirname(os.path.abspath(__file__)) + "/"
    tests = [
        {"test_app": os.path.join(test_path, "demo_static"), "expected_events": 8},
        {"test_app": os.path.join(test_path, "demo_builtin"), "expected_events": 8},
    ]
    demo = os.path.join(test_path, "demo")
    if os.path.exists(demo):
        tests.append(
            {"test_app": os.path.join(test_path, "demo_preload"), "expected_events": 8}
        )
        tests.append({"test_app": demo, "expected_events": 0})

    tap = lttngtest.TapGenerator(len(tests) * 2)
    for test_conf in tests:
        with lttngtest.test_environment(
            with_sessiond=True, log=tap.diagnostic
        ) as test_env:
            test(
                tap,
                test_env,
                **test_conf,
            )

    sys.exit(0 if tap.is_successful else 1)
