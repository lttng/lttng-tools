#!/usr/bin/env python3
#
# Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only

import pathlib
import sys
import os
from typing import Any, Callable, Type

"""
Test the addition of various user space contexts.

This test successively sets up a session with a certain context enabled, traces
a test application, and then reads the resulting trace to determine if:
  - the context field is present in the trace
  - the context field has the expected value.

The vpid, vuid, vgid and java application contexts are validated by this test.
"""

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest
import bt2


def context_trace_field_name(context_type):
    # type: (Type[lttngtest.ContextType]) -> str
    if isinstance(context_type, lttngtest.VpidContextType):
        return "vpid"
    elif isinstance(context_type, lttngtest.VuidContextType):
        return "vuid"
    elif isinstance(context_type, lttngtest.VgidContextType):
        return "vgid"
    elif isinstance(context_type, lttngtest.JavaApplicationContextType):
        # Depends on the trace format and will need to be adapted for CTF 2.
        return "_app_{retriever}_{name}".format(
            retriever=context_type.retriever_name, name=context_type.field_name
        )
    else:
        raise NotImplementedError


def trace_stream_class_has_context_field_in_event_context(
    trace_location, context_field_name
):
    # type: (pathlib.Path, str) -> bool
    iterator = bt2.TraceCollectionMessageIterator(str(trace_location))

    # A bt2 message sequence is guaranteed to begin with a StreamBeginningMessage.
    # Since we only have one channel (one stream class) and one trace, it is
    # safe to use it to determine if the stream class contains the expected
    # context field.
    stream_begin_msg = next(iterator)

    trace_class = stream_begin_msg.stream.trace.cls
    # Ensure the trace class has only one stream class.
    assert len(trace_class)

    stream_class_id = next(iter(trace_class))
    stream_class = trace_class[stream_class_id]
    event_common_context_field_class = stream_class.event_common_context_field_class

    return context_field_name in event_common_context_field_class


def trace_events_have_context_value(trace_location, context_field_name, value):
    # type: (pathlib.Path, str, Any) -> bool
    for msg in bt2.TraceCollectionMessageIterator(str(trace_location)):
        if type(msg) is not bt2._EventMessageConst:
            continue

        if msg.event.common_context_field[context_field_name] != value:
            print(msg.event.common_context_field[context_field_name])
            return False
    return True


def test_static_context(tap, test_env, context_type, context_value_retriever):
    # type: (lttngtest.TapGenerator, lttngtest._Environment, lttngtest.ContextType, Callable[[lttngtest.WaitTraceTestApplication], Any]) -> None
    tap.diagnostic(
        "Test presence and expected value of context `{context_name}`".format(
            context_name=type(context_type).__name__
        )
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

    with tap.case(
        "Add {context_type} context to channel `{channel_name}`".format(
            context_type=type(context_type).__name__, channel_name=channel.name
        )
    ) as test_case:
        channel.add_context(context_type)

    test_app = test_env.launch_wait_trace_test_application(50)

    # Only track the test application
    session.user_vpid_process_attribute_tracker.track(test_app.vpid)
    expected_context_value = context_value_retriever(test_app)

    # Enable all user space events, the default for a user tracepoint event rule.
    channel.add_recording_rule(lttngtest.UserTracepointEventRule())

    session.start()
    test_app.trace()
    test_app.wait_for_exit()
    session.stop()
    session.destroy()

    tap.test(
        trace_stream_class_has_context_field_in_event_context(
            session_output_location.path, context_trace_field_name(context_type)
        ),
        "Stream class contains field `{context_field_name}`".format(
            context_field_name=context_trace_field_name(context_type)
        ),
    )

    tap.test(
        trace_events_have_context_value(
            session_output_location.path,
            context_trace_field_name(context_type),
            expected_context_value,
        ),
        "Trace's events contain the expected `{context_field_name}` value `{expected_context_value}`".format(
            context_field_name=context_trace_field_name(context_type),
            expected_context_value=expected_context_value,
        ),
    )


tap = lttngtest.TapGenerator(20)
tap.diagnostic("Test user space context tracing")

with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
    test_static_context(
        tap, test_env, lttngtest.VpidContextType(), lambda test_app: test_app.vpid
    )
    test_static_context(
        tap, test_env, lttngtest.VuidContextType(), lambda test_app: os.getuid()
    )
    test_static_context(
        tap, test_env, lttngtest.VgidContextType(), lambda test_app: os.getgid()
    )
    test_static_context(
        tap,
        test_env,
        lttngtest.JavaApplicationContextType("mayo", "ketchup"),
        lambda test_app: {},
    )

sys.exit(0 if tap.is_successful else 1)
