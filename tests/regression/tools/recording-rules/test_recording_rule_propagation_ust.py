#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Check that a user space recording rule reaches the applications which
must apply it, whenever the session daemon learns of them.

An application only emits the event records of a recording rule that
reached it, so counting the event records of the resulting trace tells
whether the rule made it to the tracer.

Validates the relative order of session creation, rule addition,
application launch, and session start, for both buffer ownership
models; a rule change occurring while an application is midway through
emitting events; and two applications tracing concurrently, one
launched before the rule exists and one after the session started.

The goal of the test is to exercise the various tracing configuration points
through which the active event-rules get pushed to applications.
"""

import itertools
import pathlib
import sys
from typing import Tuple

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import recording_rule_propagation_utils as utils

TRACEPOINT_NAME = "tp:tptest"
EVENT_COUNT = 100

BUFFER_SHARING_POLICIES = (
    lttngtest.lttngctl.BufferSharingPolicy.PerUID,
    lttngtest.lttngctl.BufferSharingPolicy.PerPID,
)

# Every order in which the four steps can occur: a recording rule can
# only be added to an existing recording session, which can only be
# started once it exists, so the session creation comes first of the
# three. The application launch can happen at any point.
STEP_ORDERS = [
    order
    for order in itertools.permutations(utils.Step)
    if order.index(utils.Step.CreateSession) < order.index(utils.Step.AddRecordingRule)
    and order.index(utils.Step.CreateSession) < order.index(utils.Step.StartSession)
]


def _create_session(
    client: lttngtest.LTTngClient,
    trace_path: pathlib.Path,
    buffer_sharing_policy: lttngtest.lttngctl.BufferSharingPolicy,
) -> Tuple[lttngtest.Session, lttngtest.lttngctl.Channel]:
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(trace_path)
    )
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User,
        buffer_sharing_policy=buffer_sharing_policy,
    )

    return session, channel


# Runs the four steps in the order defined by `step_order`, then makes the
# application emit its events.
def test_step_order(
    test_env: lttngtest._Environment,
    tap: lttngtest.TapGenerator,
    client: lttngtest.LTTngClient,
    step_order: Tuple[utils.Step, ...],
    buffer_sharing_policy: lttngtest.lttngctl.BufferSharingPolicy,
) -> None:
    scenario = "{} ({})".format(
        utils.format_step_order(step_order), buffer_sharing_policy.name
    )
    trace_path = test_env.create_temporary_directory("trace")

    for step in step_order:
        if step is utils.Step.CreateSession:
            session, channel = _create_session(
                client, trace_path, buffer_sharing_policy
            )
        elif step is utils.Step.AddRecordingRule:
            channel.add_recording_rule(
                lttngtest.lttngctl.UserTracepointEventRule(TRACEPOINT_NAME)
            )
        elif step is utils.Step.LaunchApplication:
            app = test_env.launch_wait_trace_test_application(EVENT_COUNT)
        else:
            session.start()

    app.trace()
    app.wait_for_tracing_done()
    app.wait_for_exit()

    session.stop()
    session.destroy()

    utils.check_event_count(tap, scenario, trace_path, EVENT_COUNT)


# Applies `change` while the application is blocked before its last
# event record, and checks that only the events on the recording side of
# the change made it to the trace.
def test_mid_run_change(
    test_env: lttngtest._Environment,
    tap: lttngtest.TapGenerator,
    client: lttngtest.LTTngClient,
    change: utils.MidRunChange,
    buffer_sharing_policy: lttngtest.lttngctl.BufferSharingPolicy,
) -> None:
    scenario = "{} while the application runs ({})".format(
        change.value, buffer_sharing_policy.name
    )
    trace_path = test_env.create_temporary_directory("trace")
    session, channel = _create_session(client, trace_path, buffer_sharing_policy)
    rule = lttngtest.lttngctl.UserTracepointEventRule(TRACEPOINT_NAME)

    if change is not utils.MidRunChange.AddRecordingRule:
        channel.add_recording_rule(rule)

    if change is not utils.MidRunChange.StartSession:
        session.start()

    app = test_env.launch_wait_trace_test_application(
        EVENT_COUNT, wait_before_last_event=True
    )

    app.trace()
    app.wait_for_before_last_event()

    if change is utils.MidRunChange.AddRecordingRule:
        channel.add_recording_rule(rule)
    elif change is utils.MidRunChange.DisableRecordingRule:
        channel.disable_recording_rules(TRACEPOINT_NAME)
    elif change is utils.MidRunChange.StartSession:
        session.start()
    else:
        session.stop()

    app.touch_last_event_file()
    app.wait_for_tracing_done()
    app.wait_for_exit()

    if change is not utils.MidRunChange.StopSession:
        session.stop()

    session.destroy()
    utils.check_event_count(
        tap,
        scenario,
        trace_path,
        1 if change.begins_recording else EVENT_COUNT - 1,
    )


# Traces an application which was already running when the recording rule
# was added along with one which spawned once the recording session was
# started.
def test_concurrent_applications(
    test_env: lttngtest._Environment,
    tap: lttngtest.TapGenerator,
    client: lttngtest.LTTngClient,
    buffer_sharing_policy: lttngtest.lttngctl.BufferSharingPolicy,
) -> None:
    scenario = "an application launched before the rule and one launched after the start ({})".format(
        buffer_sharing_policy.name
    )
    trace_path = test_env.create_temporary_directory("trace")
    early_app = test_env.launch_wait_trace_test_application(EVENT_COUNT)
    session, channel = _create_session(client, trace_path, buffer_sharing_policy)

    channel.add_recording_rule(
        lttngtest.lttngctl.UserTracepointEventRule(TRACEPOINT_NAME)
    )
    session.start()

    late_app = test_env.launch_wait_trace_test_application(EVENT_COUNT)
    apps = (early_app, late_app)

    for app in apps:
        app.trace()

    for app in apps:
        app.wait_for_tracing_done()
        app.wait_for_exit()

    session.stop()
    session.destroy()
    utils.check_event_count(tap, scenario, trace_path, len(apps) * EVENT_COUNT)


# Per buffer ownership model: one case per step order, one per mid-run
# change, and the concurrent applications case.
TEST_COUNT = len(BUFFER_SHARING_POLICIES) * (
    len(STEP_ORDERS) + len(utils.MidRunChange) + 1
)
tap = lttngtest.TapGenerator(TEST_COUNT)

with lttngtest.test_environment(
    with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=False
) as test_env:
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

    for buffer_sharing_policy in BUFFER_SHARING_POLICIES:
        for step_order in STEP_ORDERS:
            test_step_order(test_env, tap, client, step_order, buffer_sharing_policy)

        for change in utils.MidRunChange:
            test_mid_run_change(test_env, tap, client, change, buffer_sharing_policy)

        test_concurrent_applications(test_env, tap, client, buffer_sharing_policy)

sys.exit(0 if tap.is_successful else 1)
