#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Kernel counterpart of test_recording_rule_propagation_ust.py.
"""

import pathlib
import sys
from typing import Tuple

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import recording_rule_propagation_utils as utils

TRACEPOINT_NAME = "lttng_test_filter_event"
EVENT_COUNT = 100

# Sizes of the two batches of the mid-run cases; they differ so that the
# resulting event record count names the batch that was recorded.
FIRST_BATCH_EVENT_COUNT = 30
SECOND_BATCH_EVENT_COUNT = 70

# The kernel domain has no application to launch, so only the three other
# steps apply, and the recording session must exist before either of the
# two which act on it.
STEP_ORDERS = [
    (utils.Step.CreateSession, utils.Step.AddRecordingRule, utils.Step.StartSession),
    (utils.Step.CreateSession, utils.Step.StartSession, utils.Step.AddRecordingRule),
]

TEST_COUNT = len(STEP_ORDERS) + len(utils.MidRunChange)


def _fire_events(count: int) -> None:
    with open("/proc/lttng-test-filter-event", "w") as proc:
        proc.write(str(count))


def _create_session(
    client: lttngtest.LTTngClient,
    trace_path: pathlib.Path,
) -> Tuple[lttngtest.Session, lttngtest.lttngctl.Channel]:
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(trace_path)
    )
    channel = session.add_channel(lttngtest.lttngctl.TracingDomain.Kernel)

    return session, channel


# Runs the three steps in the order defined by `step_order`, then fires the
# events.
#
# Since the events are only fired once every step is done, the order the
# steps ran in must not change the resulting trace (all of the events are
# expected in either case).
def test_step_order(
    test_env: lttngtest._Environment,
    tap: lttngtest.TapGenerator,
    client: lttngtest.LTTngClient,
    step_order: Tuple[utils.Step, ...],
) -> None:
    scenario = utils.format_step_order(step_order)
    trace_path = test_env.create_temporary_directory("trace")

    for step in step_order:
        if step is utils.Step.CreateSession:
            session, channel = _create_session(client, trace_path)
        elif step is utils.Step.AddRecordingRule:
            channel.add_recording_rule(
                lttngtest.lttngctl.KernelTracepointEventRule(TRACEPOINT_NAME)
            )
        else:
            session.start()

    _fire_events(EVENT_COUNT)

    session.stop()
    session.destroy()

    utils.check_event_count(tap, scenario, trace_path, EVENT_COUNT)


# Applies `change` between the two batches of events, and checks that
# only the batch on the recording side of the change made it to the
# trace.
def test_mid_run_change(
    test_env: lttngtest._Environment,
    tap: lttngtest.TapGenerator,
    client: lttngtest.LTTngClient,
    change: utils.MidRunChange,
) -> None:
    scenario = "{} between two batches of events".format(change.value)
    trace_path = test_env.create_temporary_directory("trace")
    session, channel = _create_session(client, trace_path)
    rule = lttngtest.lttngctl.KernelTracepointEventRule(TRACEPOINT_NAME)

    if change is not utils.MidRunChange.AddRecordingRule:
        channel.add_recording_rule(rule)

    if change is not utils.MidRunChange.StartSession:
        session.start()

    _fire_events(FIRST_BATCH_EVENT_COUNT)

    if change is utils.MidRunChange.AddRecordingRule:
        channel.add_recording_rule(rule)
    elif change is utils.MidRunChange.DisableRecordingRule:
        channel.disable_recording_rules(TRACEPOINT_NAME)
    elif change is utils.MidRunChange.StartSession:
        session.start()
    else:
        session.stop()

    _fire_events(SECOND_BATCH_EVENT_COUNT)

    if change is not utils.MidRunChange.StopSession:
        session.stop()

    session.destroy()
    utils.check_event_count(
        tap,
        scenario,
        trace_path,
        (
            SECOND_BATCH_EVENT_COUNT
            if change.begins_recording
            else FIRST_BATCH_EVENT_COUNT
        ),
    )


def test_recording_rule_propagation_kernel(
    test_env: lttngtest._Environment,
    tap: lttngtest.TapGenerator,
) -> None:
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

    for step_order in STEP_ORDERS:
        test_step_order(test_env, tap, client, step_order)

    for change in utils.MidRunChange:
        test_mid_run_change(test_env, tap, client, change)


tap = lttngtest.TapGenerator(TEST_COUNT)

if not lttngtest._Environment.run_kernel_tests():
    tap.skip_all_remaining(
        "kernel recording rule tests require `root` and the `lttng-test` module"
    )
else:
    with lttngtest.kernel_module("lttng-test"):
        with lttngtest.test_environment(
            with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=True
        ) as test_env:
            test_recording_rule_propagation_kernel(test_env, tap)

sys.exit(0 if tap.is_successful else 1)
