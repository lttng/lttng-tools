#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
A stopped recording session must not see its map counters update.

Build a user space map channel and an "event rule matches" → "increment
map value" trigger on the tracepoint of the test application, then drive
it through three phases:

1. While started, fire `DEFAULT_EVENT_COUNT` events: the counter
   reaches `DEFAULT_EVENT_COUNT`.

2. While stopped, fire `DEFAULT_EVENT_COUNT` more events: the counter
   must stay put because a stopped session drops the increments.

3. While started again, fire `DEFAULT_EVENT_COUNT` more events: the
   counter resumes and reaches `2 * DEFAULT_EVENT_COUNT`.

Phase 3 is what makes phase 2 trustworthy: had the stopped session
leaked the phase-2 increments, the final counter would be
`3 * DEFAULT_EVENT_COUNT` rather than `2 * DEFAULT_EVENT_COUNT`. Reading
after a full restart-and-fire cycle leaves no doubt that the phase-2
events were dropped rather than merely still in flight.
"""

import pathlib
import sys

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common


# Fires `count` `UST_TRACEPOINT_NAME` events through the test
# application and waits for the application to finish tracing and exit.
def _fire_events(
    test_env,  # type: lttngtest._Environment
    count=common.DEFAULT_EVENT_COUNT,  # type: int
):
    # type: (...) -> None
    app = test_env.launch_wait_trace_test_application(count)
    app.trace()
    app.wait_for_tracing_done()
    app.wait_for_exit()


def test_no_update_when_stopped(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
):
    # type: (...) -> None
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = common._create_recording_session(test_env, client)
    channel = session.add_user_map_channel()
    common.add_user_event_count_trigger(client, session, channel.name)

    key = "count/{}".format(common.UST_TRACEPOINT_NAME)

    # Phase 1: the started session counts its events
    session.start()
    _fire_events(test_env)
    val = common.read_map_value(session, key)
    tap.test(
        val == common.DEFAULT_EVENT_COUNT,
        "counter `{}` is {} while started".format(key, common.DEFAULT_EVENT_COUNT),
    )

    # Phase 2: the stopped session drops the increments
    session.stop()
    _fire_events(test_env)
    val = common.read_map_value(session, key)
    tap.test(
        val == common.DEFAULT_EVENT_COUNT,
        "counter `{}` stays {} while stopped".format(key, common.DEFAULT_EVENT_COUNT),
    )

    # Phase 3: restarting resumes the counting, and the phase-2 events
    # stayed dropped (otherwise the counter would be three times the
    # event count here).
    session.start()
    _fire_events(test_env)
    val = common.read_map_value(session, key)
    tap.test(
        val == 2 * common.DEFAULT_EVENT_COUNT,
        "counter `{}` is {} after restarting".format(
            key, 2 * common.DEFAULT_EVENT_COUNT
        ),
    )

    session.destroy()


tap = lttngtest.TapGenerator(3)

with lttngtest.test_environment(
    with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=False
) as test_env:
    test_no_update_when_stopped(test_env, tap)

sys.exit(0 if tap.is_successful else 1)
