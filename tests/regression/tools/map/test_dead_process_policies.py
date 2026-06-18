#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Dead process policy of a per-process user space map channel: once a
traced application has incremented its own process counters and exited,
and the session daemon has reaped the dead process,

• `MapChannelDeadProcessPolicy.Drop` discards the counters of the dead
  process; and

• `MapChannelDeadProcessPolicy.SumIntoShared` folds them into a
  channel-wide shared group.

Reaping is asynchronous relative to the application exit, therefore the
test uses a rotation as a synchronization point before reading
the counter.
"""

import pathlib
import sys
from typing import Tuple

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common


# Creates a per-process user map channel with the given dead process
# policy `policy`, fires `DEFAULT_EVENT_COUNT` events from an
# application that then exits, and forces a synchronization point so
# that the daemon reaps the dead process before the test reads
# the counter.
#
# Returns (session, channel, key).
def _populate_dead_process(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
    policy,  # type: lttngtest.lttngctl.MapChannelDeadProcessPolicy
):
    # type: (...) -> Tuple[lttngtest.Session, lttngtest.lttngctl.UserMapChannel, str]
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = common._create_recording_session(test_env, client)
    channel = session.add_user_map_channel(
        buffer_sharing_policy=lttngtest.lttngctl.BufferSharingPolicy.PerPID,
        dead_process_policy=policy,
    )

    common.add_user_event_count_trigger(client, session, channel.name)
    session.start()

    app = test_env.launch_wait_trace_test_application(common.DEFAULT_EVENT_COUNT)
    app.trace()
    app.wait_for_tracing_done()
    app.wait_for_exit()

    # Force a synchronization point so the daemon reaps the dead process
    # before the test reads the counter.
    session.rotate(wait=True)

    key = "count/{}".format(common.UST_TRACEPOINT_NAME)
    return session, channel, key


def test_drop(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
):
    # type: (...) -> None
    session, channel, key = _populate_dead_process(
        test_env, tap, lttngtest.lttngctl.MapChannelDeadProcessPolicy.Drop
    )

    val = common.read_map_value(session, key)
    tap.test(
        val is None or val == 0,
        "drop policy discards the dead process counters (counter `{}` is {})".format(
            key, val
        ),
    )

    # The discarded counters leave nothing behind: the per-process map
    # group of the reaped process is gone, and the policy folded nothing
    # into the shared map group.
    tap.test(
        common.sum_map_value_in_group_type(session, "user-per-process", key) is None,
        "drop policy removes the dead process per-process group",
    )
    shared = common.sum_map_value_in_group_type(session, "shared", key)
    tap.test(
        shared is None or shared == 0,
        "drop policy folds nothing into the shared group (shared `{}` is {})".format(
            key, shared
        ),
    )

    session.destroy()


def test_sum_into_shared(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
):
    # type: (...) -> None
    session, channel, key = _populate_dead_process(
        test_env, tap, lttngtest.lttngctl.MapChannelDeadProcessPolicy.SumIntoShared
    )

    # The value must reside in the shared map group specifically, not
    # merely somewhere in the channel: query the shared map
    # group directly.
    shared = common.sum_map_value_in_group_type(session, "shared", key)
    tap.test(
        shared == common.DEFAULT_EVENT_COUNT,
        '"sum into shared" policy folds the dead process counters into the '
        "shared group (shared `{}` is {}, expected {})".format(
            key, shared, common.DEFAULT_EVENT_COUNT
        ),
    )

    # And the per-process map group of the reaped process is gone: the
    # fold moved the value rather than duplicating it.
    tap.test(
        common.sum_map_value_in_group_type(session, "user-per-process", key) is None,
        "the dead process per-process group is gone after the fold",
    )

    session.destroy()


tap = lttngtest.TapGenerator(5)

with lttngtest.test_environment(
    with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=False
) as test_env:
    test_drop(test_env, tap)
    test_sum_into_shared(test_env, tap)

sys.exit(0 if tap.is_successful else 1)
