#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Observable difference between the per-user
(`BufferSharingPolicy.PerUID`) and per-process
(`BufferSharingPolicy.PerPID`) buffer ownership models of a user space
map channel, surfaced through UserMapChannel.groups():

Per-user:
    A single per-user map group owned by the current Unix user, and no
    dead process policy.

Per-process:
    A per-process map group owned by the PID of the traced application,
    and a dead process policy.
"""

import os
import pathlib
import sys

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common


def test_per_user(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
):
    # type: (...) -> None
    populated = common.populate_user_map_from_events(
        test_env,
        tap,
        buffer_sharing_policy=lttngtest.lttngctl.BufferSharingPolicy.PerUID,
    )
    channel = populated.channel

    tap.test(
        channel.buffer_sharing_policy == lttngtest.lttngctl.BufferSharingPolicy.PerUID,
        "map channel reports the per-user buffer sharing policy",
    )
    tap.test(
        channel.dead_process_policy is None,
        "per-user map channel has no dead process policy",
    )

    groups = channel.groups()
    user_group = next(
        (g for g in groups if g.type == lttngtest.lttngctl.MapGroupType.UserPerUser),
        None,
    )
    tap.test(user_group is not None, "per-user map channel has a per-user map group")
    tap.test(
        user_group is not None and user_group.owner_id == os.getuid(),
        "the per-user map group is owned by the current user",
    )

    populated.session.destroy()


def test_per_process(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
):
    # type: (...) -> None

    # Build the per-process case by hand and keep the application alive
    # while reading the map groups: a per-process map group only exists
    # for as long as its owning process does (subject to the dead
    # process policy once that process exits).
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = common._create_recording_session(test_env, client)
    channel = session.add_user_map_channel(
        buffer_sharing_policy=lttngtest.lttngctl.BufferSharingPolicy.PerPID,
        dead_process_policy=lttngtest.lttngctl.MapChannelDeadProcessPolicy.Drop,
    )

    common.add_user_event_count_trigger(client, session, channel.name)
    session.start()

    app = test_env.launch_wait_trace_test_application(
        common.DEFAULT_EVENT_COUNT, wait_before_exit=True
    )
    app.trace()
    app.wait_for_tracing_done()

    # The application is still alive here
    tap.test(
        channel.buffer_sharing_policy == lttngtest.lttngctl.BufferSharingPolicy.PerPID,
        "map channel reports the per-process buffer sharing policy",
    )
    tap.test(
        channel.dead_process_policy is not None,
        "per-process map channel has a dead process policy",
    )

    process_group = next(
        (
            g
            for g in channel.groups()
            if g.type == lttngtest.lttngctl.MapGroupType.UserPerProcess
        ),
        None,
    )

    tap.test(
        process_group is not None, "per-process map channel has a per-process map group"
    )
    tap.test(
        process_group is not None and process_group.owner_id == app.vpid,
        "the per-process map group is owned by the PID of the application",
    )

    app.touch_exit_file()
    app.wait_for_exit()
    session.destroy()


tap = lttngtest.TapGenerator(8)

with lttngtest.test_environment(
    with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=False
) as test_env:
    test_per_user(test_env, tap)
    test_per_process(test_env, tap)

sys.exit(0 if tap.is_successful else 1)
