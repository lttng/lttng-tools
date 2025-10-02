#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Validate that when a session is configured with per-uid buffer ownership policy,
and more than one user has active traced applications that `lttng clear`
completely clears the buffers.
"""

import os
import pathlib
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest
import bt2


def test_ust_multi_user(tap, test_env, user_count=10):
    if user_count < 2:
        tap.skip("Test requires at least two users")
        return

    events_per_user = 10
    users = []
    for i in range(user_count):
        users.append(test_env.create_dummy_user())

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(snapshot=True)
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User,
        buffer_sharing_policy=lttngtest.lttngctl.BufferSharingPolicy.PerUID,
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()

    test_pass = True
    # Confirm snapshot is empty
    snapshot_dir_pre = lttngtest.TemporaryDirectory("pre-app-run")
    session.record_snapshot(lttngtest.LocalSessionOutputLocation(snapshot_dir_pre.path))
    received, discarded = lttngtest.count_events(
        snapshot_dir_pre.path, ignore_exceptions=True
    )
    tap.diagnostic("Snapshot before app run contains {} events".format(received))
    if received > 0:
        test_pass = False

    # Run apps
    for uid, user in users:
        app = test_env.launch_wait_trace_test_application(events_per_user, run_as=user)
        app.trace()
        app.wait_for_exit()

    # Confirm snapshot contains user_count * events_per_user
    snapshot_dir_post_run = lttngtest.TemporaryDirectory("post-app-run")
    session.record_snapshot(
        lttngtest.LocalSessionOutputLocation(snapshot_dir_post_run.path)
    )
    received, discarded = lttngtest.count_events(snapshot_dir_post_run.path)
    tap.diagnostic("Snapshot after app runs contains {} events".format(received))
    if received != user_count * events_per_user:
        test_pass = False

    # Clear, and confirm snapshot is empty
    session.clear()
    snapshot_dir_post_clear = lttngtest.TemporaryDirectory("post-clear")
    session.record_snapshot(
        lttngtest.LocalSessionOutputLocation(snapshot_dir_post_clear.path)
    )
    received, discarded = lttngtest.count_events(
        snapshot_dir_post_clear.path, ignore_exceptions=True
    )
    tap.diagnostic("Snapshot post-clear contains {} events".format(received))
    if received != 0:
        test_pass = False

    tap.test(test_pass, "Snapshot contains 0 events after clear")


if __name__ == "__main__":
    tap = lttngtest.TapGenerator(1)

    # This test requires multiple users, so must be run as the root user
    if not (os.getuid() == 0 and lttngtest._Environment.allows_destructive()):
        tap.skip_all_remaining(
            "Need to run test as root with `LTTNG_ENABLE_DESTRUCT_TESTS` properly set to create a dummy user"
        )
        sys.exit(0)

    with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
        test_ust_multi_user(tap, test_env)
    sys.exit(0 if tap.is_successful else 1)
