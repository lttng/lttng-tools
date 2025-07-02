#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2024 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only

"""
Test that the consumerd doesn't leak file descriptor allocations in /dev/shm
when the relayd exits before instrumented applications start.

@see https://bugs.lttng.org/issues/1411
"""

import os
import pathlib
import subprocess
import sys
import time

test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest


def get_consumerd_pid(tap, parent, match_string):
    pid = None
    try:
        process = subprocess.Popen(
            ["pgrep", "-P", str(parent), "-f", match_string],
            stdout=subprocess.PIPE,
        )
        process.wait()
        output = str(process.stdout.read(), encoding="UTF-8").splitlines()
        if len(output) > 1:
            raise Exception(
                "Unexpected number of output lines (got {}): {}".format(
                    len(output), output
                )
            )
        elif len(output) == 1:
            pid = int(output[0])
    except Exception as e:
        tap.diagnostic(
            "Failed to find child process of '{}' matching '{}': '{}'".format(
                parent, match_string, str(e)
            )
        )
    return pid


def count_process_dev_shm_fds(pid):
    count = 0
    if pid is None:
        return count
    dir = os.path.join("/proc", str(pid), "fd")
    for root, dirs, files in os.walk(dir):
        for f in files:
            filename = pathlib.Path(os.path.join(root, f))
            try:
                # The symlink in /proc/PID may exist, but point to an unlinked
                # file - shm_unlink is called but either the kernel hasn't yet
                # finished the clean-up or the consumer hasn't called close()
                # on the FD yet.
                if filename.is_symlink() and str(filename.resolve()).startswith(
                    "/dev/shm/shm-ust-consumer"
                ):
                    count += 1
            except FileNotFoundError:
                # As /proc/XX/fd/ is being walked, fds may be added or removed
                continue
    return count


def count_dev_shm_fds(tap, test_env):
    consumer32_pid = get_consumerd_pid(tap, test_env._sessiond.pid, "ustconsumerd32")
    fds_consumerd32 = count_process_dev_shm_fds(consumer32_pid)
    consumer64_pid = get_consumerd_pid(tap, test_env._sessiond.pid, "ustconsumerd64")
    fds_consumerd64 = count_process_dev_shm_fds(consumer64_pid)
    return (fds_consumerd32, fds_consumerd64)


def test_fd_leak(tap, test_env, buffer_sharing_policy, kill_relayd=True):
    tap.diagnostic(
        "test_fd_leak with buffer sharing policy {}, kill relayd: {}".format(
            buffer_sharing_policy, kill_relayd
        )
    )
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    output = lttngtest.NetworkSessionOutputLocation(
        "net://localhost:{}:{}/".format(
            test_env.lttng_relayd_control_port, test_env.lttng_relayd_data_port
        )
    )

    session = client.create_session(output=output, live=True)
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User,
        buffer_sharing_policy=buffer_sharing_policy,
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule())
    session.start()

    count_post_start = count_dev_shm_fds(tap, test_env)

    # Kill the relayd
    if kill_relayd:
        test_env._terminate_relayd()

    test_env.launch_wait_trace_test_application(10)
    count_post_app1 = count_dev_shm_fds(tap, test_env)

    test_env.launch_wait_trace_test_application(10)
    count_post_app2 = count_dev_shm_fds(tap, test_env)

    test_env.launch_wait_trace_test_application(10)
    count_post_app3 = count_dev_shm_fds(tap, test_env)

    session.stop()
    session.destroy()

    # As there is not method to know exactly when the final close of the
    # shm happens (it is timing dependant from an external point of view),
    # this test iterates waiting for the post-destroy count to reach the
    # post-start count. In a failure, this will loop infinitely.
    tap.diagnostic(
        "Waiting for post-destroy shm count to drop back to post-start level"
    )
    while True:
        count_post_destroy = count_dev_shm_fds(tap, test_env)
        if count_post_destroy == count_post_start:
            break
        time.sleep(0.1)

    tap.diagnostic(
        "FD counts post-start: {}, post-destroy: {}".format(
            count_post_start, count_post_destroy
        )
    )
    tap.test(
        count_post_start == count_post_destroy,
        "Count of consumerd FDs in /dev/shm are equal after session start then after destroy",
    )

    tap.diagnostic(
        "FD counts post-app-1: {}, post-app-2: {}, post-app-3: {}".format(
            count_post_app1, count_post_app2, count_post_app3
        )
    )
    if buffer_sharing_policy == lttngtest.lttngctl.BufferSharingPolicy.PerUID:
        tap.test(
            (count_post_app1 == count_post_app2)
            and (count_post_app2 == count_post_app3),
            "Count of consumerd FDs in /dev/shm doesn't leak over several application invocations",
        )
    else:
        tap.skip(
            "Count of consumerds FDs in /dev/shm doesn't leak over several application invocations - no mechanism is available to guarantee buffer reclamation within a given time frame"
        )


tap = lttngtest.TapGenerator(8)
for kill_relayd in [True, False]:
    for buffer_sharing_policy in [
        lttngtest.lttngctl.BufferSharingPolicy.PerUID,
        lttngtest.lttngctl.BufferSharingPolicy.PerPID,
    ]:
        with lttngtest.test_environment(
            log=tap.diagnostic, with_relayd=True, with_sessiond=True
        ) as test_env:
            test_fd_leak(tap, test_env, buffer_sharing_policy, kill_relayd)

sys.exit(0 if tap.is_successful else 1)
