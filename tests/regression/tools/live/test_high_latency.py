#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Test that creating a new session does not hang after destroying a live
session with multiple users in a high-latency environment.
"""

import contextlib
import os
import pathlib
import shutil
import subprocess
import sys
import time

test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest


def test(tap, test_env, delay="300ms", command_timeout_seconds=30):
    if not test_env.allows_destructive():
        tap.skip_all_remaining(
            "Need to run as root with `LTTNG_ENABLE_DESTRUCTIVE_TESTS` set properly to create a dummy user and net interface"
        )
        return

    # Start the relayd in ns2
    with open("/run/netns/ns2", "r") as f:
        os.setns(f, os.CLONE_NEWNET)
        test_env._relayd = test_env._launch_lttng_relayd()
    os.unshare(os.CLONE_NEWNET)

    # Start the sessiond in ns1
    with open("/run/netns/ns1", "r") as f:
        os.setns(f, os.CLONE_NEWNET)
        test_env._sessiond = test_env._launch_lttng_sessiond()

    (uid, user) = test_env.create_dummy_user()
    apps = []
    apps.append(
        test_env.launch_wait_trace_test_application(
            1000, wait_before_exit=True, run_as=user
        )
    )
    apps.append(
        test_env.launch_wait_trace_test_application(1000, wait_before_exit=True)
    )

    with set_delay(delay):
        client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
        output = lttngtest.NetworkSessionOutputLocation(
            "net://{}:{}:{}/".format(
                "10.0.0.12",
                test_env.lttng_relayd_control_port,
                test_env.lttng_relayd_data_port,
            )
        )
        session = client.create_session(output=output, live=True)
        channel = session.add_channel(
            lttngtest.lttngctl.TracingDomain.User,
            buffer_sharing_policy=lttngtest.lttngctl.BufferSharingPolicy.PerUID,
        )
        channel.add_recording_rule(
            lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
        )
        session.start()
        for app in apps:
            app.trace()

        # Destroy
        time.sleep(1)
        time_function(tap, session.destroy)

        client.timeout = command_timeout_seconds
        # Create a new one (check timeout)
        t1, session2 = time_function(
            tap, client.create_session, kwargs={"output": output, "live": True}
        )

        # Add channel (check timeout)
        t2, channel = time_function(
            tap,
            session2.add_channel,
            args=(lttngtest.lttngctl.TracingDomain.User,),
            kwargs={
                "buffer_sharing_policy": lttngtest.lttngctl.BufferSharingPolicy.PerUID
            },
        )

        # Add recording rule (checkout timeout)
        t3, _ = time_function(
            tap,
            channel.add_recording_rule,
            (lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"),),
        )

        # Start a new one (check timeout)
        t4, _ = time_function(tap, session2.start)

        client.timeout = None
        for app in apps:
            app.wait_for_tracing_done()
            app.touch_exit_file()
            app.wait_for_exit()

        tap.test(
            t1 < command_timeout_seconds
            and t2 < command_timeout_seconds
            and t3 < command_timeout_seconds
            and t4 < command_timeout_seconds,
            "LTTng commands took less than {}s each".format(command_timeout_seconds),
        )

    return


def time_function(tap, function, args=tuple(), kwargs=dict()):
    t_start = time.time()
    ret = function(*args, **kwargs)
    t = time.time() - t_start
    tap.diagnostic("{} ran in {}s".format(function, t))
    return (t, ret)


@contextlib.contextmanager
def create_interfaces():
    create_commands = [
        ["ip", "netns", "add", "ns1"],
        ["ip", "netns", "add", "ns2"],
        ["ip", "link", "add", "veth1", "type", "veth", "peer", "name", "veth2"],
        ["ip", "link", "set", "veth1", "netns", "ns1"],
        ["ip", "link", "set", "veth2", "netns", "ns2"],
        # addr and interfaces up in each NS
        [
            "ip",
            "netns",
            "exec",
            "ns1",
            "ip",
            "addr",
            "add",
            "10.0.0.11/24",
            "dev",
            "veth1",
        ],
        ["ip", "netns", "exec", "ns1", "ip", "link", "set", "up", "lo"],
        ["ip", "netns", "exec", "ns1", "ip", "link", "set", "up", "veth1"],
        [
            "ip",
            "netns",
            "exec",
            "ns2",
            "ip",
            "addr",
            "add",
            "10.0.0.12/24",
            "dev",
            "veth2",
        ],
        ["ip", "netns", "exec", "ns2", "ip", "link", "set", "up", "lo"],
        ["ip", "netns", "exec", "ns2", "ip", "link", "set", "up", "veth2"],
    ]
    delete_commands = [
        ["ip", "netns", "del", "ns1"],
        ["ip", "netns", "del", "ns2"],
    ]
    try:
        for create_command in create_commands:
            p = subprocess.Popen(create_command)
            p.wait()
            if p.returncode != 0:
                raise Exception(
                    "Failed to run command '{}' (code: {})".format(
                        create_command, p.returncode
                    )
                )
        yield
    finally:
        for delete_command in delete_commands:
            p = subprocess.Popen(delete_command)
            p.wait()
            if p.returncode != 0:
                raise Exception(
                    "Failed to run command '{}' (code: {})".format(
                        delete_command, p.returncode
                    )
                )


@contextlib.contextmanager
def set_delay(delay):
    create_command = [
        "ip",
        "netns",
        "exec",
        "ns2",
        "tc",
        "qdisc",
        "add",
        "dev",
        "veth2",
        "root",
        "netem",
        "delay",
        delay,
    ]
    delete_command = [
        "ip",
        "netns",
        "exec",
        "ns2",
        "tc",
        "qdisc",
        "del",
        "dev",
        "veth2",
        "root",
    ]
    try:
        p = subprocess.Popen(create_command)
        p.wait()
        if p.returncode != 0:
            raise Exception(
                "Failed to run command '{}' (code: {})".format(
                    create_command, p.returncode
                )
            )
        yield
    finally:
        p = subprocess.Popen(delete_command)
        p.wait()
        if p.returncode != 0:
            raise Exception(
                "Failed to run command '{}' (code: {})".format(
                    delete_command, p.returncode
                )
            )


if __name__ == "__main__":
    tap = lttngtest.TapGenerator(1)
    if os.getuid() != 0:
        tap.skip_all_remaining("Need root")
        sys.exit(0)

    if sys.version_info < (3, 12):
        tap.missing_platform_requirement("Requires Python 3.12+")

    if not shutil.which("ip"):
        tap.missing_platform_requirement("`ip` is required")

    if not shutil.which("tc"):
        tap.missing_platform_requirement("`tc` is required")

    with create_interfaces():
        with lttngtest.test_environment(
            log=tap.diagnostic, with_relayd=False, with_sessiond=False
        ) as test_env:
            test(tap, test_env)

    sys.exit(0 if tap.is_successful else 1)
