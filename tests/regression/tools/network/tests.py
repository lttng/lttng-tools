#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Kienan Stewart <kstewart@efficios.com>
#

import logging
import os
import pathlib
import platform
import subprocess
import sys
import threading
import time

# Import in-tree test utils
# Modify this depending on where the test file is in the tree
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest


def wait_for_file(path, timeout_s=60):
    # type: (pathlib.Path, int) -> None
    deadline = time.monotonic() + timeout_s
    while not path.exists():
        if time.monotonic() >= deadline:
            raise RuntimeError(
                "Timed out after {}s waiting for '{}'".format(timeout_s, path)
            )

        logging.info("Waiting for file '{}'".format(path))
        time.sleep(1)


def test_session_creation_with_relayd_interruption(
    tap, test_env, channel_count: int = 2, channel_success_count: int = 1
):
    # Note: this test does not exert any post-reconnection functionality
    if not lttngtest.utils.gdb_exists():
        tap.missing_platform_requirement("GDB required to run this test", max_skip=1)
        return

    # Tests that the sessiond doesn't assert when relayd_add_stream fails after N channels worth of streams succeeded.
    assert channel_success_count < channel_count
    test_env._relayd = test_env._launch_lttng_relayd()
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    output = lttngtest.NetworkSessionOutputLocation(
        "net://{}:{}:{}/".format(
            "localhost",
            test_env.lttng_relayd_control_port,
            test_env.lttng_relayd_data_port,
        )
    )

    session = client.create_session(output=output)
    channels = list()
    for _ in range(channel_count):
        channel = session.add_channel(lttngtest.lttngctl.TracingDomain.User)
        channel.add_recording_rule(
            lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
        )
        channels.append(channel)

    # Start an app, but don't exit
    app = test_env.launch_wait_trace_test_application(100, wait_before_exit=True)
    app.trace()
    app.wait_for_tracing_done()

    # Connect gdb to the consumerd and prep for the relayd_add_stream failure
    workdir = lttngtest.TemporaryDirectory("lttngtest_gdb")
    logging.info("Using GDB workdir: '{}'".format(str(workdir.path)))
    consumerd_pid = test_env.lttng_consumerd_get_pid(
        lttngtest.ConsumerType.UST64
        if platform.architecture()[0] == "64bit"
        else lttngtest.ConsumerType.UST32
    )
    gdb_attached_file = workdir.path / "attached"
    gdb_log_file = workdir.path / "log"
    relayd_ready_to_die_file = workdir.path / "limit_break"
    gdb_resume_file = workdir.path / "resume"
    # Per-UID channels have one stream per possible CPU, and the data
    # channels are created before the metadata channel.
    expected_breakpoint_hits = (
        channel_success_count * lttngtest.possible_cpus_array_len()
    )
    script = [
        "set logging file {}".format(str(gdb_log_file)),
        lttngtest.utils.gdb_set_logging_command(True),
        "attach {}".format(consumerd_pid),
        "break relayd_add_stream",
        "shell touch {}".format(str(gdb_attached_file)),
        "continue",
    ]
    if expected_breakpoint_hits > 0:
        script.extend(["continue"] * expected_breakpoint_hits)

    script.extend(
        [
            "shell touch {}".format(relayd_ready_to_die_file),
            # Hold the consumerd at the breakpoint until the test has
            # killed the relayd, otherwise the next streams get added.
            "shell while [ ! -e {} ]; do sleep 0.1; done".format(gdb_resume_file),
            "detach",
        ]
    )
    gdb_process, script_file = lttngtest.utils.gdb_script(script, debug=True)
    wait_for_file(gdb_attached_file)

    start_thread = threading.Thread(target=session.start)
    logging.info("Starting session in another thread")
    start_thread.start()

    wait_for_file(relayd_ready_to_die_file)

    logging.info("Terminating lttng-relayd pid {}".format(test_env._relayd.pid))
    test_env._relayd.terminate()
    logging.info("Waiting for lttng-relayd to exit")
    test_env._relayd.wait()
    logging.info("relayd exit: ret={}".format(test_env._relayd.returncode))

    logging.info("Resuming and detaching GDB")
    gdb_resume_file.touch()
    gdb_process.wait(timeout=60)

    logging.info("Waiting for session start to return")
    start_thread.join()

    # Confirm that activating and deactivating events works
    for channel in channels:
        channel.disable_recording_rules("tp:tptest")
        channel.add_recording_rule(
            lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
        )
        channel.add_recording_rule(
            lttngtest.lttngctl.UserTracepointEventRule("tp:tptest2")
        )
        try:
            test_env._sessiond.wait(timeout=1)
            assert False, "sessiond process should not be dead"
        except subprocess.TimeoutExpired:
            pass

    # Confirm that start/stop doesn't crash the sessiond
    session.stop()
    session.start()
    try:
        test_env._sessiond.wait(timeout=1)
        assert False, "sessiond process should not be dead"
    except subprocess.TimeoutExpired:
        pass

    # Quit still open traced application
    app.touch_exit_file()
    app.wait_for_exit()

    # Run another app against the broken session to check nothing crashes
    app2 = test_env.launch_wait_trace_test_application(100)
    app2.trace()
    app2.wait_for_tracing_done()
    app2.wait_for_exit()

    # Attempt a rotation
    try:
        session.rotate()
        assert False, "session rotation worked with dead relayd"
    except lttngtest.lttng.LTTngClientError as e:
        # This is an expected failure
        pass

    session.destroy()

    # Confirm that a new session works fine for basic operations
    session = client.create_session()
    for _ in range(channel_count):
        channel = session.add_channel(lttngtest.lttngctl.TracingDomain.User)
        channel.add_recording_rule(
            lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
        )

    session.start()
    app = test_env.launch_wait_trace_test_application(100)
    app.trace()
    app.wait_for_tracing_done()
    app.wait_for_exit()
    session.stop()

    tap.ok(
        "test_session_creation_with_relayd_interruption with channel_count={}, channel_success_count={}".format(
            channel_count, channel_success_count
        )
    )
