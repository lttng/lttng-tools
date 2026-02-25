#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Olivier Dion <odion@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only

import os
import pathlib
import resource
import subprocess
import sys
import tempfile
import time

test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest

from common import *

"""
Test that ust_app_release() is not called while the application is alive.

When an application is slow to respond (e.g., stalled at a breakpoint), the
sessiond will timeout. However, ust_app_release() should only be called when
the socket is actually closed, not during the timeout.

The test proceeds as follows:

  1. Attach GDB to sessiond with a breakpoint on ust_app_release().

     a) Each time the breakpoint is hit, a marker file is appended to.

  2. Launch an application.

  3. Attach GDB to the application with a breakpoint on comm_handle_message.

     a) When hit, the breakpoint stalls for longer than the sessiond timeout.

  4. Start tracing. The application hits the breakpoint and stalls.

  5. Verify ust_app_release() was NOT called during the stall.

  6. Kill the application while it is still stalled.

  7. Verify ust_app_release() was called after the application is killed.
"""

REGISTER_TIMEOUT = 5
STALL_SECONDS = 10 * REGISTER_TIMEOUT
STALL_HIT_TIMEOUT = 60
APP_GDB_HOLD_SECONDS = 3600


def sync_wait(fifo_path):
    """Block until a byte is written to the FIFO."""
    with open(fifo_path, "r") as f:
        f.read(1)


def make_sessiond_gdb_script(pid, marker_file, ready_fifo, gdb_debug_directory):
    """
    Generate a GDB script that attaches to sessiond and counts ust_app_release()
    calls by appending to a marker file each time the breakpoint is hit.

    The ready_fifo is written to after the breakpoint is set, allowing the
    caller to synchronize.
    """
    commands = [
        "set breakpoint pending on",
        "set pagination off",
        "source {}".format(gdb_helper_script_path),
    ]

    if gdb_debug_directory:
        commands.append("set debug-file-directory {}".format(gdb_debug_directory))

    commands.extend(
        [
            "attach {}".format(pid),
            "python",
            "bps = break_testpoint('lttng_tools_testpoint_ust_app_release')",
            "if not bps:",
            "    raise gdb.GdbError('No matching ust_app_release testpoint')",
            "install_breakpoint_commands("
            "bps, {!r})".format(
                [
                    "silent",
                    "shell echo hit >> {}".format(marker_file),
                    "continue",
                ]
            ),
            "end",
            # Signal ready and continue. Backgrounded to avoid blocking on FIFO.
            "shell echo . > {} &".format(ready_fifo),
            "continue",
        ]
    )

    return commands


def make_app_gdb_script(
    pid,
    sync_fifo,
    stall_marker_file,
    start_tracing_path,
    gdb_debug_directory,
):
    """
    Generate a GDB script that attaches to the application and stops at the
    comm_handle_message testpoint.

    The sync_fifo is written to after the breakpoint is armed and the app is
    continued, allowing the caller to synchronize before starting the session.

    The stall_marker_file is appended to when the app first hits the
    comm_handle_message breakpoint.

    The app's start-tracing file is touched once breakpoints are armed so the
    test app progresses and eventually handles messages.
    """
    commands = [
        "set breakpoint pending on",
        "set pagination off",
        "handle SIGTRAP stop noprint nopass",
        "handle SIGSTOP stop noprint nopass",
        "source {}".format(gdb_helper_script_path),
    ]

    if gdb_debug_directory:
        commands.append("set debug-file-directory {}".format(gdb_debug_directory))

    commands.extend(
        [
            "attach {}".format(pid),
            "python",
            "bps = break_testpoint('lttng_ust_testpoint_comm_handle_message')",
            "if not bps:",
            "    raise gdb.GdbError('No matching comm_handle_message testpoint')",
            "install_breakpoint_commands("
            "bps, {!r})".format(
                [
                    "silent",
                    "shell echo hit >> {}".format(stall_marker_file),
                ]
            ),
            "end",
            # Start app tracing once breakpoints are armed.
            "shell touch {}".format(start_tracing_path),
            # Signal ready. Backgrounded to avoid blocking on FIFO.
            "shell echo . > {} &".format(sync_fifo),
            # Run until comm_handle_message is hit.
            "continue",
            # Keep GDB attached while inferior stays stopped at the breakpoint.
            "shell sleep {}".format(APP_GDB_HOLD_SECONDS),
        ]
    )

    return commands


def count_marker_hits(marker_file):
    """Return the number of times 'hit' appears in the marker file."""
    if not os.path.exists(marker_file):
        return 0
    with open(marker_file, "r") as f:
        return f.read().count("hit")


def wait_marker_hits(marker_file, expected, timeout=None):
    """Poll the marker file until it contains at least `expected` hits."""
    deadline = time.time() + timeout if timeout is not None else None
    while True:
        if count_marker_hits(marker_file) >= expected:
            return
        if deadline is not None and time.time() > deadline:
            raise RuntimeError("Timeout waiting for {} marker hits".format(expected))
        time.sleep(0.1)


def log_progress(tap, message):
    tap.diagnostic("[slow-test] {}".format(message))


def kill_and_wait_process(proc, name, tap, timeout_s):
    if proc is None:
        return

    try:
        if proc.poll() is None:
            log_progress(tap, "cleanup: {} still running, killing".format(name))
            proc.kill()
        proc.wait(timeout=timeout_s)
        log_progress(tap, "cleanup: {} reaped".format(name))
    except subprocess.TimeoutExpired:
        tap.diagnostic("{} did not terminate cleanly".format(name))
    except Exception as e:
        tap.diagnostic("failed while terminating {}: {}".format(name, e))


def run_scenario(tap, test_env, client):
    gdb_debug_directory = os.getenv("GDB_DEBUG_FILE_DIRECTORY")
    tmp_dir = str(test_env.lttng_home_location)
    gdb_script_dir = test_env.create_temporary_directory("gdb_scripts")

    # Marker file for counting ust_app_release() calls.
    marker_file = tempfile.mktemp(prefix="marker_", dir=tmp_dir)
    app_stall_marker = tempfile.mktemp(prefix="app_stall_", dir=tmp_dir)

    # FIFOs for synchronization with GDB.
    sessiond_ready_fifo = tempfile.mktemp(prefix="sessiond_ready_", dir=tmp_dir)
    app_sync_fifo = tempfile.mktemp(prefix="app_sync_", dir=tmp_dir)
    os.mkfifo(sessiond_ready_fifo)
    os.mkfifo(app_sync_fifo)

    session = None
    app = None
    app_gdb = None
    sessiond_gdb = None

    try:
        log_progress(tap, "run_scenario: begin")

        # 1.
        sessiond_script = str(gdb_script_dir / "sessiond.gdb")
        write_gdb_script(
            sessiond_script,
            make_sessiond_gdb_script(
                test_env._sessiond.pid,
                marker_file,
                sessiond_ready_fifo,
                gdb_debug_directory,
            ),
        )

        log_progress(tap, "starting sessiond GDB")
        sessiond_gdb = subprocess.Popen(
            ["gdb", "--nx", "--nw", "--batch", "-x", sessiond_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        # Wait for sessiond GDB to attach and set breakpoint.
        log_progress(tap, "waiting for sessiond GDB ready FIFO")
        sync_wait(sessiond_ready_fifo)
        log_progress(tap, "sessiond GDB ready")

        # 2.
        log_progress(tap, "creating session and channel")
        session = client.create_session(
            output=lttngtest.LocalSessionOutputLocation(
                test_env.create_temporary_directory("trace")
            )
        )
        channel = session.add_channel(lttngtest.TracingDomain.User)
        channel.add_recording_rule(
            lttngtest.UserTracepointEventRule(name_pattern="tp:*")
        )

        log_progress(tap, "launching wait-trace test app")
        app = test_env.launch_wait_trace_test_application(
            event_count=10,
            wait_before_exit=True,
            register_timeout_s=REGISTER_TIMEOUT,
        )
        log_progress(tap, "app launched with pid={}".format(app.vpid))

        # Sanity check: ust_app_release() should not have been called yet.
        assert count_marker_hits(marker_file) == 0

        # 3.
        app_script = str(gdb_script_dir / "app.gdb")
        write_gdb_script(
            app_script,
            make_app_gdb_script(
                app.vpid,
                app_sync_fifo,
                app_stall_marker,
                app.start_tracing_path,
                gdb_debug_directory,
            ),
        )

        log_progress(tap, "starting app GDB")
        app_gdb = subprocess.Popen(
            ["gdb", "--nx", "--nw", "--batch", "-x", app_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        # Wait for app GDB to attach and arm the breakpoint.
        log_progress(tap, "waiting for app GDB ready FIFO")
        sync_wait(app_sync_fifo)
        log_progress(tap, "app GDB ready")

        # 4.
        #
        # Starting the session sends commands to the app. The app is expected to
        # stop at comm_handle_message.
        log_progress(tap, "starting session")
        session.start()
        log_progress(tap, "session started")

        # 5.
        #
        # First confirm that the app reached the stall breakpoint.
        log_progress(
            tap,
            "waiting for comm_handle_message stall marker (timeout={}s)".format(
                STALL_HIT_TIMEOUT
            ),
        )
        wait_marker_hits(app_stall_marker, 1, timeout=STALL_HIT_TIMEOUT)
        tap.diagnostic("app comm_handle_message stall breakpoint reached")

        before_stall_wait_count = count_marker_hits(marker_file)
        tap.diagnostic(
            "ust_app_release count before stall wait: {}".format(
                before_stall_wait_count
            )
        )
        if before_stall_wait_count != 0:
            raise RuntimeError(
                "ust_app_release called {} times before stall wait (expected 0)".format(
                    before_stall_wait_count
                )
            )

        # Keep the app stalled for longer than the register timeout and ensure no
        # release happened during this period.
        log_progress(tap, "sleeping {}s during stall window".format(STALL_SECONDS))
        time.sleep(STALL_SECONDS)
        log_progress(tap, "stall window sleep complete")

        after_stall_wait_count = count_marker_hits(marker_file)
        tap.diagnostic(
            "ust_app_release count after stall wait: {}".format(after_stall_wait_count)
        )
        if after_stall_wait_count != 0:
            raise RuntimeError(
                "ust_app_release called {} times during stall (expected 0)".format(
                    after_stall_wait_count
                )
            )

        # 6.
        #
        # Kill the app while it is stopped at the breakpoint.
        log_progress(tap, "killing app pid={}".format(app.vpid))
        try:
            app._process.kill()
        except ProcessLookupError:
            # Process already exited.
            log_progress(tap, "app already exited before kill")
            pass

        # Looping until we see the app release to happen. This can be long on
        # slow system thus the infinite loop.
        time.sleep(STALL_SECONDS)
        while True:
            time.sleep(1)

            post_kill_count = count_marker_hits(marker_file)
            tap.diagnostic(
                "ust_app_release count after app kill: {}".format(post_kill_count)
            )
            if post_kill_count == 1:
                break
    finally:
        log_progress(tap, "cleanup: begin")

        # Ensure app-side GDB is not left behind first; app may still be ptrace-controlled.
        if app_gdb is not None:
            log_progress(tap, "cleanup: reaping app GDB")
            kill_and_wait_process(app_gdb, "App GDB", tap, timeout_s=5)

        # Ensure the app is gone before destroying the session.
        if app is not None:
            if app.status is None:
                log_progress(tap, "cleanup: killing app pid={}".format(app.vpid))
                try:
                    app._process.kill()
                except ProcessLookupError:
                    log_progress(tap, "cleanup: app already exited")
                    pass
            log_progress(tap, "cleanup: waiting for app process to terminate")
            try:
                app._process.wait(timeout=10)
                log_progress(tap, "cleanup: app process terminated")
            except subprocess.TimeoutExpired:
                tap.diagnostic("App process did not terminate after kill")

        # Stop and destroy session after all traced processes are gone.
        if session is not None:
            try:
                log_progress(tap, "cleanup: session.stop()")
                session.stop()
                log_progress(tap, "cleanup: session.stop() done")
            except Exception as e:
                tap.diagnostic("session.stop() failed during cleanup: {}".format(e))
            try:
                log_progress(tap, "cleanup: session.destroy()")
                session.destroy(timeout_s=test_env.teardown_timeout)
                log_progress(tap, "cleanup: session.destroy() done")
            except Exception as e:
                tap.diagnostic("session.destroy() failed during cleanup: {}".format(e))

        # Ensure sessiond-side GDB is not left behind.
        if sessiond_gdb is not None:
            log_progress(tap, "cleanup: reaping sessiond GDB")
            kill_and_wait_process(sessiond_gdb, "Sessiond GDB", tap, timeout_s=5)

        log_progress(tap, "cleanup: end")


if __name__ == "__main__":
    tap = lttngtest.TapGenerator(1)

    if not gdb_exists():
        tap.missing_platform_requirement("GDB not available")

    # Disable core dumps. GDB may cause traps which would otherwise produce
    # core files and fill up disk space.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
        client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

        with tap.case(
            "Slow response does not trigger premature ust_app_release"
        ) as test_case:
            try:
                run_scenario(tap, test_env, client)
            except Exception as e:
                tap.diagnostic("Exception: {}".format(e))
                test_case.fail()

    sys.exit(0 if tap.is_successful else 1)
