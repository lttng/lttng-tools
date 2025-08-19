#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Validates that the begin and end timestamp of the packets in a session
with no events permit to infer that there were no events during the interval.
"""

import itertools
import os
import pathlib
import platform
import sys
import time

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[2] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest
import bt2


def run_test(test_env, tap):
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session_output_location = lttngtest.LocalSessionOutputLocation(
        test_env.create_temporary_directory("trace")
    )
    session = client.create_session(output=session_output_location)
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User,
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()

    # Run an app that doesn't emit events that match any of the enabled event rules
    app = test_env.launch_wait_trace_test_application(0)
    app.trace()
    time.sleep(1)
    app.wait_for_exit()
    session.stop()

    received, discarded = lttngtest.count_events(session_output_location.path)

    passed = True
    if received != 0 or discarded != 0:
        tap.diagnostic(
            "Expected 0 received and 0 discarded events, got {} and {} respectively".format(
                received, discarded
            )
        )
        passed = False

    # Steam files
    offset_begin = 32
    offset_end = 40
    timestamp_length = 8
    for file_path in session_output_location.path.glob("ust/uid/*/*/channel*"):
        with open(file_path, "rb") as f:
            f.seek(offset_begin)
            begin = int.from_bytes(
                f.read(timestamp_length), byteorder="little", signed=False
            )
            f.seek(offset_end)
            end = int.from_bytes(
                f.read(timestamp_length), byteorder="little", signed=False
            )
            duration = end - begin
            tap.diagnostic(
                "Stream file '{}' begin={}, end={}, duration={}".format(
                    file_path, begin, end, duration
                )
            )
            if begin == end:
                tap.diagnostic("Begin and end timestamps do not differ")
                passed = False

            if duration < 1_000_000_000:
                tap.diagnostic(
                    "Expected duration should be at least one second, got {}ns".format(
                        duration
                    )
                )
                passed = False

    session.destroy()
    tap.test(passed, "All checks passed")


if __name__ == "__main__":
    tap = lttngtest.TapGenerator(1)

    if platform.machine() != "x86_64":
        tap.skip_all_remaining("Only run on x86_64")
        sys.exit(0)

    if sys.maxsize <= 2**32:
        tap.skip_all_remaining("Only run on 64-bit systems")
        sys.exit(0)

    with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
        run_test(test_env, tap)

    sys.exit(0 if tap.is_successful else 1)
