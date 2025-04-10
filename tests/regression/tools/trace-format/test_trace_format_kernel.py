#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only

import pathlib
import sys
import os
import contextlib
import subprocess

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest
import bt2

from trace_format_helpers import (
    test_local_trace_all_formats,
)


@contextlib.contextmanager
def kernel_module(module_name):
    """
    Context manager to load a kernel module and unload it when it goes out of scope.
    """
    try:
        subprocess.run(["modprobe", module_name], check=True)
        yield module_name
    finally:
        subprocess.run(["modprobe", "-r", module_name], check=True)


def capture_local_kernel_trace(environment):
    # type: (lttngtest._Environment) -> pathlib.Path
    session_output_location = lttngtest.LocalSessionOutputLocation(
        environment.create_temporary_directory("trace")
    )

    client = lttngtest.LTTngClient(environment, log=tap.diagnostic)

    session = client.create_session(output=session_output_location)
    tap.diagnostic("Created session `{session_name}`".format(session_name=session.name))

    channel = session.add_channel(lttngtest.TracingDomain.User)
    tap.diagnostic("Created channel `{channel_name}`".format(channel_name=channel.name))

    # Only track the events emitted by this process
    session.kernel_vpid_process_attribute_tracker.track(os.getpid())

    channel.add_recording_rule(
        lttngtest.KernelTracepointEventRule("lttng_test_filter_event")
    )

    session.start()

    with kernel_module("lttng-test"):
        tap.diagnostic("Loaded kernel module `lttng-test`")
        tap.diagnostic("Writing to /proc/lttng-test-filter-event")
        with open("/proc/lttng-test-filter-event", "w") as f:
            f.write("10")

        session.stop()
        session.destroy()

    return session_output_location.path


tap = lttngtest.TapGenerator(10)
tap.diagnostic("Test trace format generation (kernel)")

version_parts = tuple(map(int, bt2.__version__.split(".")[:2]))
if version_parts < (2, 1):
    tap.skip_all_remaining(
        "Skipping test: Babeltrace 2.1.0 or later is required to run the trace format test"
    )
    sys.exit(0)

if not lttngtest._Environment.run_kernel_tests():
    tap.skip_all_remaining(
        "Skipping test: Kernel tests are not enabled, skipping trace format test"
    )
    sys.exit(0)

pretty_expect_path = pretty_expect_path = (
    pathlib.Path(__file__).absolute().parents[0] / "kernel-local-trace-pretty.expect"
)
test_local_trace_all_formats(
    tap=tap,
    capture_local_trace=capture_local_kernel_trace,
    pretty_expect_path=pretty_expect_path,
    enable_kernel_domain=True,
    expected_events={"lttng_test_filter_event": 10},
)

sys.exit(0 if tap.is_successful else 1)
