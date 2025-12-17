#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only

import pathlib
import sys
from typing import Optional

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest
import bt2

from trace_format_helpers import (
    check_ctf2_trace_smoketest,
    check_trace_event_counts,
    test_local_trace_all_formats,
)


def capture_local_ust_trace(environment, trace_format=None):
    # type: (lttngtest._Environment, Optional[lttngtest.TraceFormat]) -> pathlib.Path
    session_output_location = lttngtest.LocalSessionOutputLocation(
        environment.create_temporary_directory("ctf2-trace")
    )
    client = lttngtest.LTTngClient(environment, log=tap.diagnostic)

    session = client.create_session(
        output=session_output_location, trace_format=trace_format
    )
    tap.diagnostic("Created session `{session_name}`".format(session_name=session.name))

    channel = session.add_channel(lttngtest.TracingDomain.User)
    tap.diagnostic("Created channel `{channel_name}`".format(channel_name=channel.name))

    test_app = environment.launch_wait_trace_test_application(10)
    test_app.taskset_anycpu()

    # Only track the test application
    session.user_vpid_process_attribute_tracker.track(test_app.vpid)

    channel.add_recording_rule(lttngtest.UserTracepointEventRule("tp:tptest"))

    session.start()
    test_app.trace()
    test_app.wait_for_exit()
    session.stop()
    session.destroy()

    return session_output_location.path


def test_snapshot_traces():
    with lttngtest.test_environment(
        with_sessiond=True,
        log=tap.diagnostic,
    ) as test_env:
        ctf2_output_location = lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("ctf-2-trace-snapshot")
        )
        ctf_1_8_output_location = lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("ctf-1.8-trace-snapshot")
        )

        with tap.case("Capture local snapshot traces in CTF 2 and CTF 1.8 formats"):
            client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

            # Create CTF 2 session (default format)
            ctf2_session = client.create_session(snapshot=True)
            tap.diagnostic(
                "Created CTF 2 snapshot session `{session_name}`".format(
                    session_name=ctf2_session.name
                )
            )

            # Create CTF 1.8 session
            ctf_1_8_session = client.create_session(
                snapshot=True, trace_format=lttngtest.TraceFormat.CTF_1_8
            )
            tap.diagnostic(
                "Created CTF 1.8 snapshot session `{session_name}`".format(
                    session_name=ctf_1_8_session.name
                )
            )

            # Set up channels
            ctf2_channel = ctf2_session.add_channel(lttngtest.TracingDomain.User)
            ctf_1_8_channel = ctf_1_8_session.add_channel(lttngtest.TracingDomain.User)

            # Launch test application
            test_app = test_env.launch_wait_trace_test_application(10)
            test_app.taskset_anycpu()

            # Track the test application in both sessions
            ctf2_session.user_vpid_process_attribute_tracker.track(test_app.vpid)
            ctf_1_8_session.user_vpid_process_attribute_tracker.track(test_app.vpid)

            # Add recording rules
            ctf2_channel.add_recording_rule(
                lttngtest.UserTracepointEventRule("tp:tptest")
            )
            ctf_1_8_channel.add_recording_rule(
                lttngtest.UserTracepointEventRule("tp:tptest")
            )

            # Start both sessions
            ctf2_session.start()
            ctf_1_8_session.start()

            # Run test application
            test_app.trace()
            test_app.wait_for_exit()

            # Stop both sessions
            ctf2_session.stop()
            ctf_1_8_session.stop()

            # Record snapshots
            ctf2_session.record_snapshot(ctf2_output_location)
            ctf_1_8_session.record_snapshot(ctf_1_8_output_location)

            # Destroy sessions
            ctf2_session.destroy()
            ctf_1_8_session.destroy()

        # Validate CTF 2 trace metadata starts with RS (0x1e)
        with tap.case("CTF 2 trace metadata starts with RS (0x1e)"):
            metadata_files = list(ctf2_output_location.path.rglob("metadata"))

            if not metadata_files:
                raise Exception("No metadata file found in CTF 2 trace")

            with open(str(metadata_files[0]), "rb") as f:
                first_byte = f.read(1)

                if first_byte != b"\x1e":
                    raise Exception(
                        "CTF 2 metadata does not start with RS (0x1e), got: {!r}".format(
                            first_byte
                        )
                    )

        # Validate CTF 1.8 trace metadata does not start with RS (0x1e)
        with tap.case("CTF 1.8 trace metadata does not start with RS (0x1e)"):
            metadata_files = list(ctf_1_8_output_location.path.rglob("metadata"))

            if not metadata_files:
                raise Exception("No metadata file found in CTF 1.8 trace")

            with open(str(metadata_files[0]), "rb") as f:
                if f.read(1) == b"\x1e":
                    raise Exception(
                        "CTF 1.8 metadata unexpectedly starts with RS (0x1e)"
                    )

        check_ctf2_trace_smoketest(ctf2_output_location.path, tap)

        with tap.case("Decode CTF 2 trace and count events by name"):
            check_trace_event_counts(ctf2_output_location.path, {"tp:tptest": 10})

        with tap.case("Decode CTF 1.8 trace and count events by name"):
            check_trace_event_counts(ctf_1_8_output_location.path, {"tp:tptest": 10})


tap = lttngtest.TapGenerator(17)
tap.diagnostic("Test trace format generation (user space)")

version_parts = tuple(map(int, bt2.__version__.split(".")[:2]))
if version_parts < (2, 1):
    tap.missing_platform_requirement(
        "Babeltrace 2.1.0 or later is required to run the CTF 2 trace format test"
    )
    sys.exit(0)

pretty_expect_path = pretty_expect_path = (
    pathlib.Path(__file__).absolute().parents[0] / "ust-local-trace-pretty.expect"
)

test_local_trace_all_formats(
    tap=tap,
    capture_local_trace=capture_local_ust_trace,
    pretty_expect_path=pretty_expect_path,
    enable_kernel_domain=False,
    expected_events={"tp:tptest": 10},
)
test_snapshot_traces()

sys.exit(0 if tap.is_successful else 1)
