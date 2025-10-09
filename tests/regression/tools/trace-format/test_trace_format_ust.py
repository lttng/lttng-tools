#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only

import pathlib
import sys

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


def capture_local_ust_trace(environment):
    # type: (lttngtest._Environment) -> pathlib.Path
    session_output_location = lttngtest.LocalSessionOutputLocation(
        environment.create_temporary_directory("ctf2-trace")
    )
    client = lttngtest.LTTngClient(environment, log=tap.diagnostic)

    session = client.create_session(output=session_output_location)
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


def test_snapshot_trace_valid_ctf2():
    with lttngtest.test_environment(
        with_sessiond=True,
        log=tap.diagnostic,
        extra_env_vars={"LTTNG_EXPERIMENTAL_FORCE_CTF_2": "1"},
    ) as test_env:
        session_output_location = lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("ctf2-trace-snapshot")
        )

        with tap.case("Capture local snapshot trace in CTF2 format"):
            client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

            session = client.create_session(snapshot=True)
            tap.diagnostic(
                "Created snapshot session `{session_name}`".format(
                    session_name=session.name
                )
            )

            channel = session.add_channel(lttngtest.TracingDomain.User)
            tap.diagnostic(
                "Created channel `{channel_name}`".format(channel_name=channel.name)
            )

            test_app = test_env.launch_wait_trace_test_application(10)
            test_app.taskset_anycpu()

            # Only track the test application
            session.user_vpid_process_attribute_tracker.track(test_app.vpid)

            channel.add_recording_rule(lttngtest.UserTracepointEventRule("tp:tptest"))

            session.start()
            test_app.trace()
            test_app.wait_for_exit()
            session.stop()

            session.record_snapshot(session_output_location)
            session.destroy()

        check_ctf2_trace_smoketest(session_output_location.path, tap)
        with tap.case("Decode trace and count events by name"):
            check_trace_event_counts(session_output_location.path, {"tp:tptest": 10})


def test_live_tracing_is_disallowed_for_ctf2():
    with lttngtest.test_environment(
        with_sessiond=True,
        log=tap.diagnostic,
        extra_env_vars={"LTTNG_EXPERIMENTAL_FORCE_CTF_2": "1"},
    ) as test_env:
        network_output = lttngtest.NetworkSessionOutputLocation(
            "net://localhost:{}:{}/".format(
                test_env.lttng_relayd_control_port, test_env.lttng_relayd_data_port
            )
        )

        with tap.case_raises(
            "Live tracing is disallowed with CTF2", lttngtest.lttng.LTTngClientError
        ):
            client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
            client.create_session(live=True, output=network_output)


def test_streaming_is_disallowed_for_ctf2():
    with lttngtest.test_environment(
        with_sessiond=True,
        log=tap.diagnostic,
        extra_env_vars={"LTTNG_EXPERIMENTAL_FORCE_CTF_2": "1"},
    ) as test_env:

        network_output = lttngtest.NetworkSessionOutputLocation(
            "net://localhost:{}:{}/".format(
                test_env.lttng_relayd_control_port, test_env.lttng_relayd_data_port
            )
        )

        with tap.case_raises(
            "Trace streaming is disallowed with CTF2", lttngtest.lttng.LTTngClientError
        ):

            client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
            client.create_session(output=network_output)


def test_snapshot_network_output_disallowed_for_ctf2():
    with lttngtest.test_environment(
        with_sessiond=True,
        log=tap.diagnostic,
        with_relayd=True,
        extra_env_vars={"LTTNG_EXPERIMENTAL_FORCE_CTF_2": "1"},
    ) as test_env:
        network_output = lttngtest.NetworkSessionOutputLocation(
            "net://localhost:{}:{}/".format(
                test_env.lttng_relayd_control_port, test_env.lttng_relayd_data_port
            )
        )

        client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

        session = client.create_session(snapshot=True)
        tap.diagnostic(
            "Created snapshot session `{session_name}`".format(
                session_name=session.name
            )
        )

        channel = session.add_channel(lttngtest.TracingDomain.User)
        tap.diagnostic(
            "Created channel `{channel_name}`".format(channel_name=channel.name)
        )

        test_app = test_env.launch_wait_trace_test_application(10)
        test_app.taskset_anycpu()

        # Only track the test application
        session.user_vpid_process_attribute_tracker.track(test_app.vpid)

        # Enable all user space events, the default for a user tracepoint event rule.
        channel.add_recording_rule(lttngtest.UserTracepointEventRule())

        session.start()
        test_app.trace()
        test_app.wait_for_exit()
        session.stop()

        with tap.case_raises(
            "Capturing a snapshot to a network output is disallowed with CTF2",
            lttngtest.lttng.LTTngClientError,
        ):
            session.record_snapshot(network_output)


tap = lttngtest.TapGenerator(17)
tap.diagnostic("Test trace format generation (user space)")

version_parts = tuple(map(int, bt2.__version__.split(".")[:2]))
if version_parts < (2, 1):
    tap.missing_platform_requirement(
        "Babeltrace 2.1.0 or later is required to run the CTF2 trace format test"
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
test_snapshot_trace_valid_ctf2()
test_live_tracing_is_disallowed_for_ctf2()
test_streaming_is_disallowed_for_ctf2()
test_snapshot_network_output_disallowed_for_ctf2()

sys.exit(0 if tap.is_successful else 1)
