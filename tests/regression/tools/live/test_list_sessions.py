#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Philippe Proulx <eeppeliteloop@gmail.com>
# SPDX-License-Identifier: GPL-2.0-only

import pathlib
import sys

test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest

tap = lttngtest.TapGenerator(2)
tap.diagnostic("Test listing live sessions with Babeltrace 2")

try:
    import bt2
except ImportError:
    tap.missing_platform_requirement("`bt2` package is required")
    sys.exit(0)

if tuple(map(int, bt2.__version__.split(".")[:2])) < (2, 1):
    tap.missing_platform_requirement("Babeltrace 2.1.0 or later is required")
    sys.exit(0)


def _create_session(client, session_name, trace_format):
    # type: (lttngtest.LTTngClient, str, lttngtest.TraceFormat) -> lttngtest.Session
    session = client.create_session(
        name=session_name,
        output=client.output,
        live=True,
        trace_format=trace_format,
    )
    channel = session.add_channel(lttngtest.TracingDomain.User)
    session.start()
    return session


def _verify_session(sessions_by_name, session_name, expected_trace_format_str):
    # type: (dict[str, bt2._MapValueConst], str, str) -> None
    if session_name not in sessions_by_name:
        raise Exception(
            "Session `{}` not found in live session list".format(session_name)
        )

    actual_trace_format = sessions_by_name[session_name]["trace-format"]

    if actual_trace_format != expected_trace_format_str:
        raise Exception(
            "Trace format mismatch: expected `{}`, got `{}`".format(
                expected_trace_format_str, actual_trace_format
            )
        )


def _test_list_sessions(tap, test_env):
    # type: (lttngtest.TapGenerator, lttngtest._Environment) -> None
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    client.output = lttngtest.NetworkSessionOutputLocation(
        "net://localhost:{}:{}/".format(
            test_env.lttng_relayd_control_port, test_env.lttng_relayd_data_port
        )
    )

    # Create live sessions
    ctf_1_8_session_name = "my-ctf-1.8-live-session"
    ctf_1_8_session = _create_session(
        client, ctf_1_8_session_name, lttngtest.TraceFormat.CTF_1_8
    )
    ctf_2_session_name = "my-ctf-2-live-session"
    ctf_2_session = _create_session(
        client, ctf_2_session_name, lttngtest.TraceFormat.CTF_2
    )

    # Query the live sessions using Babeltrace 2
    query_executor = bt2.QueryExecutor(
        bt2.find_plugin("ctf").source_component_classes["lttng-live"],
        "sessions",
        params={"url": "net://localhost:{}".format(test_env.lttng_relayd_live_port)},
    )
    query_result = query_executor.query()

    # Build a map of session name to session info
    sessions_by_name = {}  # type: dict[str, bt2._MapValueConst]

    for live_session in query_result:
        tap.diagnostic(
            "Found live session `{}` with trace format `{}`".format(
                live_session["session-name"], live_session["trace-format"]
            )
        )
        sessions_by_name[str(live_session["session-name"])] = live_session

    # Verify sessions
    with tap.case("CTF 1.8 live session is listed with the expected trace format"):
        _verify_session(sessions_by_name, ctf_1_8_session_name, "ctf-1.8")

    with tap.case("CTF 2 live session is listed with the expected trace format"):
        _verify_session(sessions_by_name, ctf_2_session_name, "ctf-2.0")

    # Clean up
    client.destroy_sessions_all()


with lttngtest.test_environment(
    with_sessiond=True, with_relayd=True, log=tap.diagnostic
) as test_env:
    _test_list_sessions(tap, test_env)

sys.exit(0 if tap.is_successful else 1)
