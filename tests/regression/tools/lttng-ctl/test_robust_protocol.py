#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Olivier Dion <odion@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only

import os
import pathlib
import sys

import bt2

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest

"""
This test suite validates the robustness of the ust-ctl protocol. By
pre-loading the `liblttng-ust-ctl-fuzz.so` library in the session daemon, some
LTTng ust-ctl functions are overloaded with fuzzed variants.

The variants simply call `lttng_ust_ctl_unknown_command` and assert that it
returns 0, before calling the real functions.

The `lttng_ust_ctl_unknown_command` is a special command that is not understood
by the client (the user application). It sends a payload and a file-descriptor
to the application. It then verifies that the client returns `LTTNG_UST_ERR_NOSYS`
(command not supported) and that the sent file descriptor was closed.

In the end, pre-loading the fuzz library will inject the unknown command before
every command sent to clients. The test suite passes if they were no errors on
the sessiond, consumerd and client sides and that the final trace is valid.
"""


# Copied from stall-buffer common.py.
def validate_trace(trace_location):
    """Validate that the trace at location `trace_location` is a valid trace.

    This is done by running the following bt2 graph on the trace:

    trace_location -> [source:ctf:fs] -> [filter:utils:muxer] ->
    [sink:utils:dummy]

    """

    inputs = []
    for dirpath, dirs, files in os.walk(trace_location):
        if "metadata" in files:
            inputs.append(dirpath)

    ctf = bt2.find_plugin("ctf")
    assert ctf

    fs = ctf.source_component_classes["fs"]
    assert fs

    utils = bt2.find_plugin("utils")
    assert utils

    dummy = utils.sink_component_classes["dummy"]
    assert dummy

    muxer = utils.filter_component_classes["muxer"]
    assert muxer

    graph = bt2.Graph()

    src = graph.add_component(fs, "source", params={"inputs": inputs})
    mux = graph.add_component(muxer, "filter")
    sink = graph.add_component(dummy, "sink")

    print(src.output_ports)
    for src_name in tuple(src.output_ports):
        print(src_name)
        print(tuple(mux.input_ports.values())[-1])
        graph.connect_ports(
            src.output_ports[src_name], tuple(mux.input_ports.values())[-1]
        )

    graph.connect_ports(mux.output_ports["out"], sink.input_ports["in"])

    graph.run()


def test_simple(tap, test_env, session):
    "All user events enabled with some contexts"

    channel = session.add_channel(
        lttngtest.TracingDomain.User,
    )

    channel.add_context(
        lttngtest.VpidContextType(),
    )

    channel.add_context(
        lttngtest.VuidContextType(),
    )

    channel.add_recording_rule(lttngtest.UserTracepointEventRule(name_pattern="*"))

    app = test_env.launch_wait_trace_test_application(100)

    # This is just for sending more messages to the application.
    session.start()
    session.stop()
    session.start()

    app.trace()
    app.wait_for_exit()

    session.rotate()

    validate_trace(str(session.output.path))


if __name__ == "__main__":

    tests = (test_simple,)

    tap = lttngtest.TapGenerator(len(tests))

    path_to_fuzz_lib = (
        pathlib.Path(__file__).absolute().parents[1] / ".libs/liblttng-ust-ctl-fuzz.so"
    )

    if not os.path.exists(str(path_to_fuzz_lib)):
        tap.bail_out(
            "Path to LTTng ust-ctl fuzz does not exists: {}".format(path_to_fuzz_lib)
        )

    os.environ["LTTNG_SESSIOND_ENV_VARS"] = "LD_PRELOAD={}".format(
        str(path_to_fuzz_lib)
    )

    with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:

        client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

        for test in tests:
            tap.diagnostic(test.__doc__)
            try:
                session = client.create_session(
                    output=lttngtest.LocalSessionOutputLocation(
                        test_env.create_temporary_directory("trace")
                    )
                )
                test(tap, test_env, session)
                tap.ok(test.__name__)
            except Exception as exn:
                tap.fail("{} - Exception: {}".format(test.__name__, exn))
            finally:
                session.destroy()

    sys.exit(0 if tap.is_successful else 1)
