#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Validate that a traced application with a (small) stack size limit can
be registered and function correctly without the application crashing.
"""

import logging
import pathlib
import resource
import sys

# Import in-tree test utils
# Modify this depending on where the test file is in the tree
test_utils_import_path = pathlib.Path(__file__).absolute().parents[2] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import bt2


def _validate_process_stack_limit(pid, stack_limit_kibibytes):
    # Double check that the processes limit is set properly
    with open("/proc/{}/limits".format(pid), "r") as f:
        for line in f.readlines():
            if line.startswith("Max stack size"):
                elements = [x for x in line.split(" ") if x != ""]
                soft, hard = (elements[3], elements[4])
                units = elements[5]
                logging.debug(
                    "PID {} stack size limits (soft/hard units): {}/{} {}".format(
                        pid, soft, hard, units
                    )
                )
                if units.strip() == "bytes":
                    soft = int(soft) / 1024
                    assert (
                        soft == stack_limit_kibibytes
                    ), "Soft limit matches test setting"
                else:
                    assert False, "Unhandled limits unit: {}".format(units)


def test_stack_size(
    tap: lttngtest.TapGenerator,
    test_env: lttngtest._Environment,
    stack_limit_kibibytes: int = 64,
) -> None:
    output_path = test_env.create_temporary_directory("trace")

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_path)
    )
    channel = session.add_channel(lttngtest.lttngctl.TracingDomain.User)
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))

    session.start()
    app = test_env.launch_wait_trace_test_application(
        1000,
        limits={resource.RLIMIT_STACK: (stack_limit_kibibytes, stack_limit_kibibytes)},
    )
    _validate_process_stack_limit(app._process.pid, stack_limit_kibibytes)
    app.trace()
    app.wait_for_tracing_done()
    app.wait_for_exit()
    session.stop()
    session.destroy()

    received, discarded = lttngtest.count_events(output_path)
    tap.test(
        received == 1000 and discarded == 0,
        "Got expected events with stack size limit {}KiB".format(stack_limit_kibibytes),
    )


def test_stack_size_map_channel(
    tap: lttngtest.TapGenerator,
    test_env: lttngtest._Environment,
    stack_limit_kibibytes: int = 64,
) -> None:
    output_path = test_env.create_temporary_directory("trace")

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_path)
    )

    channel = session.add_user_map_channel()
    client.add_trigger(
        lttngtest.lttngctl.EventRuleMatchesCondition(
            lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
        ),
        [
            lttngtest.lttngctl.IncrementMapValueTriggerAction(
                session_name=session.name,
                channel_name=channel.name,
                channel_type=channel._channel_type,
                key_template="{event_name}_count",
            )
        ],
    )

    session.start()
    app = test_env.launch_wait_trace_test_application(
        1000,
        limits={resource.RLIMIT_STACK: (stack_limit_kibibytes, stack_limit_kibibytes)},
    )
    _validate_process_stack_limit(app._process.pid, stack_limit_kibibytes)
    app.trace()
    app.wait_for_tracing_done()
    app.wait_for_exit()
    session.stop()
    conn = session.export_maps()
    try:
        map_values = {
            row["key"]: row["value"]
            for row in conn.execute(
                "SELECT key, SUM(value) AS value FROM vmap GROUP BY key"
            )
        }
    finally:
        conn.close()

    assert "tp:tptest_count" in map_values
    tap.test(
        map_values["tp:tptest_count"] == 1000,
        "Session with user map channel counted events for app with stack limit {}KiB".format(
            stack_limit_kibibytes
        ),
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format=lttngtest.utils.get_logging_format())
    # Prior to lttng-ust:28f7e9deb3cf207505b9097e25df4c5ed2d04744 : stack sizes < ~128KiB fail
    sizes = [512, 256, 128, 64]
    test_functions = [test_stack_size, test_stack_size_map_channel]
    tests = list()
    for size in sizes:
        for test_function in test_functions:
            tests.append(
                {
                    "function": test_function,
                    "kwargs": {
                        "stack_limit_kibibytes": size,
                    },
                }
            )

    tap = lttngtest.TapGenerator(len(tests))
    for test in tests:
        with lttngtest.test_environment(
            with_sessiond=True, log=tap.diagnostic
        ) as test_env:
            try:
                test["function"](tap, test_env, **test["kwargs"])
            except Exception as e:
                tap.fail("Unhandled exception: {}".format(e))
                logging.exception(
                    "Unhandled exception during test '{}', kwargs={}".format(
                        test["function"].__name__, test["kwargs"]
                    )
                )

    sys.exit(0 if tap.is_successful else 1)
