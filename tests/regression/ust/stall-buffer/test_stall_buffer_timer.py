#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Olivier Dion <odion@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only

import mmap
import pathlib
import resource
import sys
import time

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest

from common import *

"""
This test suite ensures that the watchdog timer can perform the fixup.

Unlike other stall buffer test suites where the fixup is done when the session
is destroyed, here we aim to validate that the watchdog timer performs the fixup.

The tests proceed as follows:

  1. Start a session

  2. Create a channel

     a) Channels are created with per-channel buffer allocation for better
     reproducibility.

     b) Channels must include a stall watchdog timer.

  3. Enable some events

  4. Start some producers that will generate the events.

     a) The applications are started under the GDB debugger, and breakpoints are set
     at test points within UST. The applications will crash once all breakpoints
     have been reached.

  5. The session is rotated, and we wait for this operation to complete.

  6. The trace is read and compared against the expected trace.

     a) The trace should not contain any errors.

     b) Depending on the test point, some events might be missing.

  7. The session is destroyed
"""


def run_scenario(
    scenario,
    tap,
    test_env,
    client,
    disable_watchdog,
    event_record_loss_mode=lttngtest.EventRecordLossMode.Discard,
):

    watchdog_timer_period_us = 100000

    # 1.
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("trace")
        )
    )

    # 2.
    if disable_watchdog:
        channel_watchdog_timer_period_us = 0
    else:
        channel_watchdog_timer_period_us = watchdog_timer_period_us

    channel = session.add_channel(
        lttngtest.TracingDomain.User,
        buffer_allocation_policy=lttngtest.BufferAllocationPolicy.PerChannel,
        subbuf_size=mmap.PAGESIZE,
        event_record_loss_mode=event_record_loss_mode,
        watchdog_timer_period_us=channel_watchdog_timer_period_us,
    )

    # 3.
    #
    # Only trace `tp` provider because the breakpoint will be installed after
    # the user application has started. Thus, statedump events would be emitted.
    channel.add_recording_rule(lttngtest.UserTracepointEventRule(name_pattern="tp:*"))
    session.start()

    # 4.
    scenario(tap.diagnostic, test_env, session)

    # 5. Wait for the watchdog timer to be run.
    #
    # If the stall fixup algorithm failed or the watchdog timer is not
    # triggered, this will block indefinitely.
    #
    # But first, we sleep for 10 period of the watchdog timer.  This ought to
    # give enough time for the stall fixup to happen.
    time.sleep(10 * (watchdog_timer_period_us / 1000000))
    session.rotate(wait=False)

    stats = TraceStats(str(session.output.path))

    # 6.
    expectation_error = stats.unmet_scenario_expectations(scenario)

    if disable_watchdog:
        if not expectation_error:
            tap.diagnostic("Expection an error when disabling watchdog timer")
            dump_trace_contents(session.output.path, tap)
            raise Exception("")
    elif expectation_error:
        tap.diagnostic(
            "Trace stats did not meet scenario expectations: dumping contents"
        )
        dump_trace_contents(session.output.path, tap)
        raise Exception(expectation_error)

    # 7.
    session.destroy(timeout_s=test_env.teardown_timeout)


def run_tests(tap, scenarios, **kwargs):
    with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:

        client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

        for scenario in scenarios:
            with tap.case("watchdog-timer enabled: {}".format(kwargs)) as test_case:
                try:
                    run_scenario(scenario, tap, test_env, client, False, **kwargs)
                except Exception as exn:
                    tap.diagnostic(
                        "Exception thrown while running test case: {}".format(exn)
                    )
                    test_case.fail()
            with tap.case("watchdog-timer disabled: {}".format(kwargs)) as test_case:
                try:
                    run_scenario(scenario, tap, test_env, client, True, **kwargs)
                except Exception as exn:
                    tap.diagnostic(
                        "Exception thrown while running test case: {}".format(exn)
                    )
                    test_case.fail()


if __name__ == "__main__":

    scenarios = (
        StallScenario(
            testpoints=["lib_ring_buffer_reserve_take_ownership_succeed"],
            expected_events=1,
            expected_discarded_events=0,
            expected_packets=2,  # Since a rotation is done, we expect two packets.
            expected_discarded_packets=0,
        ),
    )

    variants = (
        {"event_record_loss_mode": lttngtest.EventRecordLossMode.Discard},
        {"event_record_loss_mode": lttngtest.EventRecordLossMode.Overwrite},
    )

    # Times two because we are testing with watchdog timer disabled also.
    tap = lttngtest.TapGenerator(len(scenarios) * len(variants) * 2)

    if not gdb_exists():
        tap.missing_platform_requirement("GDB not available")

    # These tests make use of traps which will produce core files.
    # Disable core dumps to avoid filling disk or tmp space.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    for variant in variants:
        tap.diagnostic("Starting variant: {}".format(variant))
        run_tests(tap, scenarios, **variant)

    sys.exit(0 if tap.is_successful else 1)
