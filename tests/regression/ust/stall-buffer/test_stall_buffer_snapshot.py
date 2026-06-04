#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import mmap
import pathlib
import resource
import sys
import time

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest

from common import *

"""
This test validates that the watchdog timer performs the stalled sub-buffer
fixup for snapshot sessions.

Recording a snapshot does not, on its own, recover a stalled sub-buffer: the
snapshot path samples the buffer positions and writes an empty packet when the
writer head and the consumed position are in the same sub-buffer. The only thing
that can make the stalled event appear in a snapshot is the watchdog timer
committing and delivering the sub-buffer while the session keeps running.

This makes a snapshot session a clean way to isolate the watchdog timer: unlike
a rotation or a stop, recording a snapshot never triggers the fixup itself.

The tests proceed as follows:

  1. Start a snapshot session

  2. Create a channel

     a) Channels are created with per-channel buffer allocation for better
     reproducibility.

     b) The watchdog timer is either enabled or disabled.

  3. Enable some events

  4. Start producers that stall a sub-buffer (see common.StallScenario).

  5. Record a snapshot.

     a) With the watchdog timer enabled, it is given time to perform the fixup
     before the snapshot is recorded.

  6. The snapshot is read.

     a) With the watchdog timer enabled, the stalled event must have been
     recovered.

     b) With the watchdog timer disabled, nothing recovers the stall, so the
     event must be absent.

  7. The session is destroyed.
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
        ),
        snapshot=True,
    )

    try:
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
        channel.add_recording_rule(
            lttngtest.UserTracepointEventRule(name_pattern="tp:*")
        )
        session.start()

        # 4.
        scenario(tap.diagnostic, test_env, session)

        # 5. Wait before recording the snapshot so that both cases observe the
        # buffers in the same quiescent state, leaving the watchdog timer as the
        # only differing factor between them. With the timer enabled, this is
        # also the time it is given to perform the fixup; wait 10 times its
        # period. If the test fails with the watchdog timer enabled it likely
        # means the load on the system slowed down the fixup algorithm.
        time.sleep(10 * (watchdog_timer_period_us / 1000000))

        session.record_snapshot()

        # 6.
        stats = TraceStats(str(session.output.path))

        if disable_watchdog:
            # Nothing recovers the stall: recording a snapshot does not perform
            # the fixup, and the watchdog timer is off. The TraceStats/StallScenario
            # infrastructure is bypassed here since those describe the
            # expectations when recovery is successful.
            if stats.events != 0:
                tap.diagnostic(
                    "Expected no recovered event with the watchdog timer disabled, got {}".format(
                        stats.events
                    )
                )
                dump_trace_contents(session.output.path, tap)
                raise Exception("Stall recovered without the watchdog timer")
        else:
            expectation_error = stats.unmet_scenario_expectations(scenario)
            if expectation_error:
                tap.diagnostic(
                    "Trace stats did not meet scenario expectations: dumping contents"
                )
                dump_trace_contents(session.output.path, tap)
                raise Exception(expectation_error)
    finally:
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
        # The producer stalls a sub-buffer holding a single event. Only the
        # watchdog timer can make that event readable through a snapshot, so the
        # event count is the meaningful signal; the snapshot packet count is
        # left unconstrained.
        StallScenario(
            testpoints=["lib_ring_buffer_reserve_take_ownership_succeed"],
            expected_events=1,
            expected_discarded_events=0,
        ),
    )

    variants = (
        {"event_record_loss_mode": lttngtest.EventRecordLossMode.Discard},
        {"event_record_loss_mode": lttngtest.EventRecordLossMode.Overwrite},
    )

    # Times two because we are testing with the watchdog timer disabled also.
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
