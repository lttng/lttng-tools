#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Olivier Dion <odion@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only

import mmap
import pathlib
import resource
import subprocess
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest

from common import *

"""
This test suite validates some simple scenarios of stalled buffers.

All tests work similarly by doing the following steps:

  1. Start a session

  2. Create a channel

     a) Channels are created with the per-channel buffer-allocation for better
     reproducibility.

     b) Channels must have a stall watchdog timer.

  3. Enable some events

  4. Start some producers that will generate the events.

     a) The applications are started under the GDB debugger and breakpoints are set
     on test-points within UST. The applications will crash once all breakpoints have
     been set.

  5. The session is destroyed.

     a) If sessiond failed to destroyed the session within time, the test
     failed. For better reproducibility, the timeout should be twice the
     maximum stall watchdog timer.

  6. The trace is read and compared against expected trace.

     a) The trace should not have any error.

     b) Depending on the test-point, some events might be missing.
"""


def run_simple_scenario(
    scenario,
    tap,
    test_env,
    client,
    event_record_loss_mode=lttngtest.EventRecordLossMode.Discard,
):

    # 1.
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("trace")
        )
    )

    # 2.
    channel = session.add_channel(
        lttngtest.TracingDomain.User,
        buffer_allocation_policy=lttngtest.BufferAllocationPolicy.PerChannel,
        subbuf_size=mmap.PAGESIZE,
        event_record_loss_mode=event_record_loss_mode,
    )

    # 3.
    #
    # Only trace `tp` provider because the breakpoint will be installed after
    # the user application has started. Thus, statedump events would be emitted.
    channel.add_recording_rule(lttngtest.UserTracepointEventRule(name_pattern="tp:*"))
    session.start()

    # 4.
    scenario(tap.diagnostic, test_env, session)

    # 5.
    session.destroy(timeout_s=test_env.teardown_timeout)

    # 6. Check trace stats against scenario expectations.
    stats = TraceStats(str(session.output.path))

    expectation_error = stats.unmet_scenario_expectations(scenario)

    if expectation_error:
        raise Exception(expectation_error)


fast_path_scenarios = (
    # No events are emitted since only a single producer is present.
    #
    # A single packet is emitted since the packet header was already commited
    # and the consumer will fixup that packet.
    StallScenario(
        testpoints=["lib_ring_buffer_reserve_take_ownership_succeed"],
        synopsis="""\
The producer crashes after succesfully taking the ownership of a
sub-buffer, but has not make a reservation yet.
""",
        expected_events=0,
        expected_discarded_events=0,
        expected_packets=1,
        expected_discarded_packets=0,
    ),
    # Same as above. Taking the reservation does not change anything.
    StallScenario(
        testpoints=["lib_ring_buffer_reserve_cmpxchg_succeed"],
        synopsis="""\
The producer crashes after succesfully taking the reservation of a
sub-buffer, but has not make a reservation yet.""",
        expected_events=0,
        expected_discarded_events=0,
        expected_packets=1,
        expected_discarded_packets=0,
    ),
    # Same as above.
    StallScenario(
        testpoints=["lib_ring_buffer_commit_after_record_count"],
        synopsis="""\
The producer crashes after incrementing the number of commited records,
but before incrementing the hot commit counter of the sub-buffer.
""",
        expected_events=0,
        expected_discarded_events=0,
        expected_packets=1,
        expected_discarded_packets=0,
    ),
    # There should be an event in the trace since the hot commit counter has
    # been incremented.
    StallScenario(
        testpoints=["lib_ring_buffer_commit_after_commit_count"],
        synopsis="""\
The producer crashes after incrementing the hot commit count of
the sub-buffer.
""",
        expected_events=1,
        expected_discarded_events=0,
        expected_packets=1,
        expected_discarded_packets=0,
    ),
    # Same as above.
    StallScenario(
        testpoints=["lib_ring_buffer_commit_before_clear_owner"],
        synopsis="""\
The producer crashes before succesfully releasing the ownership of a
sub-buffer.""",
        expected_events=1,
        expected_discarded_events=0,
        expected_packets=1,
        expected_discarded_packets=0,
    ),
)

# These scenarios only happen on sub-buffer boundaries.
slow_path_scenarios = (
    # Expect a non-zero amount of events since the sub-buffer is filled.
    StallScenario(
        testpoints=["lib_ring_buffer_reserve_slow_take_ownership_succeed"],
        synopsis="""\
The producer crashes after succesfully taking the ownership of a
sub-buffer (slow-path), but has not make a reservation yet.
""",
        expected_events=lambda x: x != 0,
        expected_discarded_events=0,
        expected_packets=1,
        expected_discarded_packets=0,
    ),
    # Expect a non-zero amount of events since the sub-buffer is filled.
    #
    # There should be two packets since the reservation was succesfull and enter
    # a new sub-buffer.
    StallScenario(
        testpoints=["lib_ring_buffer_reserve_slow_cmpxchg_succeed"],
        synopsis="""\
The producer crashes after succesfully taking the reservation of a
sub-buffer (slow-path), but has not make a reservation yet.""",
        expected_events=lambda x: x != 0,
        expected_discarded_events=0,
        expected_packets=2,
        expected_discarded_packets=0,
    ),
    StallScenario(
        testpoints=["lib_ring_buffer_switch_new_start_after_commit"],
        synopsis="""\
The producer crashes after succesfully comitting the packet header
of a new sub-buffer.""",
        expected_events=lambda x: x != 0,
        expected_discarded_events=0,
        expected_packets=2,
        expected_discarded_packets=0,
    ),
    StallScenario(
        testpoints=["lib_ring_buffer_check_deliver_slow_cmpxchg_succeed"],
        expected_events=lambda x: x != 0,
        expected_discarded_events=0,
        expected_packets=lambda x: x != 0,
        expected_discarded_packets=0,
    ),
    StallScenario(
        testpoints=["lib_ring_buffer_check_deliver_slow_before_wakeup"],
        synopsis="""\
The producer crashes before delivering the wakeup to the consumer.
""",
        expected_events=lambda x: x != 0,
        expected_discarded_events=0,
        expected_packets=2,
        expected_discarded_packets=0,
    ),
    StallScenario(
        producers=(1, 2),
        scheduling=[
            (1, "lib_ring_buffer_clear_owner_lazy_padding_before_ownership_release"),
            (2, "lib_ring_buffer_switch_slow_cmpxchg_succeed"),
            (1, "lib_ring_buffer_clear_owner_lazy_padding_before_take_ownership"),
        ],
        synopsis="""\
Reproduce a high-throughput scenario.

The first producer will stop just before releasing its ownership. It has already checked
that the reserve position has not changed. The second producer is then started and stopped on
the buffer switch path. Thus, the reserve position has moved and no owner exist within the
ring-buffer, other than the first producer. Then, the first producer crashes just before
taking the ownership again, after seeing that the reserve position has moved.
""",
    ),
)


def run_tests(tap, scenarios, **kwargs):
    with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:

        client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

        for scenario in scenarios:
            with tap.case(scenario.synopsis) as test_case:
                try:
                    run_simple_scenario(scenario, tap, test_env, client, **kwargs)
                except Exception as exn:
                    tap.diagnostic(
                        "Exception thrown while running test case: {}".format(exn)
                    )
                    test_case.fail()


if __name__ == "__main__":

    scenarios = fast_path_scenarios + slow_path_scenarios

    variants = (
        {"event_record_loss_mode": lttngtest.EventRecordLossMode.Discard},
        {"event_record_loss_mode": lttngtest.EventRecordLossMode.Overwrite},
    )

    tap = lttngtest.TapGenerator(len(scenarios) * len(variants))

    if not gdb_exists():
        tap.skip_all_remaining("GDB not available")
        sys.exit(0)

    # These tests make use of traps which will produce core files.
    # Disable core dumps to avoid filling disk or tmp space.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    for variant in variants:
        tap.diagnostic("Starting variant: {}".format(variant))
        run_tests(tap, scenarios, **variant)

    sys.exit(0 if tap.is_successful else 1)
