#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Olivier Dion <odion@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only

import contextlib
import itertools
import multiprocessing
import pathlib
import signal
import subprocess
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest

from common import *


"""
This test suite validates complex scenarios of stalled buffers by following a
brute-force approach. Consider the number of states that exist for P producers,
S sub-buffers and O observable side effects. This sounds like a NP-hard
problems.

As opposed to the simple tests, here we are not interested in verifying the
number of events/packets emitted/discarded, but rather ensuring that the the
session-daemon won't hang when destroying the session and that the final trace
can be consumed by babeltrace.

So the idea is to do a n-ary Cartesian product of O, where the power is P. This
new O^P set is the set of scenarios to test.

However, the set quickly become big as P increase and this is why P is limited
to 3 for now.

However, there might be a way to increase P and keeping the number of scenarios
linear, maybe even hitting a convergence point where increasing P does not add
new possible scenarios

Consider for example a scenario { O1, O2 } from the set O^2. Now consider that
P1 succesfully enter O1, but P2 failed. We say that this scenario is impossible
and this is handled by the test runner with `might_be_impossible=True` (see
common.py).

Given the previous scenario, we could mark any scenario starting with { O1, O2 }
as impossible and so for the O^3 set, { O1, O2, ON } won't be run for any
N. Same goes for scenarios in O^4 matching, { O1, O2, OM, ON } where any M and N
won't be run.

In theory, for a given impossible scenario in O^P, then |O| impossible tests
can be removed from the set O^(P + 1).

--

All tests work similarly by doing the following steps:

  1. Start a session

  2. Create a channel

     a) Channels are created with the per-channel buffer-allocation for better
     reproducibility.

     b) Channels must have a stall watchdog timer.

  3. Enable some events

  4. Start some producers that will generate the events.

     a) The applications are started under the GDB debugger and breakpoints are
     set on test-points within UST. The applications will crash whenever thesen
     test-points are reached.

  5. The session is destroyed.

     a) If sessiond failed to destroyed the session within time, the test
     failed. For better reproducibility, the timeout should be twice the
     maximum stall watchdog timer.

  6. The trace is validated.
"""


class Result:

    def __init__(self, synopsis):
        self.synopsis = synopsis
        self.logs = []
        self.state = False
        self.state_set = False
        self.reason = ""

    def append_log(self, msg):
        self.logs.append(msg)

    def summary(self):
        return "\n".join(self.logs)

    def log(self, msg):
        self.logs.append(msg)

    @property
    def skipped(self):
        return self.state is None

    @property
    def failed(self):
        return self.state is False

    def set_state(self, state):
        if self.state_set:
            raise Exception("Result state already set")
        self.state_set = True
        self.state = state

    def skip(self, reason):
        self.set_state(None)
        self.reason = reason

    def fail(self):
        self.set_state(False)

    def success(self):
        self.set_state(True)


def run_test(testpoints, event_record_loss_mode=lttngtest.EventRecordLossMode.Discard):

    scenario = StallScenario(
        testpoints=testpoints,
        synopsis="{}: event_record_loss_mode={}".format(
            " ".join(testpoints), event_record_loss_mode
        ),
        might_be_impossible=True,
    )

    result = Result(scenario.synopsis)

    result.log(
        "Starting scenario {}: event_record_loss_mode={}".format(
            testpoints, event_record_loss_mode
        )
    )

    with lttngtest.test_environment(with_sessiond=True, log=result.log) as test_env:
        try:
            client = lttngtest.LTTngClient(test_env, log=result.log)

            session = client.create_session(
                output=lttngtest.LocalSessionOutputLocation(
                    test_env.create_temporary_directory("trace")
                )
            )

            channel = session.add_channel(
                lttngtest.TracingDomain.User,
                buffer_allocation_policy=lttngtest.BufferAllocationPolicy.PerChannel,
                subbuf_size=scenario.subbuf_size,
                subbuf_count=scenario.subbuf_count,
                event_record_loss_mode=event_record_loss_mode,
            )

            channel.add_recording_rule(
                lttngtest.UserTracepointEventRule(name_pattern="tp:*")
            )

            session.start()

            try:
                scenario(result.log, test_env, session)
            except subprocess.TimeoutExpired:
                result.skip("Test case impossible")
            except Exception as exn:
                result.log("Exception thrown while running test case: {}".format(exn))
                result.fail()
            else:
                result.log("Trace available at {}".format(str(session.output.path)))

                try:
                    session.destroy(timeout_s=test_env.teardown_timeout)
                except subprocess.TimeoutExpired:
                    result.log("sessiond timeout")
                    result.fail()
                else:
                    validate_trace(str(session.output.path))
                    result.success()

        except Exception as exn:
            result.log("Uncaught exception: {}".format(exn))
            result.fail()

    if not result.state_set:
        result.fail()

    return result


all_testpoints = (
    "lib_ring_buffer_check_deliver_slow_before_set_noref",
    "lib_ring_buffer_check_deliver_slow_before_wakeup",
    "lib_ring_buffer_check_deliver_slow_cmpxchg_succeed",
    "lib_ring_buffer_commit_after_commit_count",
    "lib_ring_buffer_commit_after_record_count",
    "lib_ring_buffer_commit_before_clear_owner",
    "lib_ring_buffer_reserve_after_push_reader",
    "lib_ring_buffer_reserve_cmpxchg_succeed",
    "lib_ring_buffer_reserve_slow_after_push_reader",
    "lib_ring_buffer_reserve_slow_cmpxchg_succeed",
    "lib_ring_buffer_reserve_slow_take_ownership_succeed",
    "lib_ring_buffer_reserve_take_ownership_succeed",
    "lib_ring_buffer_switch_new_start_after_commit",
    "lib_ring_buffer_switch_old_end_after_commit",
    "lib_ring_buffer_switch_old_start_after_commit",
    "lib_ring_buffer_switch_slow_cmpxchg_succeed",
    "lib_ring_buffer_clear_owner_lazy_padding_before_ownership_release",
    # This testpoint is only reachable with non-linear scheduling.
    # "lib_ring_buffer_clear_owner_lazy_padding_before_take_ownership"
)

if __name__ == "__main__":

    scenarios = tuple(
        itertools.product(
            all_testpoints,
            all_testpoints,
            all_testpoints,
        )
    )

    variants = (
        {"event_record_loss_mode": lttngtest.EventRecordLossMode.Discard},
        {"event_record_loss_mode": lttngtest.EventRecordLossMode.Overwrite},
    )

    number_of_tests = len(scenarios) * len(variants)

    tap = lttngtest.TapGenerator(number_of_tests)

    if gdb_exists():

        def handle_result(result):

            with tap.case(result.synopsis) as test_case:
                tap.diagnostic(result.summary())
                if result.skipped:
                    test_case.skip(result.reason)
                elif result.failed:
                    test_case.fail()
                else:
                    test_case.success()

        def handle_error(exn):
            tap.fail("Unknown exception: {}".format(exn))

        pool = multiprocessing.Pool()

        for variant in variants:
            for testpoints in scenarios:
                pool.apply_async(
                    run_test,
                    args=(testpoints,),
                    kwds=variant,
                    callback=handle_result,
                    error_callback=handle_error,
                )
        pool.close()
        pool.join()
    else:
        tap.skip_all_remaining("GDB not available")

    sys.exit(0 if tap.is_successful else 1)
