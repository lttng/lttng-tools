#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Validate that under heaving tracing load the sum of the recorded and dropped
events matches the expected output of the traced applications
"""

import concurrent.futures
import os
import pathlib
import subprocess
import sys
import time

test_utils_import_path = pathlib.Path(__file__).absolute().parents[2] / "utils"
print(test_utils_import_path)
sys.path.append(str(test_utils_import_path))

import bt2
import lttngtest


def test_high_throughput(tap, test_env, app_count=20, events_per_app=1000000):
    online_cpus = list(lttngtest.online_cpus())

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    output_path = test_env.create_temporary_directory()
    output = lttngtest.LocalSessionOutputLocation(trace_path=output_path)
    session = client.create_session(output=output)
    channel = session.add_channel(lttngtest.lttngctl.TracingDomain.Kernel)
    channel.add_recording_rule(lttngtest.KernelTracepointEventRule("lttng_test_*"))
    session.start()

    proc = subprocess.Popen(
        ["taskset", "-p", "-c", str(online_cpus[0]), str(os.getpid())]
    )
    proc.wait()
    if proc.returncode != 0:
        tap.bail_out(
            "Failed to taskset self to first online CPU `{}`: {}".format(
                online_cpus[0], proc.returncode
            )
        )
        return

    with lttngtest.kernel_module("lttng-test"):

        def submit_events(count):
            with open("/proc/lttng-test-recursive-event", "w") as f:
                f.write(str(count))

            return True

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = {
                executor.submit(submit_events, events_per_app): x
                for x in range(app_count)
            }

            for future in concurrent.futures.as_completed(futures):
                index = futures[future]
                tap.diagnostic("Job {} done: {}".format(index, future.result()))

        session.stop()
        session.destroy()

    # There is a single lttng_test_recursive_event per app run not counted in events_per_app
    expected = app_count * (events_per_app + 1)
    received = 0
    discarded = 0
    for msg in bt2.TraceCollectionMessageIterator(str(output_path)):
        if type(msg) is bt2._EventMessageConst:
            received += 1
            continue

        if type(msg) is bt2._DiscardedEventsMessageConst:
            discarded += msg.count

    total = received + discarded
    tap.diagnostic(
        "received={}, discarded={}, total={}, expected={}".format(
            received, discarded, total, expected
        )
    )
    tap.test(
        total == expected,
        "Total events {} match expected total {}".format(total, expected),
    )


if __name__ == "__main__":
    tap = lttngtest.TapGenerator(1)
    if not lttngtest._Environment.run_kernel_tests():
        tap.skip_all_remaining("Kernel tests not enabled")
        sys.exit(0)

    with lttngtest.test_environment(
        log=tap.diagnostic, with_sessiond=True, enable_kernel_domain=True
    ) as test_env:
        test_high_throughput(tap, test_env)
    sys.exit(0 if tap.is_successful else 1)
