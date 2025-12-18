#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2024 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Tests that the lttng command-line client emits a warning when the
the a shared memory path for a session is smaller than an estimate
of the minimum memory allocation required based on the number of
sub-buffers, the sub-buffer size, the number of CPUs, and if the
session is in snapshot mode or not.
"""

import math
import os
import pathlib
import subprocess
import sys
import time

test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest


def test_shm_warning(tap, test_env, tests):
    if os.getuid() != 0:
        tap.skip_all_remaining("This test requires root to make a temporary shm mount")
        return

    # Create a 64M shm mount. Many containers default to a shm of this size.
    # @see https://github.com/moby/moby/blob/a95a6788b59885056512c837897db20684433780/daemon/config/config.go#L39
    # @see https://docs.podman.io/en/v5.3.0/markdown/podman-run.1.html#shm-size-number-unit
    shm_path = lttngtest.TemporaryDirectory("tmp")
    p = subprocess.Popen(
        ["mount", "-t", "tmpfs", "-o", "size=64M", "tmpfs", str(shm_path.path)]
    )
    p.wait()
    if p.returncode != 0:
        tap.skip_all_remaining("Couldn't create tmpfs for testing alternate shm path")
        return

    shm_path.add_cleanup_callback(
        lambda path: subprocess.Popen(["umount", path]).wait(), str(shm_path.path)
    )

    # This may not be the CPUs available on the system, as it could be limited
    # by `-X cpu-count` or `PYTHON_CPU_COUNT` as of Python 3.13
    ncpus = os.cpu_count()
    if ncpus is None:
        tap.skip_all_remaining("Cannot determine CPU count")
        return

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    for test in tests:
        subbuf_count = 2
        subbuf_size = (
            test["target_usage_mib"] / ncpus / test["nchannels"] / subbuf_count
        )
        if not math.log(subbuf_size, 2).is_integer():
            tag.diagnostic(subbuf_size)
            tap.skip("Sub-buffer size {} is not a power of 2".format(subbuf_size))
            continue
        subbuf_size = int(subbuf_size)

        tap.diagnostic(
            "Case: nCPUs {} with {} channels of {} sub-buffer(s) of size {}M [{}] {} warn".format(
                ncpus,
                test["nchannels"],
                subbuf_count,
                subbuf_size,
                "snapshot enabled" if test["snapshot"] else "snapshot disabled",
                "should" if test["warning_expected"] else "should not",
            )
        )

        session = client.create_session(
            output=None, shm_path=shm_path.path, snapshot=test["snapshot"]
        )
        channels = []
        for channel in range(test["nchannels"]):
            channel = session.add_channel(
                lttngtest.lttngctl.TracingDomain.User,
                buffer_sharing_policy=lttngtest.lttngctl.BufferSharingPolicy.PerUID,
                subbuf_size="{}M".format(subbuf_size),
                subbuf_count=subbuf_count,
            )
            channel.add_recording_rule(
                lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
            )

        output, error = client._run_cmd("start '{}'".format(session.name))
        tap.diagnostic("\n{}\n".format(output))
        session.destroy()
        tap.test(
            ("Warning" in error and test["warning_expected"])
            or ("Warning" not in error and not test["warning_expected"]),
            "Warning {} in lttng client output when starting session".format(
                "present" if test["warning_expected"] else "not present"
            ),
        )


if __name__ == "__main__":
    tests = [
        {
            "warning_expected": False,
            "target_usage_mib": 32,
            "snapshot": False,
            "nchannels": 1,
        },
        {
            "warning_expected": True,
            "target_usage_mib": 64,
            "snapshot": False,
            "nchannels": 1,
        },
        {
            "warning_expected": True,
            "target_usage_mib": 128,
            "snapshot": False,
            "nchannels": 1,
        },
        {
            "warning_expected": False,
            "target_usage_mib": 32,
            "snapshot": True,
            "nchannels": 1,
        },
        {
            "warning_expected": True,
            "target_usage_mib": 64,
            "snapshot": True,
            "nchannels": 1,
        },
        {
            "warning_expected": False,
            "target_usage_mib": 32,
            "snapshot": False,
            "nchannels": 2,
        },
        {
            "warning_expected": True,
            "target_usage_mib": 64,
            "snapshot": False,
            "nchannels": 2,
        },
    ]

    tap = lttngtest.TapGenerator(len(tests))
    with lttngtest.test_environment(log=tap.diagnostic, with_sessiond=True) as test_env:
        test_shm_warning(tap, test_env, tests)
