#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Name <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Validate that a relayd started with LTTNG_RELAYD_DISALLOW_CLEAR causes lttng clear to fail.
"""

import pathlib
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest
import bt2


def test_relayd_disallow_clear(test_env, tap):
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session_output = lttngtest.NetworkSessionOutputLocation(
        "net://localhost:{}:{}/".format(
            test_env.lttng_relayd_control_port, test_env.lttng_relayd_data_port
        )
    )
    session = client.create_session(output=session_output)
    channel = session.add_channel(lttngtest.lttngctl.TracingDomain.User)
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule())
    session.start()

    # Run clear (should fail)
    try:
        session.clear()
        tap.fail("lttng clear should fail")
    except:
        tap.ok("lttng clear failed as expected")


if __name__ == "__main__":
    tap = lttngtest.TapGenerator(1)
    with lttngtest.test_environment(
        with_sessiond=True,
        log=tap.diagnostic,
        with_relayd=True,
        extra_env_vars={"LTTNG_RELAYD_DISALLOW_CLEAR": "1"},
    ) as test_env:
        test_relayd_disallow_clear(test_env, tap)
    sys.exit(0 if tap.is_successful else 1)
