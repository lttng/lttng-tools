#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
A recording session that only ever uses map channels (and no recording,
ring-buffer channel) must not launch a consumer daemon.
"""

import pathlib
import sys

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common


def ust_consumerd_spawned(
    test_env: lttngtest._Environment,
) -> bool:
    return (
        test_env.lttng_consumerd_ust64_pid is not None
        or test_env.lttng_consumerd_ust32_pid is not None
    )


def kernel_consumerd_spawned(
    test_env: lttngtest._Environment,
) -> bool:
    return test_env.lttng_consumerd_kernel_pid is not None


def test_user_map_only_spawns_no_consumerd(
    test_env: lttngtest._Environment,
    tap: lttngtest.TapGenerator,
) -> None:

    # A user space map channel, driven to a known counter value by an
    # "event rule matches" trigger firing on the test application.
    populated_map = common.populate_user_map_from_events(test_env, tap)

    val = common.read_map_value(populated_map.session, populated_map.key)
    tap.test(
        val == populated_map.expected_val,
        "user map counter reaches {} without a consumer daemon".format(
            populated_map.expected_val
        ),
    )
    tap.test(
        not ust_consumerd_spawned(test_env),
        "a user map-only session spawns no user space consumer daemon",
    )

    populated_map.session.destroy()


def test_kernel_map_only_spawns_no_consumerd(
    test_env: lttngtest._Environment,
    tap: lttngtest.TapGenerator,
) -> None:

    # A kernel map channel, driven to a known counter value by an
    # "event rule matches" trigger firing on the events of
    # the `lttng-test` module.
    populated_map = common.populate_kernel_map_from_events(test_env, tap)

    val = common.read_map_value(populated_map.session, populated_map.key)
    tap.test(
        val == populated_map.expected_val,
        "kernel map counter reaches {} without a consumer daemon".format(
            populated_map.expected_val
        ),
    )
    tap.test(
        not kernel_consumerd_spawned(test_env),
        "a kernel map-only session spawns no kernel consumer daemon",
    )

    populated_map.session.destroy()


tap = lttngtest.TapGenerator(4)

with lttngtest.test_environment(
    with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=False
) as test_env:
    test_user_map_only_spawns_no_consumerd(test_env, tap)

common.run_kernel_test(tap, test_kernel_map_only_spawns_no_consumerd, skip_count=2)

sys.exit(0 if tap.is_successful else 1)
