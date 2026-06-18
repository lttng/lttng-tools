#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Increment a map channel counter from a non-"event rule matches"
condition: a "recording session rotation finishes" → "increment map
value" trigger.

Each manual rotation must bump the literal `rotations` counter by one.
"""

import pathlib
import sys

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common


def test_increment_on_rotation(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
):
    # type: (...) -> None

    # The helper builds the "recording session rotation finishes" →
    # "increment map value" trigger via the typed API and performs
    # `DEFAULT_ROTATION_COUNT` rotations.
    populated = common.populate_map_from_rotations(
        test_env, tap, lttngtest.lttngctl.UserMapChannel
    )
    session = populated.session

    val = common.read_map_value(session, populated.key)
    tap.test(
        val == populated.expected_val,
        "counter `{}` is {} after {} rotations".format(
            populated.key, populated.expected_val, populated.expected_val
        ),
    )

    # A few more rotations must keep incrementing the same counter by
    # one each
    session.rotate(wait=True)
    session.rotate(wait=True)
    val = common.read_map_value(session, populated.key)
    tap.test(
        val == populated.expected_val + 2,
        "counter `{}` is {} after two more rotations".format(
            populated.key, populated.expected_val + 2
        ),
    )

    session.destroy()


tap = lttngtest.TapGenerator(2)

with lttngtest.test_environment(
    with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=False
) as test_env:
    test_increment_on_rotation(test_env, tap)

sys.exit(0 if tap.is_successful else 1)
