#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
End-to-end happy path test of the whole user space map channel feature:

1. Create a user space map channel with explicit attributes.

2. Confirm the returned `UserMapChannel` reports the
   effective configuration.

3. List it through Session.map_channels(), with and without a
   type filter.

4. Inspect its groups.

5. Read back the counter that an "increment map value" trigger, driven
   by an "event rule matches" condition, increments.
"""

import os
import pathlib
import sys

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common


def test_integration(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
):
    # type: (...) -> None
    val_type = lttngtest.lttngctl.MapChannelValueType.SignedIntMax
    max_key_count = 128
    update_policy = lttngtest.lttngctl.MapChannelUpdatePolicy.PerEvent
    buffer_sharing_policy = lttngtest.lttngctl.BufferSharingPolicy.PerUID

    populated = common.populate_user_map_from_events(
        test_env,
        tap,
        val_type=val_type,
        max_key_count=max_key_count,
        update_policy=update_policy,
        buffer_sharing_policy=buffer_sharing_policy,
    )
    channel = populated.channel
    session = populated.session

    # The returned channel reflects the effective configuration.
    tap.test(channel.is_enabled, "map channel is enabled")
    tap.test(
        channel.value_type == val_type,
        "map channel reports the configured value type",
    )
    tap.test(
        channel.max_key_count == max_key_count,
        "map channel reports the configured max key count",
    )
    tap.test(
        channel.update_policy == update_policy,
        "map channel reports the configured update policy",
    )
    tap.test(
        channel.buffer_sharing_policy == buffer_sharing_policy,
        "map channel reports the configured buffer sharing policy",
    )
    tap.test(
        channel.dead_process_policy is None,
        "per-user map channel has no dead process policy",
    )

    # map_channels() lists the channel, and filtering by type returns
    # the right subset.
    all_channels = list(session.map_channels())
    tap.test(
        any(c.name == channel.name for c in all_channels),
        "map_channels() lists the created channel",
    )

    user_channels = list(session.map_channels(lttngtest.lttngctl.UserMapChannel))
    tap.test(
        any(c.name == channel.name for c in user_channels),
        "`map_channels(UserMapChannel)` includes the user channel",
    )

    kernel_channels = list(session.map_channels(lttngtest.lttngctl.KernelMapChannel))
    tap.test(
        all(c.name != channel.name for c in kernel_channels),
        "`map_channels(KernelMapChannel)` excludes the user channel",
    )

    # A per-user map channel exposes a single per-user map group that
    # the current user owns (alongside the always-present channel-wide
    # shared group).
    groups = channel.groups()
    user_groups = [
        g for g in groups if g.type == lttngtest.lttngctl.MapGroupType.UserPerUser
    ]
    tap.test(
        len(user_groups) == 1,
        "per-user map channel has one per-user map group (got {})".format(
            len(user_groups)
        ),
    )
    tap.test(
        len(user_groups) == 1 and user_groups[0].owner_id == os.getuid(),
        "the per-user map group is owned by the current user",
    )

    # The counter that the trigger increments holds the expected value
    val = common.read_map_value(session, populated.key)
    tap.test(
        val == populated.expected_val,
        "counter `{}` is {} (expected {})".format(
            populated.key, val, populated.expected_val
        ),
    )

    session.destroy()


tap = lttngtest.TapGenerator(12)

with lttngtest.test_environment(
    with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=False
) as test_env:
    test_integration(test_env, tap)

sys.exit(0 if tap.is_successful else 1)
