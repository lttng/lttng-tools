#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
End-to-end happy path of a Linux kernel map channel, mirroring the user
space `test_user_map_channel_integration.py`.

This test exercises the whole kernel feature on a single channel:

1. Create a kernel map channel and confirm it reports as enabled.

2. List it through Session.map_channels(), with and without a
   type filter.

3. Drive a counter from a real kernel event (an "increment map value"
   trigger on `lttng_test_filter_event`, fired by writing
   to `/proc/lttng-test-filter-event`).

4. Discover its single, ownerless `KernelGlobal` map group.

5. Read the counter back through `lttng export-maps`.

6. Confirm `lttng show-maps --type=kernel` surfaces it (and
   `--type=user` does not).

7. Clear the recording session and confirm the kernel clear path resets
   the counter to zero while preserving the key.

The whole test needs `root` access and the `lttng-test` module,
therefore the test runner skips it wholesale otherwise
(see _Environment.run_kernel_tests()).
"""

import pathlib
import shlex
import sys

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common

EVENT_COUNT = 10
KEY = "events"
NOTHING_TO_SHOW = "Nothing to show!"


# Runs `lttng show-maps` against `session` and returns its
# human-readable output.
def _show_maps(
    client,  # type: lttngtest.LTTngClient
    session,  # type: lttngtest.Session
    args,  # type: str
):
    # type: (...) -> str
    return client._run_cmd(
        "show-maps --session={} {}".format(shlex.quote(session.name), args),
        lttngtest.LTTngClient.CommandOutputFormat.HUMAN,
    )[0]


def test_kernel_integration(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
):
    # type: (...) -> None
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("map-trace")
        )
    )

    channel = session.add_kernel_map_channel()
    tap.test(channel.is_enabled, "kernel map channel is enabled")

    # map_channels() lists the channel, and filtering by type returns
    # the right subset.
    all_channels = list(session.map_channels())
    tap.test(
        any(c.name == channel.name for c in all_channels),
        "map_channels() lists the created kernel map channel",
    )
    kernel_channels = list(session.map_channels(lttngtest.lttngctl.KernelMapChannel))
    tap.test(
        any(c.name == channel.name for c in kernel_channels),
        "`map_channels(KernelMapChannel)` includes the kernel map channel",
    )
    user_channels = list(session.map_channels(lttngtest.lttngctl.UserMapChannel))
    tap.test(
        all(c.name != channel.name for c in user_channels),
        "`map_channels(UserMapChannel)` excludes the kernel map channel",
    )

    # Drive the counter from a real kernel event.
    #
    # The "event rule matches" condition enables the kernel event,
    # therefore the trigger must exist before anything emits the events.
    common.add_kernel_event_count_trigger(client, session, channel.name, KEY)
    session.start()
    common.fire_kernel_test_events(EVENT_COUNT)

    # A kernel map channel exposes a single, ownerless system-wide
    # map group.
    groups = channel.groups()
    kernel_groups = [
        g for g in groups if g.type == lttngtest.lttngctl.MapGroupType.KernelGlobal
    ]
    tap.test(
        len(kernel_groups) == 1,
        "kernel map channel has one `KernelGlobal` map group (got {})".format(
            len(kernel_groups)
        ),
    )
    tap.test(
        len(kernel_groups) == 1 and kernel_groups[0].owner_id is None,
        "the `KernelGlobal` map group has no owner",
    )

    # Read the counter back through `export-maps`.
    val = common.read_map_value(session, KEY)
    tap.test(
        val == EVENT_COUNT,
        "counter `{}` is {} (expected {})".format(KEY, val, EVENT_COUNT),
    )

    # `show-maps` surfaces the kernel counter, and the `--type` filter
    # keeps it out of the user space listing.
    kernel_output = _show_maps(client, session, "--type=kernel")
    tap.test(
        KEY in kernel_output,
        "`show-maps --type=kernel` lists the counter key `{}`".format(KEY),
    )
    tap.test(
        _show_maps(client, session, "--type=user").strip() == NOTHING_TO_SHOW,
        "`show-maps --type=user` shows nothing for a kernel-only session",
    )

    # Clearing resets the counter to zero through the kernel clear path,
    # but keeps the key listed.
    session.clear()
    vals_after = common.read_map_values(session)
    tap.test(
        vals_after.get(KEY) == 0,
        "counter `{}` is reset to 0 after clear (got {})".format(
            KEY, vals_after.get(KEY)
        ),
    )

    session.stop()
    session.destroy()


tap = lttngtest.TapGenerator(10)

common.run_kernel_test(tap, test_kernel_integration)

sys.exit(0 if tap.is_successful else 1)
