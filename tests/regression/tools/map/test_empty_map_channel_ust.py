#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
A user space map channel that holds no allocated keys (an empty map).

A map channel allocates a counter key lazily, on the first increment of
that key. Until then the channel exists but carries no keys, and a tool
must still describe it gracefully rather than fail or invent rows.

This test covers two ways a channel ends up empty:

• No trigger at all targets the channel, so nothing ever increments it.

• A trigger targets the channel but its "event rule matches" condition
  never fires (the test runs no application), so no key is allocated.

For each case it asserts, through `lttng export-maps` (see
lttng-export-maps(1)), that:

• The channel itself is present in the `channels` table (an empty map is
  still a map).

• The `keys`, `entries`, and `vmap` relations are empty for that channel
  (no key was allocated, hence no per-key rows).

• Reading any key back yields `None` rather than zero, distinguishing a
  never-allocated key from one allocated and holding zero.

The Linux kernel counterpart lives in test_empty_map_channel_kernel.py.
"""

import pathlib
import sys

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common

from empty_map_channel_utils import check_empty


def test_no_trigger(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
):
    # type: (...) -> None

    # A map channel that no trigger targets: it can never allocate a key
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = common._create_recording_session(test_env, client)
    channel = session.add_user_map_channel(channel_name="untouched")
    session.start()

    check_empty(tap, session, channel.name, "user", "no trigger")

    session.destroy()


def test_trigger_never_fires(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
):
    # type: (...) -> None

    # A map channel with an event-driven trigger, but no application
    # runs, so the condition never fires and no key is ever allocated.
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = common._create_recording_session(test_env, client)
    channel = session.add_user_map_channel(channel_name="armed-but-idle")
    common.add_user_event_count_trigger(client, session, channel.name)
    session.start()

    check_empty(tap, session, channel.name, "user", "trigger never fires")

    session.destroy()


tap = lttngtest.TapGenerator(6)

with lttngtest.test_environment(
    with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=False
) as test_env:
    test_no_trigger(test_env, tap)
    test_trigger_never_fires(test_env, tap)

sys.exit(0 if tap.is_successful else 1)
