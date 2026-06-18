#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Late binding of an "increment map value" trigger action to its target
map channel.

Every other map test registers the trigger _after_ creating the channel
it targets.

This test exercises the reverse order, for which the session daemon has
dedicated logic: a trigger whose action names a map channel that does
_not_ exist yet registers successfully with the action left unbound, and
the daemon binds it when that exact (domain, session, channel) is
later added.

The test:

1. Registers an "event rule matches" trigger whose "increment map value"
   action targets a named, not-yet-existing user space map channel.

2. Creates that map channel, by its exact name, which must trigger the
   late binding.

3. Starts the session and fires the events, then verifies that the
   trigger incremented the counter, proving the action bound to
   the channel.
"""

import pathlib
import sys

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common


def test_late_binding(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
):
    # type: (...) -> None
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = common._create_recording_session(test_env, client)

    # The channel the action targets, by name, before it exists
    channel_name = "late-bound-channel"
    key = "count/{}".format(common.UST_TRACEPOINT_NAME)

    # Register the trigger first: its action names a channel that does
    # not exist yet, so the action registers unbound.
    common.add_user_event_count_trigger(client, session, channel_name)

    # Now create the channel by its exact name: this is what binds the
    # pending action.
    channel = session.add_user_map_channel(channel_name=channel_name)
    tap.test(
        channel.name == channel_name,
        "the late-bound map channel `{}` was created".format(channel_name),
    )

    session.start()

    app = test_env.launch_wait_trace_test_application(common.DEFAULT_EVENT_COUNT)
    app.trace()
    app.wait_for_tracing_done()
    app.wait_for_exit()

    # If the action bound late, the counter holds the event count
    val = common.read_map_value(session, key)
    tap.test(
        val == common.DEFAULT_EVENT_COUNT,
        "counter `{}` is {} (expected {}), so the action bound to the "
        "late-created channel".format(key, val, common.DEFAULT_EVENT_COUNT),
    )

    session.destroy()


tap = lttngtest.TapGenerator(2)

with lttngtest.test_environment(
    with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=False
) as test_env:
    test_late_binding(test_env, tap)

sys.exit(0 if tap.is_successful else 1)
