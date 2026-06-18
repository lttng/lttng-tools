#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Demonstrate the map channel update policy distinction using the famous
"two triggers, same key" technique.

For each update policy, build a user space map channel with that policy,
and then install _two_ independent "event rule matches" triggers on the
tracepoint of the test application, each carrying a single "increment
map value" action that targets the _same_ counter key.

Firing the events of the application then shows how the policy decides
whether the two matching rules collapse into a single counter bump per
event or each bump the counter on their own:

`MapChannelUpdatePolicy.PerEvent`:
    The increments of both triggers collapse into one bump per event, so
    the counter equals the event count.

`MapChannelUpdatePolicy.PerRuleMatch`:
    Each matching rule bumps the counter once, so the counter equals
    twice the event count.
"""

import pathlib
import sys

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common


def test_policy(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
    update_policy,  # type: lttngtest.lttngctl.MapChannelUpdatePolicy
    expected_val,  # type: int
):
    # type: (...) -> None
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = common._create_recording_session(test_env, client)
    channel = session.add_user_map_channel(update_policy=update_policy)

    # Two independent triggers, same key template, same channel
    for _ in range(2):
        common.add_user_event_count_trigger(client, session, channel.name)

    session.start()

    app = test_env.launch_wait_trace_test_application(common.DEFAULT_EVENT_COUNT)
    app.trace()
    app.wait_for_tracing_done()
    app.wait_for_exit()

    value = common.read_map_value(
        session, "count/{}".format(common.UST_TRACEPOINT_NAME)
    )
    tap.test(
        channel.update_policy == update_policy,
        "map channel reports the configured update policy ({})".format(
            update_policy.name
        ),
    )
    tap.test(
        value == expected_val,
        "map counter `count/tp:tptest` is {} (expected {})".format(value, expected_val),
    )

    session.destroy()


tap = lttngtest.TapGenerator(4)

with lttngtest.test_environment(
    with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=False
) as test_env:
    test_policy(
        test_env,
        tap,
        lttngtest.lttngctl.MapChannelUpdatePolicy.PerEvent,
        common.DEFAULT_EVENT_COUNT,
    )
    test_policy(
        test_env,
        tap,
        lttngtest.lttngctl.MapChannelUpdatePolicy.PerRuleMatch,
        2 * common.DEFAULT_EVENT_COUNT,
    )

sys.exit(0 if tap.is_successful else 1)
