#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Confirm that a full map channel silently drops new keys.

Create a user space map channel with a maximum key count smaller than
the number of distinct keys we then attempt to populate.

A single "recording session rotation finishes" trigger carrying several
"increment map value" actions writes the keys, each action targeting the
same channel with a distinct literal key. Because that condition is not
an "event rule matches" condition, the actions have no triggering
application context and accumulate into the shared counters of the
channel, where the test reads them back.

The map allocates keys per channel, not per individual map, from one
registry capped at the maximum key count, therefore the distinct keys
all draw from a single channel-wide budget: a rotation increments each
surviving key exactly once, and only the maximum number of keys survive.
"""

import pathlib
import sys

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common


def test_max_key_count(
    test_env,  # type: lttngtest._Environment
    tap,  # type: lttngtest.TapGenerator
):
    # type: (...) -> None
    MAX_KEY_COUNT = 2
    KEY_COUNT = 5

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = common._create_recording_session(test_env, client)
    channel = session.add_user_map_channel(max_key_count=MAX_KEY_COUNT)

    # A single rotation trigger carrying one increment action per
    # distinct literal key.
    #
    # All actions target the same shared user space map.
    client.add_trigger(
        lttngtest.lttngctl.SessionRotationCompletedCondition(session.name),
        [
            lttngtest.lttngctl.IncrementMapValueTriggerAction(
                session_name=session.name,
                channel_name=channel.name,
                channel_type=lttngtest.lttngctl.UserMapChannel,
                key_template="k{}".format(i),
            )
            for i in range(KEY_COUNT)
        ],
    )

    session.start()
    session.rotate(wait=True)

    vals = common.read_map_values(session)

    # Only `max_key_count` of the `KEY_COUNT` keys survive: the map
    # silently drops the rest once it is full.
    tap.test(
        len(vals) == MAX_KEY_COUNT,
        "full map drops extra keys: {} of {} keys kept".format(len(vals), KEY_COUNT),
    )

    # The map allocates keys first-come and never evicts them: once the
    # map is full, it drops new keys while the keys it already allocated
    # keep their slots.
    #
    # The actions execute in the order they were added, so the first
    # `MAX_KEY_COUNT` keys are exactly the ones that survive, each
    # incremented once.
    expected = {"k{}".format(i): 1 for i in range(MAX_KEY_COUNT)}
    tap.test(
        vals == expected,
        "the first {} keys survive, each incremented once: {}".format(
            MAX_KEY_COUNT, vals
        ),
    )

    session.destroy()


tap = lttngtest.TapGenerator(2)

with lttngtest.test_environment(
    with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=False
) as test_env:
    test_max_key_count(test_env, tap)

sys.exit(0 if tap.is_successful else 1)
