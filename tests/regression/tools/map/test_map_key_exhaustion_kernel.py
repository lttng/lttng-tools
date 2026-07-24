#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Target more distinct keys than a kernel map channel can hold.

The kernel counterpart of the application-driven cases of
test_map_key_exhaustion_ust.py: register one "increment map value"
trigger per key, one key more than the channel can hold, then fire the
events of the `lttng-test` module.

The kernel tracer allocates a key slot when it instantiates an enabler's
event counter and silently refuses the extra key once the channel is
full (see the `-EMFILE` path of LTTng-modules'
_lttng_kernel_event_create()): the surviving keys hold their expected
value and the denied key is simply absent. Both relative orders of the
trigger registrations and the recording session start are checked since
each affects when the keys resolve.

The rotation path of the user space test has no kernel equivalent
because the session daemon cannot allocate a key in a kernel counter
itself.
"""

import pathlib
import sys
from typing import Tuple

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common
import map_key_exhaustion_utils as utils

# Number of events the `lttng-test` module emits, and therefore the
# value each surviving key holds.
EVENT_COUNT = 100

STEP_ORDERS = [
    (utils.Step.RegisterTriggers, utils.Step.StartSession),
    (utils.Step.StartSession, utils.Step.RegisterTriggers),
]


# Runs the two steps in the order named by `step_order`, and checks the
# resulting keys.
def _test_step_order(
    test_env: lttngtest._Environment,
    tap: lttngtest.TapGenerator,
    step_order: Tuple[utils.Step, ...],
) -> None:
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = common._create_recording_session(test_env, client)
    channel = session.add_kernel_map_channel(
        max_key_count=utils.MAX_KEY_COUNT,
        update_policy=lttngtest.lttngctl.MapChannelUpdatePolicy.PerEvent,
    )

    for step in step_order:
        if step is utils.Step.RegisterTriggers:
            for key in utils.KEYS:
                common.add_kernel_event_count_trigger(
                    client, session, channel.name, key
                )
        else:
            session.start()

    common.fire_kernel_test_events(EVENT_COUNT)
    utils.check_denied_key(
        tap, utils.format_step_order(step_order), session, EVENT_COUNT
    )
    session.destroy()


def test_key_exhaustion_kernel(
    test_env: lttngtest._Environment,
    tap: lttngtest.TapGenerator,
) -> None:
    for step_order in STEP_ORDERS:
        _test_step_order(test_env, tap, step_order)


TEST_COUNT = 2 * len(STEP_ORDERS)
tap = lttngtest.TapGenerator(TEST_COUNT)

# The kernel cases need `root` and the `lttng-test` module.
common.run_kernel_test(tap, test_key_exhaustion_kernel, skip_count=TEST_COUNT)

sys.exit(0 if tap.is_successful else 1)
