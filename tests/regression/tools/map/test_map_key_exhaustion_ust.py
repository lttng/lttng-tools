#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Target more distinct keys than a user space map channel can hold.

Register one "increment map value" trigger per key, one key more than
the channel can hold, and check that the channel keeps the keys of the
earlier triggers and denies the key of the last registered one.

The session daemon reaches the cap through two paths, both covered here:

1. The application-driven path, where an "event rule matches" condition
   makes the application resolve its key on the session daemon when the
   rule reaches it. When the channel is full, the daemon denies the key
   and the application drops its hits. Since the trigger registrations,
   the application launch, and the recording session start each affect
   when the keys resolve, every relative order of the three is checked.

2. The session daemon-driven path, where a "recording session rotation
   finishes" condition makes the daemon perform the increment itself.
   The denied key's action then reports one execution failure per
   rotation, which `lttng list-triggers` exposes. Both ways the
   notification subsystem populates the per-session trigger list are
   checked: triggers registered after the session exists (appended to
   the list one by one) and before it exists (list rebuilt when the
   session is published to the notification subsystem).
"""

import itertools
import pathlib
import sys
from typing import Dict, List, Tuple

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common
import map_key_exhaustion_utils as utils

# Number of events the test application emits, and therefore the value
# each surviving key of the application-driven channel holds.
EVENT_COUNT = 100

# Number of manual rotations, and therefore the value each surviving key
# of the rotation-driven channel holds.
ROTATION_COUNT = 3

# Counter that the session daemon reports for a failing trigger action
# (see lttng_action_generic_add_error_query_results()).
_EXECUTION_FAILURES_COUNTER = "total execution failures"


# Sums the "total execution failures" that `lttng list-triggers` reports
# for the actions of the trigger named `trigger_name`.
def _execution_failure_count(
    client: lttngtest.LTTngClient,
    trigger_name: str,
) -> int:
    trigger = next(t for t in client.list_triggers() if t.name == trigger_name)

    return sum(
        result.value
        for action in trigger.actions
        for result in action.error_query_results
        if result.name == _EXECUTION_FAILURES_COUNTER
    )


# Runs the three steps of the application-driven path in the order named
# by `step_order`, and checks the resulting keys.
def test_event_driven(
    test_env: lttngtest._Environment,
    tap: lttngtest.TapGenerator,
    step_order: Tuple[utils.Step, ...],
) -> None:
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = common._create_recording_session(test_env, client)
    channel = session.add_user_map_channel(
        max_key_count=utils.MAX_KEY_COUNT,
        update_policy=lttngtest.lttngctl.MapChannelUpdatePolicy.PerEvent,
    )

    for step in step_order:
        if step is utils.Step.RegisterTriggers:
            for key in utils.KEYS:
                common.add_user_event_count_trigger(
                    client, session, channel.name, key=key
                )
        elif step is utils.Step.LaunchApplication:
            app = test_env.launch_wait_trace_test_application(EVENT_COUNT)
        else:
            session.start()

    app.trace()
    app.wait_for_tracing_done()
    app.wait_for_exit()

    utils.check_denied_key(
        tap, utils.format_step_order(step_order), session, EVENT_COUNT
    )
    session.destroy()


# Makes the session daemon perform the increments itself through manual
# rotations, registering the triggers before or after the recording
# session exists depending on `triggers_before_session`.
def test_rotation_driven(
    test_env: lttngtest._Environment,
    tap: lttngtest.TapGenerator,
    triggers_before_session: bool,
) -> None:
    scenario = "rotation, triggers {} session".format(
        "before" if triggers_before_session else "after"
    )
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

    # Fixed names so that the triggers can be registered before the
    # recording session and its channel exist.
    session_name = "map-exhaustion-rotation"
    channel_name = "map-exhaustion-rotation-channel"
    trigger_names = [
        "{}-{}".format(session_name, i) for i in range(len(utils.KEYS))
    ]  # type: List[str]

    # One trigger per key, each carrying a single action, so that the
    # per-action failure counter isolates the trigger whose key is
    # denied.
    def register_triggers() -> None:
        for name, key in zip(trigger_names, utils.KEYS):
            client.add_trigger(
                lttngtest.lttngctl.SessionRotationCompletedCondition(session_name),
                [
                    lttngtest.lttngctl.IncrementMapValueTriggerAction(
                        session_name=session_name,
                        channel_name=channel_name,
                        channel_type=lttngtest.lttngctl.UserMapChannel,
                        key_template=key,
                    )
                ],
                name=name,
            )

    if triggers_before_session:
        register_triggers()

    session = client.create_session(
        name=session_name,
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("map-trace")
        ),
    )
    session.add_user_map_channel(
        channel_name=channel_name, max_key_count=utils.MAX_KEY_COUNT
    )

    if not triggers_before_session:
        register_triggers()

    session.start()

    for _ in range(ROTATION_COUNT):
        session.rotate(wait=True)

    utils.check_denied_key(tap, scenario, session, ROTATION_COUNT)

    # The channel fills on the first rotation, so the trigger of the
    # denied key fails its increment on every rotation while no other
    # trigger ever fails.
    failures = {
        name: _execution_failure_count(client, name) for name in trigger_names
    }  # type: Dict[str, int]
    expected_failures = {name: 0 for name in trigger_names}
    expected_failures[trigger_names[-1]] = ROTATION_COUNT

    tap.test(
        failures == expected_failures,
        "{}: only the denied key's trigger reports a failure per rotation (expected {}, got {})".format(
            scenario, expected_failures, failures
        ),
    )

    session.destroy()


STEP_ORDERS = list(itertools.permutations(utils.Step))

tap = lttngtest.TapGenerator(2 * len(STEP_ORDERS) + 3 * 2)

for step_order in STEP_ORDERS:
    with lttngtest.test_environment(
        with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=False
    ) as test_env:
        test_event_driven(test_env, tap, step_order)

for triggers_before_session in (False, True):
    with lttngtest.test_environment(
        with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=False
    ) as test_env:
        test_rotation_driven(test_env, tap, triggers_before_session)

sys.exit(0 if tap.is_successful else 1)
