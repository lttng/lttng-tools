#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Olivier Dion <odion@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only

"""
Test trigger start and stop session actions using event-rule-matches condition.

The tests proceed as follows:

  1. Create a userspace tracing session and enable `tp:tptest`.

  2. Register a trigger with an `event-rule-matches` condition on `tp:tptest`.

     a) In the first test, the action list is: `start-session`, then `notify`.

     b) In the second test, the action list is: `stop-session`, then `notify`.

  3. Start `notification-client` and wait for registration synchronization.

  4. Emit UST events from `gen-ust-events` to satisfy the trigger condition.

  5. Wait for `notification-client` to receive the trigger notification.

  6. Verify the target session state transition.

     a) `start-session` test ensures the session becomes active.

     b) `stop-session` test ensures the session becomes inactive.
"""

import pathlib
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest


def test_session_action(tap, test_env, action_type):
    # type: (lttngtest.TapGenerator, lttngtest._Environment, str) -> None
    """
    Test that a trigger with a start-session or stop-session action changes
    the session state when the event-rule-matches condition is satisfied.
    """
    tap.diagnostic(
        "Test {}-session action triggered by event-rule-matches".format(action_type)
    )

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

    # Create a session
    output_path = test_env.create_temporary_directory(
        "trace-{}-action".format(action_type)
    )
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_path)
    )
    channel = session.add_channel(lttngtest.TracingDomain.User)
    channel.add_recording_rule(lttngtest.UserTracepointEventRule("tp:tptest"))

    # Set initial state based on action type
    if action_type == "start":
        # Session should be inactive initially for start-session test
        tap.test(
            not session.is_active,
            "Session '{}' is initially inactive".format(session.name),
        )
    else:
        # Session should be active initially for stop-session test
        session.start()
        tap.test(
            session.is_active,
            "Session '{}' is initially active".format(session.name),
        )

    # Create trigger with appropriate action
    trigger_name = "{}-session-trigger".format(action_type)
    rule = lttngtest.UserTracepointEventRule(name_pattern="tp:tptest")
    condition = lttngtest.EventRuleMatchesCondition(rule)

    if action_type == "start":
        session_action = lttngtest.StartSessionTriggerAction(session.name)
    else:
        session_action = lttngtest.StopSessionTriggerAction(session.name)

    notify_action = lttngtest.NotifyTriggerAction()
    client.add_trigger(condition, [session_action, notify_action], name=trigger_name)

    # Launch notification-client and wait for it to register
    notif_client = test_env.launch_notification_client(trigger_name=trigger_name)

    # Launch test application to generate events
    app = test_env.launch_wait_trace_test_application(5)
    app.trace()
    app.wait_for_tracing_done()

    # Wait for notification-client to receive the notification and exit
    notif_client.wait(timeout=10)
    tap.test(
        notif_client.returncode == 0,
        "Notification client exited successfully",
    )

    # Verify the session state was changed by the trigger
    if action_type == "start":
        tap.test(
            session.is_active,
            "Session '{}' was started by the trigger".format(session.name),
        )
    else:
        tap.test(
            not session.is_active,
            "Session '{}' was stopped by the trigger".format(session.name),
        )

    # Clean up
    app.wait_for_exit()
    client.remove_trigger(trigger_name)
    if session.is_active:
        session.stop()
    session.destroy()


if __name__ == "__main__":
    tap = lttngtest.TapGenerator(6)
    tap.diagnostic("Test trigger start and stop session actions")

    for action_type in ("start", "stop"):
        with lttngtest.test_environment(
            with_sessiond=True, log=tap.diagnostic
        ) as test_env:
            test_session_action(tap, test_env, action_type)

    sys.exit(0 if tap.is_successful else 1)
