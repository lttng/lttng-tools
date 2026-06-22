#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Test suite for trigger save/load functionality.

Triggers are global objects (not owned by a recording session), but the
`lttng save`/`lttng load` commands persist and restore them alongside
recording sessions.

This test validates that:

• Triggers survive a save/load cycle (condition and actions preserved).

• The `--no-triggers` option of `lttng save` excludes triggers from the
  saved configuration.

• The `--no-triggers` option of `lttng load` ignores the triggers
  present in the configuration.

• Loading a configuration of which a trigger name already exists is
  accepted when the existing trigger is identical, and rejected when it
  differs.

• Each supported condition, action, and rate policy type survives a
  save/load cycle unchanged (one test per trigger type), exercising the
  whole trigger serialization/deserialization round trip.
"""

import pathlib
import sys
import traceback
from typing import Callable, List, Optional

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest


# Creates a recording session with a UST channel and a recording rule,
# and returns it.
def _make_session_with_channel(test_env, client):
    # type: (lttngtest._Environment, lttngtest.LTTngClient) -> lttngtest.Session
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("trace")
        )
    )
    session.add_channel(lttngtest.TracingDomain.User).add_recording_rule(
        lttngtest.lttngctl.UserTracepointEventRule("tp:*")
    )
    return session


# Returns the trigger named `trigger_name`, or `None` if there is no
# such trigger.
def _find_trigger_by_name(client, trigger_name):
    # type: (lttngtest.LTTngClient, str) -> Optional[lttngtest.lttngctl.Trigger]
    for trigger in client.list_triggers():
        if trigger.name == trigger_name:
            return trigger

    return


# Returns the recording session named `session_name`, or `None` if there
# is no such recording session.
def _find_session_by_name(client, session_name):
    # type: (lttngtest.LTTngClient, str) -> Optional[lttngtest.Session]
    for session in client.list_sessions():
        if session.name == session_name:
            return session

    return


# Saves and loads a trigger, then verifies that the condition and actions
# survive the cycle.
def test_trigger_save_load(tap, test_env, client):
    # type: (lttngtest.TapGenerator, lttngtest._Environment, lttngtest.LTTngClient) -> bool
    session = _make_session_with_channel(test_env, client)
    session_name = session.name

    trigger_name = "save_load_trigger"
    condition = lttngtest.EventRuleMatchesCondition(
        lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
    )
    actions = [
        lttngtest.NotifyTriggerAction()
    ]  # type: List[lttngtest.lttngctl.TriggerAction]
    client.add_trigger(condition, actions, name=trigger_name)

    client.save_sessions(session_name=session_name)

    # Removes the live trigger and recording session so that the load
    # restores them from the configuration rather than finding them
    # already present.
    client.remove_trigger(trigger_name)
    session.destroy()

    client.load_sessions(session_name=session_name)

    loaded_trigger = _find_trigger_by_name(client, trigger_name)

    if loaded_trigger is None:
        tap.diagnostic("Trigger `{}` not found after load".format(trigger_name))
        return False

    if loaded_trigger.condition != condition:
        tap.diagnostic(
            "Trigger condition mismatch. Expected {!r}, got {!r}".format(
                condition, loaded_trigger.condition
            )
        )
        return False

    if loaded_trigger.actions != actions:
        tap.diagnostic(
            "Trigger actions mismatch. Expected {!r}, got {!r}".format(
                actions, loaded_trigger.actions
            )
        )
        return False

    client.remove_trigger(trigger_name)
    client.destroy_session_by_name(session_name)
    return True


# Verifies that `lttng save --no-triggers` excludes triggers from the saved
# configuration: loading restores the recording session but not the trigger.
def test_save_no_triggers(tap, test_env, client):
    # type: (lttngtest.TapGenerator, lttngtest._Environment, lttngtest.LTTngClient) -> bool
    session = _make_session_with_channel(test_env, client)
    session_name = session.name

    trigger_name = "save_no_triggers_trigger"
    client.add_trigger(
        lttngtest.EventRuleMatchesCondition(
            lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
        ),
        [lttngtest.NotifyTriggerAction()],
        name=trigger_name,
    )

    client.save_sessions(session_name=session_name, no_triggers=True)

    client.remove_trigger(trigger_name)
    session.destroy()

    client.load_sessions(session_name=session_name)

    # The recording session must be restored
    if _find_session_by_name(client, session_name) is None:
        tap.diagnostic(
            "Recording session `{}` not found after load".format(session_name)
        )
        return False

    # The trigger must not have been saved
    if _find_trigger_by_name(client, trigger_name) is not None:
        tap.diagnostic(
            "Trigger `{}` was saved despite `--no-triggers`".format(trigger_name)
        )
        return False

    client.destroy_session_by_name(session_name)
    return True


# Verifies that `lttng load --no-triggers` ignores the triggers present
# in the configuration: loading restores the recording session but not
# the trigger.
def test_load_no_triggers(tap, test_env, client):
    # type: (lttngtest.TapGenerator, lttngtest._Environment, lttngtest.LTTngClient) -> bool
    session = _make_session_with_channel(test_env, client)
    session_name = session.name

    trigger_name = "load_no_triggers_trigger"
    client.add_trigger(
        lttngtest.EventRuleMatchesCondition(
            lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
        ),
        [lttngtest.NotifyTriggerAction()],
        name=trigger_name,
    )

    # Saves with triggers included
    client.save_sessions(session_name=session_name)

    client.remove_trigger(trigger_name)
    session.destroy()

    # Loads while ignoring triggers
    client.load_sessions(session_name=session_name, no_triggers=True)

    # The recording session must be restored
    if _find_session_by_name(client, session_name) is None:
        tap.diagnostic("Session `{}` not found after load".format(session_name))
        return False

    # The trigger must not have been loaded
    if _find_trigger_by_name(client, trigger_name) is not None:
        tap.diagnostic(
            "Trigger `{}` was loaded despite --no-triggers".format(trigger_name)
        )
        return False

    client.destroy_session_by_name(session_name)

    return True


# Verifies that loading a configuration of which a trigger name already
# exists is accepted when the existing trigger is identical to the saved one.
def test_load_existing_trigger_identical(tap, test_env, client):
    # type: (lttngtest.TapGenerator, lttngtest._Environment, lttngtest.LTTngClient) -> bool
    session = _make_session_with_channel(test_env, client)
    session_name = session.name

    trigger_name = "existing_identical_trigger"
    client.add_trigger(
        lttngtest.EventRuleMatchesCondition(
            lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
        ),
        [lttngtest.NotifyTriggerAction()],
        name=trigger_name,
    )

    client.save_sessions(session_name=session_name)

    # Destroys only the recording session; keeps the identical trigger
    # registered so that the load encounters a same-name,
    # same-definition trigger.
    session.destroy()

    try:
        client.load_sessions(session_name=session_name)
    except lttngtest.LTTngClientError as e:
        tap.diagnostic(
            "Load of an identical existing trigger failed: {}".format(e._error_output)
        )
        return False

    # The trigger must still be present, exactly once.
    trigger_count = len([t for t in client.list_triggers() if t.name == trigger_name])
    if trigger_count != 1:
        tap.diagnostic(
            "Expected exactly one trigger named `{}`, found {}".format(
                trigger_name, trigger_count
            )
        )
        return False

    client.remove_trigger(trigger_name)
    client.destroy_session_by_name(session_name)

    return True


# Verifies that loading a configuration of which a trigger name already
# exists is rejected when the existing trigger differs from the
# saved one.
def test_load_existing_trigger_conflict(tap, test_env, client):
    # type: (lttngtest.TapGenerator, lttngtest._Environment, lttngtest.LTTngClient) -> bool
    session = _make_session_with_channel(test_env, client)
    session_name = session.name

    trigger_name = "existing_conflicting_trigger"
    saved_cond = lttngtest.EventRuleMatchesCondition(
        lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
    )

    # Saves a configuration containing a trigger with a notify action.
    client.add_trigger(saved_cond, [lttngtest.NotifyTriggerAction()], name=trigger_name)
    client.save_sessions(session_name=session_name)

    # Replaces the live trigger with a different one bearing the same
    # name (a different action) so that the load hits a name conflict.
    client.remove_trigger(trigger_name)
    client.add_trigger(
        saved_cond,
        [lttngtest.StartSessionTriggerAction(session_name)],
        name=trigger_name,
    )

    session.destroy()

    try:
        client.load_sessions(session_name=session_name)
    except lttngtest.LTTngClientError:
        # Expected: the conflicting trigger name aborts the load
        client.remove_trigger(trigger_name)
        return True

    tap.diagnostic(
        "Load of a conflicting existing trigger `{}` unexpectedly succeeded".format(
            trigger_name
        )
    )
    client.remove_trigger(trigger_name)
    return False


# Creates a recording session with a regular user space channel and a
# user space map channel, and returns it along with the names of
# both channels.
#
# The regular channel name feeds the "event record channel buffer usage"
# conditions and the map channel name feeds the "increment map value"
# actions of the comprehensive round trip test.
def _make_session_with_channels(test_env, client):
    # type: (lttngtest._Environment, lttngtest.LTTngClient) -> tuple
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("trace")
        )
    )
    channel = session.add_channel(lttngtest.TracingDomain.User, channel_name="chan")
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:*"))
    return (
        session,
        channel.name,
        session.add_user_map_channel(channel_name="mapchan").name,
    )


# Returns a list of (name, condition, actions) tuples describing one
# trigger per supported condition, action, and rate policy type.
#
# The collection is meant to exercise every
# serialization/deserialization path of the trigger save/load feature.
#
# Kernel event rules are only included when `include_kernel` is true.
def _build_all_type_trigger_specs(
    session_name, channel_name, map_channel_name, include_kernel
):
    # type: (str, str, str, bool) -> list
    specs = [
        # "Event rule matches" conditions over every user space and
        # agent event rule type, paired with each action and rate
        # policy type.
        (
            "erm-ust-notify",
            lttngtest.EventRuleMatchesCondition(
                lttngtest.UserTracepointEventRule("tp:tp1")
            ),
            [lttngtest.NotifyTriggerAction()],
        ),
        (
            "erm-ust-filter-notify-every",
            lttngtest.EventRuleMatchesCondition(
                lttngtest.UserTracepointEventRule(
                    "tp:tp2", filter_expression="intfield > 0"
                )
            ),
            [lttngtest.NotifyTriggerAction(lttngtest.EveryNRatePolicy(5))],
        ),
        (
            "erm-ust-loglevel-severe-exclude-notify-once",
            lttngtest.EventRuleMatchesCondition(
                lttngtest.UserTracepointEventRule(
                    "tp:*",
                    log_level_rule=lttngtest.LogLevelRuleAsSevereAs(
                        lttngtest.UserLogLevel.WARNING
                    ),
                    name_pattern_exclusions=["tp:secret"],
                )
            ),
            [lttngtest.NotifyTriggerAction(lttngtest.OnceAfterNRatePolicy(3))],
        ),
        (
            "erm-ust-loglevel-exact-start",
            lttngtest.EventRuleMatchesCondition(
                lttngtest.UserTracepointEventRule(
                    "tp:tp4",
                    log_level_rule=lttngtest.LogLevelRuleExactly(
                        lttngtest.UserLogLevel.INFO
                    ),
                )
            ),
            [lttngtest.StartSessionTriggerAction(session_name)],
        ),
        (
            "erm-jul-stop",
            lttngtest.EventRuleMatchesCondition(
                lttngtest.JULTracepointEventRule("jul.logger")
            ),
            [lttngtest.StopSessionTriggerAction(session_name)],
        ),
        (
            "erm-log4j-rotate",
            lttngtest.EventRuleMatchesCondition(
                lttngtest.Log4jTracepointEventRule("log4j.logger")
            ),
            [lttngtest.RotateSessionTriggerAction(session_name)],
        ),
        (
            "erm-log4j2-snapshot",
            lttngtest.EventRuleMatchesCondition(
                lttngtest.Log4j2TracepointEventRule("log4j2.logger")
            ),
            [lttngtest.SnapshotSessionTriggerAction(session_name)],
        ),
        (
            "erm-python-notify",
            lttngtest.EventRuleMatchesCondition(
                lttngtest.PythonTracepointEventRule("py.logger")
            ),
            [lttngtest.NotifyTriggerAction()],
        ),
        # The "increment map value" action with a key template requires
        # an "event rule matches" condition over a tracepoint event rule
        # so that the `{event_name}` token can be substituted at
        # fire time.
        (
            "erm-ust-incr-map-template",
            lttngtest.EventRuleMatchesCondition(
                lttngtest.UserTracepointEventRule("tp:incr")
            ),
            [
                lttngtest.IncrementMapValueTriggerAction(
                    session_name=session_name,
                    channel_name=map_channel_name,
                    channel_type=lttngtest.UserMapChannel,
                    key_template="count/{event_name}",
                )
            ],
        ),
        # Multiple actions exercise the action list reconstruction path
        (
            "erm-ust-multi-action",
            lttngtest.EventRuleMatchesCondition(
                lttngtest.UserTracepointEventRule("tp:multi")
            ),
            [
                lttngtest.StartSessionTriggerAction(session_name),
                lttngtest.NotifyTriggerAction(),
                lttngtest.StopSessionTriggerAction(session_name),
            ],
        ),
        # Conditions other than "event rule matches"
        (
            "consumed-size-notify",
            lttngtest.SessionConsumedSizeCondition(session_name, 1024 * 1024),
            [lttngtest.NotifyTriggerAction()],
        ),
        (
            "buffer-usage-high-bytes-notify",
            lttngtest.BufferUsageHighCondition(
                session_name,
                channel_name,
                lttngtest.TracingDomain.User,
                threshold_bytes=4096,
            ),
            [lttngtest.NotifyTriggerAction()],
        ),
        (
            "buffer-usage-low-ratio-notify",
            lttngtest.BufferUsageLowCondition(
                session_name,
                channel_name,
                lttngtest.TracingDomain.User,
                threshold_ratio=0.25,
            ),
            [lttngtest.NotifyTriggerAction()],
        ),
        (
            "rotation-ongoing-notify",
            lttngtest.SessionRotationOngoingCondition(session_name),
            [lttngtest.NotifyTriggerAction()],
        ),
        # A "recording session rotation finishes" condition uses a
        # literal key (templates are only meaningful with "event
        # rule matches").
        (
            "rotation-completed-incr-map",
            lttngtest.SessionRotationCompletedCondition(session_name),
            [
                lttngtest.IncrementMapValueTriggerAction(
                    session_name=session_name,
                    channel_name=map_channel_name,
                    channel_type=lttngtest.UserMapChannel,
                    key_template="rotations",
                )
            ],
        ),
    ]

    if include_kernel:
        specs.extend(
            [
                (
                    "erm-kernel-tracepoint-notify",
                    lttngtest.EventRuleMatchesCondition(
                        lttngtest.KernelTracepointEventRule("sched_switch")
                    ),
                    [lttngtest.NotifyTriggerAction()],
                ),
                (
                    "erm-kernel-syscall-notify",
                    lttngtest.EventRuleMatchesCondition(
                        lttngtest.KernelSyscallEventRule("read")
                    ),
                    [lttngtest.NotifyTriggerAction()],
                ),
                (
                    "erm-kernel-kprobe-notify-every",
                    lttngtest.EventRuleMatchesCondition(
                        lttngtest.KernelKprobeEventRule(
                            event_name="my_kprobe",
                            symbol_name="lttng_channel_destroy",
                        )
                    ),
                    [lttngtest.NotifyTriggerAction(lttngtest.EveryNRatePolicy(2))],
                ),
            ]
        )

    return specs


# Adds the single trigger named `trigger_name` from the comprehensive
# spec collection, saves the configuration, removes the trigger and its
# recording session, then loads everything back and verifies that the
# trigger is restored with an equivalent condition and action list.
#
# The intent is to exercise the serialization/deserialization round trip
# of one trigger type at a time, without firing any trigger.
def test_trigger_round_trip(tap, test_env, client, trigger_name, include_kernel):
    # type: (lttngtest.TapGenerator, lttngtest._Environment, lttngtest.LTTngClient, str, bool) -> bool
    session, channel_name, map_channel_name = _make_session_with_channels(
        test_env, client
    )
    session_name = session.name

    _, condition, actions = next(
        spec
        for spec in _build_all_type_trigger_specs(
            session_name, channel_name, map_channel_name, include_kernel
        )
        if spec[0] == trigger_name
    )

    client.add_trigger(condition, actions, name=trigger_name)

    client.save_sessions(session_name=session_name)

    # Remove the live trigger and recording session so that the load
    # restores them from the configuration rather than finding them
    # already present.
    client.remove_trigger(trigger_name)
    session.destroy()

    client.load_sessions(session_name=session_name)

    success = True
    loaded_trigger = _find_trigger_by_name(client, trigger_name)
    if loaded_trigger is None:
        tap.diagnostic("Trigger `{}` not found after load".format(trigger_name))
        success = False
    else:
        if loaded_trigger.condition != condition:
            tap.diagnostic(
                "Condition mismatch. Expected {!r}, got {!r}".format(
                    condition, loaded_trigger.condition
                )
            )
            success = False

        if loaded_trigger.actions != actions:
            tap.diagnostic(
                "Actions mismatch. Expected {!r}, got {!r}".format(
                    actions, loaded_trigger.actions
                )
            )
            success = False

        client.remove_trigger(trigger_name)

    client.destroy_session_by_name(session_name)
    return success


# Runs a single test, handling exceptions and reporting the TAP result.
def run_test(tap, test_env, test_func, test_name):
    # type: (lttngtest.TapGenerator, lttngtest._Environment, Callable[..., bool], str) -> None
    try:
        if test_func(
            tap, test_env, lttngtest.LTTngClient(test_env, log=tap.diagnostic)
        ):
            tap.ok(test_name)
        else:
            tap.fail(test_name)
    except lttngtest.LTTngClientError as exc:
        tap.fail("{} - LTTng client error: {}".format(test_name, exc._error_output))
    except Exception as exc:
        tap.fail("{} - Uncaught exception: {}".format(test_name, str(exc)))
        tap.diagnostic("".join(traceback.format_exception(exc)))


if __name__ == "__main__":
    include_kernel = lttngtest._Environment.run_kernel_tests()

    tests = [
        ("Trigger save/load", test_trigger_save_load),
        ("Save with `--no-triggers`", test_save_no_triggers),
        ("Load with `--no-triggers`", test_load_no_triggers),
        ("Load existing identical trigger", test_load_existing_trigger_identical),
        ("Load existing conflicting trigger", test_load_existing_trigger_conflict),
    ]

    # One round trip test per supported condition, action and rate
    # policy type.
    #
    # The trigger name (the first spec. field, independent of the
    # placeholder arguments here) is both the test label and the name of
    # the registered trigger.
    for trigger_name, _, _ in _build_all_type_trigger_specs(
        "s", "c", "m", include_kernel
    ):
        tests.append(
            (
                "Round-trip trigger `{}`".format(trigger_name),
                lambda tap, test_env, client, name=trigger_name: test_trigger_round_trip(
                    tap, test_env, client, name, include_kernel
                ),
            )
        )

    tap = lttngtest.TapGenerator(len(tests))

    with lttngtest.test_environment(
        with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=include_kernel
    ) as test_env:
        for test_name, test_func in tests:
            run_test(tap, test_env, test_func, test_name)

    sys.exit(0 if tap.is_successful else 1)
