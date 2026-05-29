#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Olivier Dion <odion@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only

"""
Exercise the creation, listing and removal of triggers covering every
condition, event rule, action and rate policy type supported by the
lttngtest framework.

The test proceeds as follows:

  1. Register a set of triggers, each combining an event-rule-matches
     condition (over a different event rule type) with one or more actions
     and rate policies.

  2. List the registered triggers and verify that each one is reported back
     with an equivalent condition and action list (round-trip).

  3. Remove the triggers one by one, verifying after each removal that the
     removed trigger is gone while the others remain.

Kernel event rules are only exercised when running as root with kernel
tests enabled.
"""

import pathlib
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest


def build_trigger_specs(session_name, include_kernel):
    # type: (str, bool) -> list
    """
    Return a list of (name, condition, actions) tuples describing the triggers
    to register. The collection covers every event rule, action and rate
    policy type understood by the framework.
    """
    specs = [
        # User space tracepoint event rule variations, paired with each
        # session-less and session action.
        (
            "ust-basic-notify",
            lttngtest.EventRuleMatchesCondition(
                lttngtest.UserTracepointEventRule("tp:tp1")
            ),
            [lttngtest.NotifyTriggerAction()],
        ),
        (
            "ust-filter-notify-every",
            lttngtest.EventRuleMatchesCondition(
                lttngtest.UserTracepointEventRule(
                    "tp:tp2", filter_expression="intfield > 0"
                )
            ),
            [lttngtest.NotifyTriggerAction(lttngtest.EveryNRatePolicy(5))],
        ),
        (
            "ust-loglevel-severe-start",
            lttngtest.EventRuleMatchesCondition(
                lttngtest.UserTracepointEventRule(
                    "tp:tp3",
                    log_level_rule=lttngtest.LogLevelRuleAsSevereAs(
                        lttngtest.UserLogLevel.WARNING
                    ),
                )
            ),
            [lttngtest.StartSessionTriggerAction(session_name)],
        ),
        (
            "ust-loglevel-exact-exclude-stop-once",
            lttngtest.EventRuleMatchesCondition(
                lttngtest.UserTracepointEventRule(
                    "tp:*",
                    log_level_rule=lttngtest.LogLevelRuleExactly(
                        lttngtest.UserLogLevel.INFO
                    ),
                    name_pattern_exclusions=["tp:secret"],
                )
            ),
            [
                lttngtest.StopSessionTriggerAction(
                    session_name, lttngtest.OnceAfterNRatePolicy(3)
                )
            ],
        ),
        # Agent domain event rules paired with the remaining session actions.
        (
            "jul-rotate",
            lttngtest.EventRuleMatchesCondition(
                lttngtest.JULTracepointEventRule("jul.logger")
            ),
            [lttngtest.RotateSessionTriggerAction(session_name)],
        ),
        (
            "log4j-snapshot",
            lttngtest.EventRuleMatchesCondition(
                lttngtest.Log4jTracepointEventRule("log4j.logger")
            ),
            [lttngtest.SnapshotSessionTriggerAction(session_name)],
        ),
        (
            "log4j2-notify",
            lttngtest.EventRuleMatchesCondition(
                lttngtest.Log4j2TracepointEventRule("log4j2.logger")
            ),
            [lttngtest.NotifyTriggerAction()],
        ),
        # Multiple actions exercise the action-list reconstruction path.
        (
            "python-multi-action",
            lttngtest.EventRuleMatchesCondition(
                lttngtest.PythonTracepointEventRule("py.logger")
            ),
            [
                lttngtest.StartSessionTriggerAction(session_name),
                lttngtest.NotifyTriggerAction(),
            ],
        ),
    ]

    if include_kernel:
        specs.extend(
            [
                (
                    "kernel-tracepoint-notify",
                    lttngtest.EventRuleMatchesCondition(
                        lttngtest.KernelTracepointEventRule("sched_switch")
                    ),
                    [lttngtest.NotifyTriggerAction()],
                ),
                (
                    "kernel-syscall-notify",
                    lttngtest.EventRuleMatchesCondition(
                        lttngtest.KernelSyscallEventRule("read")
                    ),
                    [lttngtest.NotifyTriggerAction()],
                ),
                (
                    "kernel-kprobe-notify-every",
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


def test_trigger_creation(tap, client, specs):
    # type: (lttngtest.TapGenerator, lttngtest.LTTngClient, list) -> None
    # Register every trigger, keeping the returned Trigger handles around for
    # removal.
    registered = {}  # name -> Trigger
    for name, condition, actions in specs:
        try:
            registered[name] = client.add_trigger(condition, actions, name=name)
            tap.test(True, "Registered trigger '{}'".format(name))
        except Exception as e:
            tap.test(False, "Registered trigger '{}': {}".format(name, e))

    # List the triggers and check each one round-trips.
    listed = {trigger.name: trigger for trigger in client.list_triggers()}
    for name, condition, actions in specs:
        trigger = listed.get(name)
        if trigger is None:
            tap.test(False, "Trigger '{}' is reported by list-triggers".format(name))
            continue

        condition_matches = trigger.condition == condition
        actions_match = trigger.actions == actions
        if not condition_matches:
            tap.diagnostic(
                "Condition mismatch for '{}': expected {!r}, got {!r}".format(
                    name, condition, trigger.condition
                )
            )
        if not actions_match:
            tap.diagnostic(
                "Action mismatch for '{}': expected {!r}, got {!r}".format(
                    name, actions, trigger.actions
                )
            )

        tap.test(
            condition_matches and actions_match,
            "Trigger '{}' round-trips through list-triggers".format(name),
        )

    tap.test(
        len(listed) == len(specs),
        "list-triggers reports the {} registered triggers (got {})".format(
            len(specs), len(listed)
        ),
    )

    # Remove the triggers one by one, verifying the expected set shrinks.
    # Iterate over the specs (rather than the registered triggers) so that the
    # number of emitted test cases matches the plan even when a registration
    # failed earlier.
    remaining = set(registered.keys())
    for name, _, _ in specs:
        trigger = registered.get(name)
        if trigger is None:
            tap.fail("Trigger '{}' is removed".format(name))
            continue

        client.remove_trigger(trigger)
        remaining.discard(name)

        listed_names = {trigger.name for trigger in client.list_triggers()}
        tap.test(
            name not in listed_names and remaining == listed_names,
            "Trigger '{}' is removed and {} trigger(s) remain".format(
                name, len(remaining)
            ),
        )

    tap.test(
        len(client.list_triggers()) == 0,
        "No triggers remain after removing all of them",
    )


if __name__ == "__main__":
    include_kernel = lttngtest._Environment.run_kernel_tests()

    # The spec count drives the test plan: one registration test and one
    # round-trip test per trigger, one list-count test, one removal test per
    # trigger and one final emptiness test.
    spec_count = len(build_trigger_specs("placeholder", include_kernel))
    tap = lttngtest.TapGenerator(3 * spec_count + 2)
    tap.diagnostic("Test trigger creation, listing and removal")

    with lttngtest.test_environment(
        with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=include_kernel
    ) as test_env:
        client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
        output_path = test_env.create_temporary_directory("trace-trigger-creation")
        session = client.create_session(
            output=lttngtest.LocalSessionOutputLocation(output_path)
        )

        specs = build_trigger_specs(session.name, include_kernel)
        test_trigger_creation(tap, client, specs)

        session.destroy()

    sys.exit(0 if tap.is_successful else 1)
