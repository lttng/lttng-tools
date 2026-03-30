#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Test suite for kernel event disable behavior.

Validates that disabling events works correctly:
- Disabling a specific event by name only disables matching events
- Disabling all events disables every event in the channel
- Disabling a non-existent event reports an error
- Disabling then re-enabling an event works correctly
- Disabling by name disables all matching rules regardless of filters
"""

import os
import pathlib
import sys
import traceback

test_utils_import_path = pathlib.Path(__file__).absolute().parents[2] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest


def _find_rule_by_name(rules, name):
    """Find a recording rule by name pattern in a list of rules."""
    for rule in rules:
        if rule.name_pattern == name:
            return rule
    return None


def _find_rules_by_name(rules, name):
    """Find all recording rules matching a name pattern."""
    return [rule for rule in rules if rule.name_pattern == name]


def test_disable_specific_kernel_event(tap, test_env, client, **kwargs):
    """
    Disabling one event by name should only disable that event;
    other events in the same channel should remain enabled.
    """
    output_dir = test_env.create_temporary_directory("trace")
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_dir)
    )

    channel_name = "kchan0"
    channel = session.add_channel(
        lttngtest.TracingDomain.Kernel, channel_name=channel_name
    )

    channel.add_recording_rule(
        lttngtest.lttngctl.KernelTracepointEventRule("sched_switch")
    )
    channel.add_recording_rule(
        lttngtest.lttngctl.KernelTracepointEventRule("sched_wakeup")
    )

    rules = list(channel.recording_rules)
    if len(rules) != 2:
        tap.diagnostic("Expected 2 rules after enable, got {}".format(len(rules)))
        return False

    channel.disable_recording_rules("sched_switch")

    rules = list(channel.recording_rules)
    switch_rule = _find_rule_by_name(rules, "sched_switch")
    wakeup_rule = _find_rule_by_name(rules, "sched_wakeup")

    if switch_rule is None:
        tap.diagnostic("sched_switch rule not found after disable")
        return False

    if switch_rule.enabled is not False:
        tap.diagnostic(
            "sched_switch should be disabled, enabled={}".format(switch_rule.enabled)
        )
        return False

    if wakeup_rule is None:
        tap.diagnostic("sched_wakeup rule not found after disabling sched_switch")
        return False

    if wakeup_rule.enabled is not True:
        tap.diagnostic(
            "sched_wakeup should still be enabled, enabled={}".format(
                wakeup_rule.enabled
            )
        )
        return False

    session.destroy()
    return True


def test_disable_all_kernel_events(tap, test_env, client, **kwargs):
    """
    Disabling all events should disable every event in the channel.
    """
    output_dir = test_env.create_temporary_directory("trace")
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_dir)
    )

    channel_name = "kchan0"
    channel = session.add_channel(
        lttngtest.TracingDomain.Kernel, channel_name=channel_name
    )

    channel.add_recording_rule(
        lttngtest.lttngctl.KernelTracepointEventRule("sched_switch")
    )
    channel.add_recording_rule(
        lttngtest.lttngctl.KernelTracepointEventRule("sched_wakeup")
    )

    channel.disable_all_recording_rules()

    rules = list(channel.recording_rules)
    for rule in rules:
        if rule.enabled is not False:
            tap.diagnostic(
                "Event '{}' should be disabled after disable-all, enabled={}".format(
                    rule.name_pattern, rule.enabled
                )
            )
            return False

    session.destroy()
    return True


def test_disable_nonexistent_kernel_event(tap, test_env, client, **kwargs):
    """
    Disabling an event that does not exist should fail with an error.
    """
    output_dir = test_env.create_temporary_directory("trace")
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_dir)
    )

    channel_name = "kchan0"
    channel = session.add_channel(
        lttngtest.TracingDomain.Kernel, channel_name=channel_name
    )

    channel.add_recording_rule(
        lttngtest.lttngctl.KernelTracepointEventRule("sched_switch")
    )

    try:
        channel.disable_recording_rules("nonexistent_event_name")
        tap.diagnostic("Disabling non-existent event should have raised an error")
        session.destroy()
        return False
    except lttngtest.LTTngClientError:
        pass

    session.destroy()
    return True


def test_disable_then_reenable_kernel_event(tap, test_env, client, **kwargs):
    """
    An event that was disabled can be re-enabled.
    """
    output_dir = test_env.create_temporary_directory("trace")
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_dir)
    )

    channel_name = "kchan0"
    channel = session.add_channel(
        lttngtest.TracingDomain.Kernel, channel_name=channel_name
    )

    channel.add_recording_rule(
        lttngtest.lttngctl.KernelTracepointEventRule("sched_switch")
    )

    channel.disable_recording_rules("sched_switch")

    rules = list(channel.recording_rules)
    switch_rule = _find_rule_by_name(rules, "sched_switch")
    if switch_rule is None or switch_rule.enabled is not False:
        tap.diagnostic(
            "sched_switch should be disabled after disable, enabled={}".format(
                switch_rule.enabled if switch_rule else "NOT FOUND"
            )
        )
        return False

    channel.add_recording_rule(
        lttngtest.lttngctl.KernelTracepointEventRule("sched_switch")
    )

    rules = list(channel.recording_rules)
    switch_rule = _find_rule_by_name(rules, "sched_switch")
    if switch_rule is None or switch_rule.enabled is not True:
        tap.diagnostic(
            "sched_switch should be re-enabled, enabled={}".format(
                switch_rule.enabled if switch_rule else "NOT FOUND"
            )
        )
        return False

    session.destroy()
    return True


def test_disable_syscall_with_and_without_filter(tap, test_env, client, **kwargs):
    """
    Enabling the same syscall twice — once without a filter and once with a
    filter — creates two distinct event rules.  Disabling by name should
    disable both rules.
    """
    output_dir = test_env.create_temporary_directory("trace")
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_dir)
    )

    channel_name = "kchan0"
    channel = session.add_channel(
        lttngtest.TracingDomain.Kernel, channel_name=channel_name
    )

    syscall_name = "open"
    channel.add_recording_rule(lttngtest.lttngctl.KernelSyscallEventRule(syscall_name))
    channel.add_recording_rule(
        lttngtest.lttngctl.KernelSyscallEventRule(
            syscall_name, filter_expression="flags == 0"
        )
    )

    rules = list(channel.recording_rules)
    matching = _find_rules_by_name(rules, syscall_name)
    if len(matching) != 2:
        tap.diagnostic(
            "Expected 2 rules for '{}' after enable, got {}".format(
                syscall_name, len(matching)
            )
        )
        return False

    channel.disable_recording_rules(syscall_name)

    rules = list(channel.recording_rules)
    matching = _find_rules_by_name(rules, syscall_name)
    for rule in matching:
        if rule.enabled is not False:
            tap.diagnostic(
                "Rule '{}' (filter={}) should be disabled, enabled={}".format(
                    rule.name_pattern,
                    getattr(rule, "filter_expression", None),
                    rule.enabled,
                )
            )
            return False

    session.destroy()
    return True


def run_test(tap, test_env, test_func, test_name, **kwargs):
    """Run a single test with proper exception handling."""
    try:
        client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
        result = test_func(tap, test_env, client, **kwargs)
        if result:
            tap.ok(test_name)
        else:
            tap.fail(test_name)
    except lttngtest.LTTngClientError as e:
        tap.fail("{} - LTTng client error: {}".format(test_name, e._error_output))
    except Exception as e:
        tap.fail("{} - Uncaught exception: {}".format(test_name, str(e)))
        tap.diagnostic("".join(traceback.format_exception(e)))


if __name__ == "__main__":
    kernel_tests = [
        (
            "Disable specific kernel event by name",
            test_disable_specific_kernel_event,
            {},
        ),
        ("Disable all kernel events", test_disable_all_kernel_events, {}),
        (
            "Disable non-existent kernel event reports error",
            test_disable_nonexistent_kernel_event,
            {},
        ),
        (
            "Disable then re-enable kernel event",
            test_disable_then_reenable_kernel_event,
            {},
        ),
        (
            "Disable syscall with and without filter disables both",
            test_disable_syscall_with_and_without_filter,
            {},
        ),
    ]

    is_root = os.getuid() == 0

    if not is_root:
        tap = lttngtest.TapGenerator(len(kernel_tests))
        tap.skip_all_remaining("Kernel tests require root privileges")
        sys.exit(0)

    tap = lttngtest.TapGenerator(len(kernel_tests))

    with lttngtest.test_environment(
        with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=True
    ) as test_env:
        for test_name, test_func, kwargs in kernel_tests:
            run_test(tap, test_env, test_func, test_name, **kwargs)

    sys.exit(0 if tap.is_successful else 1)
