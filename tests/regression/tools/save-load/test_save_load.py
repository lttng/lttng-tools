#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Test suite for session configuration save/load functionality.

This test validates that session configurations are correctly preserved
through save/load cycles, including:
- Events in various domains (UST, kernel, agent domains)
- Process attribute trackers (with user/group names preserved as names)
- Kernel syscalls and tracepoints
"""

import os
import pathlib
import sys
import traceback

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest


def _find_session_by_name(client, session_name):
    """Find a session by name using the client's list_sessions()."""
    for session in client.list_sessions():
        if session.name == session_name:
            return session
    return None


def _find_recording_rule(recording_rules, expected_rule):
    """Find a matching recording rule in an iterable of rules."""
    for rule in recording_rules:
        if rule == expected_rule:
            return rule
    return None


def test_ust_events_save_load(tap, test_env, client, **kwargs):
    """
    Test that UST domain events without filters are correctly saved and loaded.
    """
    output_dir = test_env.create_temporary_directory("trace")

    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_dir)
    )
    session_name = session.name

    channel_name = "test_chan"
    channel = session.add_channel(
        lttngtest.TracingDomain.User, channel_name=channel_name
    )

    rule1 = lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
    rule2 = lttngtest.lttngctl.UserTracepointEventRule("tp:other_event")
    channel.add_recording_rule(rule1)
    channel.add_recording_rule(rule2)

    client.save_sessions(session_name=session_name)
    session.destroy()
    client.load_sessions(session_name=session_name)

    loaded_session = _find_session_by_name(client, session_name)
    if loaded_session is None:
        tap.diagnostic("Session '{}' not found after load".format(session_name))
        return False

    loaded_channel = loaded_session.channel(lttngtest.TracingDomain.User, channel_name)
    loaded_rules = list(loaded_channel.recording_rules)

    if _find_recording_rule(loaded_rules, rule1) is None:
        tap.diagnostic(
            "Event 'tp:tptest' not found after load. Loaded rules: {}".format(
                loaded_rules
            )
        )
        return False

    if _find_recording_rule(loaded_rules, rule2) is None:
        tap.diagnostic(
            "Event 'tp:other_event' not found after load. Loaded rules: {}".format(
                loaded_rules
            )
        )
        return False

    client.destroy_session_by_name(session_name)

    return True


def test_ust_filter_expression_save_load(tap, test_env, client, **kwargs):
    """
    Test that UST events with filter expressions are correctly saved and loaded.
    """
    output_dir = test_env.create_temporary_directory("trace")

    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_dir)
    )
    session_name = session.name

    channel_name = "test_chan"
    channel = session.add_channel(
        lttngtest.TracingDomain.User, channel_name=channel_name
    )

    expected_filter = 'intfield > 42 && strfield != "exclude_me"'
    rule = lttngtest.lttngctl.UserTracepointEventRule(
        "tp:tptest", filter_expression=expected_filter
    )
    channel.add_recording_rule(rule)

    client.save_sessions(session_name=session_name)
    session.destroy()
    client.load_sessions(session_name=session_name)

    loaded_session = _find_session_by_name(client, session_name)
    if loaded_session is None:
        tap.diagnostic("Session '{}' not found after load".format(session_name))
        return False

    loaded_channel = loaded_session.channel(lttngtest.TracingDomain.User, channel_name)
    loaded_rules = list(loaded_channel.recording_rules)

    restored_rule = _find_recording_rule(loaded_rules, rule)
    if restored_rule is None:
        tap.diagnostic(
            "Event 'tp:tptest' with filter not found after load. Loaded rules: {}".format(
                loaded_rules
            )
        )
        return False

    if restored_rule.filter_expression != expected_filter:
        tap.diagnostic(
            "Filter mismatch. Expected '{}', got '{}'".format(
                expected_filter, restored_rule.filter_expression
            )
        )
        return False

    client.destroy_session_by_name(session_name)

    return True


def test_ust_wildcard_exclusions_save_load(tap, test_env, client, **kwargs):
    """
    Test that UST events with a trailing wildcard name pattern and an exclusion
    list are correctly saved and loaded.
    """
    output_dir = test_env.create_temporary_directory("trace")

    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_dir)
    )
    session_name = session.name

    channel_name = "test_chan"
    channel = session.add_channel(
        lttngtest.TracingDomain.User, channel_name=channel_name
    )

    exclusions = ["tp:excluded_a", "tp:excluded_b"]
    rule = lttngtest.lttngctl.UserTracepointEventRule(
        "tp:*", name_pattern_exclusions=exclusions
    )
    channel.add_recording_rule(rule)

    client.save_sessions(session_name=session_name)
    session.destroy()
    client.load_sessions(session_name=session_name)

    loaded_session = _find_session_by_name(client, session_name)
    if loaded_session is None:
        tap.diagnostic("Session '{}' not found after load".format(session_name))
        return False

    loaded_channel = loaded_session.channel(lttngtest.TracingDomain.User, channel_name)
    loaded_rules = list(loaded_channel.recording_rules)

    restored_rule = _find_recording_rule(loaded_rules, rule)
    if restored_rule is None:
        tap.diagnostic(
            "Wildcard rule with exclusions not found after load. Loaded rules: {}".format(
                loaded_rules
            )
        )
        return False

    if sorted(restored_rule.name_pattern_exclusions) != sorted(exclusions):
        tap.diagnostic(
            "Exclusion list mismatch. Expected {}, got {}".format(
                exclusions, restored_rule.name_pattern_exclusions
            )
        )
        return False

    client.destroy_session_by_name(session_name)

    return True


def test_agent_events_save_load(tap, test_env, client, domain):
    """
    Test that agent domain events are correctly saved and loaded.

    Agent domains internally use filter expressions to match logger names,
    so when you enable event "my.logger.event1", it's stored with a filter
    like 'logger_name == "my.logger.event1"'. This test verifies that the
    event configuration survives a save/load cycle.
    """
    output_dir = test_env.create_temporary_directory("trace")

    event_rule_map = {
        lttngtest.TracingDomain.JUL: lttngtest.lttngctl.JULTracepointEventRule,
        lttngtest.TracingDomain.Log4j: lttngtest.lttngctl.Log4jTracepointEventRule,
        lttngtest.TracingDomain.Log4j2: lttngtest.lttngctl.Log4j2TracepointEventRule,
        lttngtest.TracingDomain.Python: lttngtest.lttngctl.PythonTracepointEventRule,
    }
    event_rule_class = event_rule_map[domain]

    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_dir)
    )
    session_name = session.name

    expected_filter_expression = "foo > 42"

    rule1 = event_rule_class(
        "my.logger.event1", filter_expression=expected_filter_expression
    )
    rule2 = event_rule_class("my.logger.event2")

    session.add_recording_rule(domain, rule1)
    session.add_recording_rule(domain, rule2)

    client.save_sessions(session_name=session_name)
    session.destroy()
    client.load_sessions(session_name=session_name)

    loaded_session = _find_session_by_name(client, session_name)
    if loaded_session is None:
        tap.diagnostic("Session '{}' not found after load".format(session_name))
        return False

    loaded_rules = list(loaded_session.recording_rules(domain))

    if _find_recording_rule(loaded_rules, rule1) is None:
        tap.diagnostic(
            "{}: Event 'my.logger.event1' not found after load. Loaded rules: {}".format(
                domain, loaded_rules
            )
        )
        return False

    if _find_recording_rule(loaded_rules, rule2) is None:
        tap.diagnostic(
            "{}: Event 'my.logger.event2' not found after load. Loaded rules: {}".format(
                domain, loaded_rules
            )
        )
        return False

    client.destroy_session_by_name(session_name)

    return True


def test_kernel_tracepoints_save_load(tap, test_env, client, **kwargs):
    """
    Test that kernel tracepoint events are correctly saved and loaded.
    Requires root privileges.
    """
    output_dir = test_env.create_temporary_directory("trace")

    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_dir)
    )
    session_name = session.name

    channel_name = "kchan0"
    channel = session.add_channel(
        lttngtest.TracingDomain.Kernel, channel_name=channel_name
    )

    rule1 = lttngtest.lttngctl.KernelTracepointEventRule("sched_switch")
    rule2 = lttngtest.lttngctl.KernelTracepointEventRule("sched_wakeup")
    channel.add_recording_rule(rule1)
    channel.add_recording_rule(rule2)

    client.save_sessions(session_name=session_name)
    session.destroy()
    client.load_sessions(session_name=session_name)

    loaded_session = _find_session_by_name(client, session_name)
    if loaded_session is None:
        tap.diagnostic("Session '{}' not found after load".format(session_name))
        return False

    loaded_channel = loaded_session.channel(
        lttngtest.TracingDomain.Kernel, channel_name
    )
    loaded_rules = list(loaded_channel.recording_rules)

    if _find_recording_rule(loaded_rules, rule1) is None:
        tap.diagnostic(
            "Event 'sched_switch' not found after load. Loaded rules: {}".format(
                loaded_rules
            )
        )
        return False

    if _find_recording_rule(loaded_rules, rule2) is None:
        tap.diagnostic(
            "Event 'sched_wakeup' not found after load. Loaded rules: {}".format(
                loaded_rules
            )
        )
        return False

    client.destroy_session_by_name(session_name)

    return True


def test_kernel_tracepoints_filter_save_load(tap, test_env, client, **kwargs):
    """
    Test that kernel tracepoint events with filter expressions are correctly
    saved and loaded. Requires root privileges.
    """
    output_dir = test_env.create_temporary_directory("trace")

    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_dir)
    )
    session_name = session.name

    channel_name = "kchan0"
    channel = session.add_channel(
        lttngtest.TracingDomain.Kernel, channel_name=channel_name
    )

    expected_filter = 'next_comm != "swapper/0"'
    rule = lttngtest.lttngctl.KernelTracepointEventRule(
        "sched_switch", filter_expression=expected_filter
    )
    channel.add_recording_rule(rule)

    client.save_sessions(session_name=session_name)
    session.destroy()
    client.load_sessions(session_name=session_name)

    loaded_session = _find_session_by_name(client, session_name)
    if loaded_session is None:
        tap.diagnostic("Session '{}' not found after load".format(session_name))
        return False

    loaded_channel = loaded_session.channel(
        lttngtest.TracingDomain.Kernel, channel_name
    )
    loaded_rules = list(loaded_channel.recording_rules)

    restored_rule = _find_recording_rule(loaded_rules, rule)
    if restored_rule is None:
        tap.diagnostic(
            "Kernel tracepoint with filter not found after load. Loaded rules: {}".format(
                loaded_rules
            )
        )
        return False

    if restored_rule.filter_expression != expected_filter:
        tap.diagnostic(
            "Filter mismatch. Expected '{}', got '{}'".format(
                expected_filter, restored_rule.filter_expression
            )
        )
        return False

    client.destroy_session_by_name(session_name)

    return True


def test_kernel_syscalls_save_load(tap, test_env, client, **kwargs):
    """
    Test that kernel syscall events are correctly saved and loaded.
    Requires root privileges.
    """
    output_dir = test_env.create_temporary_directory("trace")

    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_dir)
    )
    session_name = session.name

    channel_name = "kchan0"
    channel = session.add_channel(
        lttngtest.TracingDomain.Kernel, channel_name=channel_name
    )
    channel.add_recording_rule(lttngtest.lttngctl.KernelSyscallEventRule("open"))
    channel.add_recording_rule(lttngtest.lttngctl.KernelSyscallEventRule("close"))

    client.save_sessions(session_name=session_name)
    session.destroy()
    client.load_sessions(session_name=session_name)

    loaded_session = _find_session_by_name(client, session_name)
    if loaded_session is None:
        tap.diagnostic("Session '{}' not found after load".format(session_name))
        return False

    loaded_channel = loaded_session.channel(
        lttngtest.TracingDomain.Kernel, channel_name
    )
    loaded_rules = list(loaded_channel.recording_rules)

    # Syscall event names may get entry/exit suffixes through save/load, so
    # match by substring rather than exact equality.
    syscall_rules = [
        r
        for r in loaded_rules
        if isinstance(r, lttngtest.lttngctl.KernelSyscallEventRule)
    ]
    if not syscall_rules:
        tap.diagnostic(
            "No syscall rules found after load. Loaded rules: {}".format(loaded_rules)
        )
        return False

    syscall_names = [r.name_pattern for r in syscall_rules]

    open_found = any("open" in name for name in syscall_names if name)
    close_found = any("close" in name for name in syscall_names if name)

    if not open_found:
        tap.diagnostic(
            "Syscall 'open' not found after load. Available: {}".format(syscall_names)
        )
        return False

    if not close_found:
        tap.diagnostic(
            "Syscall 'close' not found after load. Available: {}".format(syscall_names)
        )
        return False

    client.destroy_session_by_name(session_name)

    return True


def test_kernel_kprobe_function_save_load(tap, test_env, client, **kwargs):
    """
    Test that kernel kprobe (--probe) and function (--function) events are
    correctly saved and loaded, preserving the distinction between the two
    instrumentation types.
    Requires root privileges and the lttng-test kernel module.
    """
    target_symbol = "lttng_test_filter_event_write"

    with lttngtest.kernel_module("lttng-test"):
        output_dir = test_env.create_temporary_directory("trace")

        session = client.create_session(
            output=lttngtest.LocalSessionOutputLocation(output_dir)
        )
        session_name = session.name

        channel_name = "kchan0"
        channel = session.add_channel(
            lttngtest.TracingDomain.Kernel, channel_name=channel_name
        )

        probe_rule = lttngtest.lttngctl.KernelKprobeEventRule(
            event_name="my_probe_event", symbol_name=target_symbol
        )
        function_rule = lttngtest.lttngctl.KernelFunctionEventRule(
            event_name="my_function_event", symbol_name=target_symbol
        )
        channel.add_recording_rule(probe_rule)
        channel.add_recording_rule(function_rule)

        client.save_sessions(session_name=session_name)
        session.destroy()
        client.load_sessions(session_name=session_name)

        loaded_session = _find_session_by_name(client, session_name)
        if loaded_session is None:
            tap.diagnostic("Session '{}' not found after load".format(session_name))
            return False

        loaded_channel = loaded_session.channel(
            lttngtest.TracingDomain.Kernel, channel_name
        )
        loaded_rules = list(loaded_channel.recording_rules)

        # Verify the probe event was restored as a KernelKprobeEventRule.
        probe_rules = [
            r
            for r in loaded_rules
            if isinstance(r, lttngtest.lttngctl.KernelKprobeEventRule)
        ]
        probe_found = any(r.event_name == "my_probe_event" for r in probe_rules)
        if not probe_found:
            tap.diagnostic(
                "Probe event 'my_probe_event' not found after load. Loaded rules: {}".format(
                    loaded_rules
                )
            )
            return False

        # Verify the function event was restored as a KernelFunctionEventRule.
        function_rules = [
            r
            for r in loaded_rules
            if isinstance(r, lttngtest.lttngctl.KernelFunctionEventRule)
        ]
        function_found = any(
            r.event_name == "my_function_event" for r in function_rules
        )
        if not function_found:
            tap.diagnostic(
                "Function event 'my_function_event' not found after load. Loaded rules: {}".format(
                    loaded_rules
                )
            )
            return False

        client.destroy_session_by_name(session_name)

    return True


def test_ust_vpid_tracker_save_load(tap, test_env, client, **kwargs):
    """
    Test that UST VPID process attribute trackers are correctly saved and loaded.
    """
    output_dir = test_env.create_temporary_directory("trace")

    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_dir)
    )
    session_name = session.name

    channel = session.add_channel(lttngtest.TracingDomain.User)
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("*"))

    session.user_vpid_process_attribute_tracker.track(12345)
    session.user_vpid_process_attribute_tracker.track(67890)

    client.save_sessions(session_name=session_name)
    session.destroy()
    client.load_sessions(session_name=session_name)

    loaded_session = _find_session_by_name(client, session_name)
    if loaded_session is None:
        tap.diagnostic("Session '{}' not found after load".format(session_name))
        return False

    tracker = loaded_session.user_vpid_process_attribute_tracker
    if (
        tracker.tracking_policy
        != lttngtest.lttngctl.ProcessAttributeTracker.TrackingPolicy.INCLUDE_SET
    ):
        tap.diagnostic(
            "Expected INCLUDE_SET policy, got {}".format(tracker.tracking_policy)
        )
        return False

    vpid_values = tracker.values

    if 12345 not in vpid_values:
        tap.diagnostic("VPID 12345 not found in tracker values: {}".format(vpid_values))
        return False

    if 67890 not in vpid_values:
        tap.diagnostic("VPID 67890 not found in tracker values: {}".format(vpid_values))
        return False

    client.destroy_session_by_name(session_name)

    return True


def test_kernel_uid_tracker_by_name_save_load(tap, test_env, client, **kwargs):
    """
    Test that kernel UID trackers specified by name are loaded back as names.
    Requires root privileges and destructive tests enabled (creates a temporary
    system user).
    """
    _, dummy_user = test_env.create_dummy_user()
    output_dir = test_env.create_temporary_directory("trace")

    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_dir)
    )
    session_name = session.name

    channel = session.add_channel(lttngtest.TracingDomain.Kernel, channel_name="kchan0")
    channel.add_recording_rule(
        lttngtest.lttngctl.KernelTracepointEventRule("sched_switch")
    )

    session.kernel_uid_process_attribute_tracker.track(dummy_user)

    client.save_sessions(session_name=session_name)
    session.destroy()
    client.load_sessions(session_name=session_name)

    loaded_session = _find_session_by_name(client, session_name)
    if loaded_session is None:
        tap.diagnostic("Session '{}' not found after load".format(session_name))
        return False

    tracker = loaded_session.kernel_uid_process_attribute_tracker
    tracked_values = tracker.values

    if not tracked_values:
        tap.diagnostic("UID tracker has no values after load")
        return False

    name_values = [v for v in tracked_values if isinstance(v, str)]
    if not name_values or name_values[0] != dummy_user:
        tap.diagnostic(
            "UID tracker name value is not '{}': {}".format(
                dummy_user, name_values[0] if name_values else "<none>"
            )
        )
        return False

    client.destroy_session_by_name(session_name)

    return True


def test_kernel_gid_tracker_by_name_save_load(tap, test_env, client, **kwargs):
    """
    Test that kernel GID trackers specified by name are loaded back as names.
    Requires root privileges and destructive tests enabled (creates a temporary
    system group).
    """
    _, dummy_group = test_env.create_dummy_group()
    output_dir = test_env.create_temporary_directory("trace")

    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_dir)
    )
    session_name = session.name

    channel = session.add_channel(lttngtest.TracingDomain.Kernel, channel_name="kchan0")
    channel.add_recording_rule(
        lttngtest.lttngctl.KernelTracepointEventRule("sched_switch")
    )

    session.kernel_gid_process_attribute_tracker.track(dummy_group)

    client.save_sessions(session_name=session_name)
    session.destroy()
    client.load_sessions(session_name=session_name)

    loaded_session = _find_session_by_name(client, session_name)
    if loaded_session is None:
        tap.diagnostic("Session '{}' not found after load".format(session_name))
        return False

    tracker = loaded_session.kernel_gid_process_attribute_tracker
    tracked_values = tracker.values

    if not tracked_values:
        tap.diagnostic("GID tracker has no values after load")
        return False

    name_values = [v for v in tracked_values if isinstance(v, str)]
    if not name_values or name_values[0] != dummy_group:
        tap.diagnostic(
            "GID tracker name value is not '{}': {}".format(
                dummy_group, name_values[0] if name_values else "<none>"
            )
        )
        return False

    client.destroy_session_by_name(session_name)

    return True


def test_ust_log_level_save_load(tap, test_env, client, **kwargs):
    """
    Test that UST events with log level rules (both range and single)
    are correctly preserved through a save/load cycle.
    """
    output_dir = test_env.create_temporary_directory("trace")

    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_dir)
    )
    session_name = session.name

    channel_name = "test_channel"
    channel = session.add_channel(
        lttngtest.TracingDomain.User, channel_name=channel_name
    )

    range_rule = lttngtest.lttngctl.UserTracepointEventRule(
        "tp:range_event",
        log_level_rule=lttngtest.lttngctl.LogLevelRuleAsSevereAs(
            lttngtest.lttngctl.UserLogLevel.WARNING
        ),
    )
    single_rule = lttngtest.lttngctl.UserTracepointEventRule(
        "tp:single_event",
        log_level_rule=lttngtest.lttngctl.LogLevelRuleExactly(
            lttngtest.lttngctl.UserLogLevel.INFO
        ),
    )

    channel.add_recording_rule(range_rule)
    channel.add_recording_rule(single_rule)

    client.save_sessions(session_name=session_name)
    session.destroy()
    client.load_sessions(session_name=session_name)

    loaded_session = _find_session_by_name(client, session_name)
    if loaded_session is None:
        tap.diagnostic("Session '{}' not found after load".format(session_name))
        return False

    loaded_channel = loaded_session.channel(lttngtest.TracingDomain.User, channel_name)
    loaded_rules = list(loaded_channel.recording_rules)

    if _find_recording_rule(loaded_rules, range_rule) is None:
        tap.diagnostic(
            "Range log level rule not found after load. Loaded rules: {}".format(
                loaded_rules
            )
        )
        return False

    if _find_recording_rule(loaded_rules, single_rule) is None:
        tap.diagnostic(
            "Single log level rule not found after load. Loaded rules: {}".format(
                loaded_rules
            )
        )
        return False

    client.destroy_session_by_name(session_name)

    return True


def test_agent_log_level_save_load(tap, test_env, client, domain):
    """
    Test that agent domain events with log level rules (both range and single)
    are correctly preserved through a save/load cycle.

    Each agent domain uses its own log level names; this test uses a
    representative level per domain and validates that the typed LogLevelRule
    is preserved.
    """
    output_dir = test_env.create_temporary_directory("trace")

    event_rule_map = {
        lttngtest.TracingDomain.JUL: lttngtest.lttngctl.JULTracepointEventRule,
        lttngtest.TracingDomain.Log4j: lttngtest.lttngctl.Log4jTracepointEventRule,
        lttngtest.TracingDomain.Log4j2: lttngtest.lttngctl.Log4j2TracepointEventRule,
        lttngtest.TracingDomain.Python: lttngtest.lttngctl.PythonTracepointEventRule,
    }
    event_rule_class = event_rule_map[domain]

    domain_levels = {
        lttngtest.TracingDomain.JUL: (
            lttngtest.lttngctl.JULLogLevel.WARNING,
            lttngtest.lttngctl.JULLogLevel.FINE,
        ),
        lttngtest.TracingDomain.Log4j: (
            lttngtest.lttngctl.Log4jLogLevel.WARN,
            lttngtest.lttngctl.Log4jLogLevel.DEBUG,
        ),
        lttngtest.TracingDomain.Log4j2: (
            lttngtest.lttngctl.Log4j2LogLevel.WARN,
            lttngtest.lttngctl.Log4j2LogLevel.DEBUG,
        ),
        lttngtest.TracingDomain.Python: (
            lttngtest.lttngctl.PythonLogLevel.WARNING,
            lttngtest.lttngctl.PythonLogLevel.DEBUG,
        ),
    }

    range_level, single_level = domain_levels[domain]

    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_dir)
    )
    session_name = session.name

    range_rule = event_rule_class(
        "my.logger.range",
        log_level_rule=lttngtest.lttngctl.LogLevelRuleAsSevereAs(range_level),
    )
    single_rule = event_rule_class(
        "my.logger.single",
        log_level_rule=lttngtest.lttngctl.LogLevelRuleExactly(single_level),
    )

    session.add_recording_rule(domain, range_rule)
    session.add_recording_rule(domain, single_rule)

    client.save_sessions(session_name=session_name)
    session.destroy()
    client.load_sessions(session_name=session_name)

    loaded_session = _find_session_by_name(client, session_name)
    if loaded_session is None:
        tap.diagnostic("Session '{}' not found after load".format(session_name))
        return False

    loaded_rules = list(loaded_session.recording_rules(domain))

    if _find_recording_rule(loaded_rules, range_rule) is None:
        tap.diagnostic(
            "{}: Range log level rule not found after load. Loaded rules: {}".format(
                domain, loaded_rules
            )
        )
        return False

    if _find_recording_rule(loaded_rules, single_rule) is None:
        tap.diagnostic(
            "{}: Single log level rule not found after load. Loaded rules: {}".format(
                domain, loaded_rules
            )
        )
        return False

    client.destroy_session_by_name(session_name)

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
    # Tests that can run without root
    user_tests = [
        ("UST events save/load", test_ust_events_save_load, {}),
        ("UST filter expression save/load", test_ust_filter_expression_save_load, {}),
        (
            "UST wildcard with exclusions save/load",
            test_ust_wildcard_exclusions_save_load,
            {},
        ),
        ("UST log level save/load", test_ust_log_level_save_load, {}),
        ("UST VPID tracker save/load", test_ust_vpid_tracker_save_load, {}),
    ]

    # Tests for agent domains (need tracing daemon but not root)
    agent_tests = [
        (
            "JUL agent events save/load",
            test_agent_events_save_load,
            {"domain": lttngtest.TracingDomain.JUL},
        ),
        (
            "LOG4J agent events save/load",
            test_agent_events_save_load,
            {"domain": lttngtest.TracingDomain.Log4j},
        ),
        (
            "LOG4J2 agent events save/load",
            test_agent_events_save_load,
            {"domain": lttngtest.TracingDomain.Log4j2},
        ),
        (
            "PYTHON agent events save/load",
            test_agent_events_save_load,
            {"domain": lttngtest.TracingDomain.Python},
        ),
        (
            "JUL agent log level save/load",
            test_agent_log_level_save_load,
            {"domain": lttngtest.TracingDomain.JUL},
        ),
        (
            "LOG4J agent log level save/load",
            test_agent_log_level_save_load,
            {"domain": lttngtest.TracingDomain.Log4j},
        ),
        (
            "LOG4J2 agent log level save/load",
            test_agent_log_level_save_load,
            {"domain": lttngtest.TracingDomain.Log4j2},
        ),
        (
            "PYTHON agent log level save/load",
            test_agent_log_level_save_load,
            {"domain": lttngtest.TracingDomain.Python},
        ),
    ]

    # Tests requiring root privileges
    kernel_tests = [
        ("Kernel tracepoints save/load", test_kernel_tracepoints_save_load, {}),
        (
            "Kernel tracepoints filter save/load",
            test_kernel_tracepoints_filter_save_load,
            {},
        ),
        ("Kernel syscalls save/load", test_kernel_syscalls_save_load, {}),
        (
            "Kernel kprobe/function save/load",
            test_kernel_kprobe_function_save_load,
            {},
        ),
    ]

    # Tests requiring root privileges and destructive test mode (creates
    # temporary system users/groups).
    destructive_kernel_tests = [
        (
            "Kernel UID tracker by name save/load",
            test_kernel_uid_tracker_by_name_save_load,
            {},
        ),
        (
            "Kernel GID tracker by name save/load",
            test_kernel_gid_tracker_by_name_save_load,
            {},
        ),
    ]

    is_root = os.getuid() == 0
    allows_destructive = lttngtest._Environment.allows_destructive()

    total_tests = len(user_tests) + len(agent_tests)
    if is_root:
        total_tests += len(kernel_tests)
        if allows_destructive:
            total_tests += len(destructive_kernel_tests)

    tap = lttngtest.TapGenerator(total_tests)

    with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
        for test_name, test_func, kwargs in user_tests:
            run_test(tap, test_env, test_func, test_name, **kwargs)

        for test_name, test_func, kwargs in agent_tests:
            run_test(tap, test_env, test_func, test_name, **kwargs)

    if is_root:
        with lttngtest.test_environment(
            with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=True
        ) as test_env:
            for test_name, test_func, kwargs in kernel_tests:
                run_test(tap, test_env, test_func, test_name, **kwargs)

            if allows_destructive:
                for test_name, test_func, kwargs in destructive_kernel_tests:
                    run_test(tap, test_env, test_func, test_name, **kwargs)
            else:
                tap.diagnostic(
                    "Skipping destructive kernel tests (LTTNG_ENABLE_DESTRUCTIVE_TESTS not set)"
                )
    else:
        tap.diagnostic("Skipping kernel tests (not running as root)")

    sys.exit(0 if tap.is_successful else 1)
