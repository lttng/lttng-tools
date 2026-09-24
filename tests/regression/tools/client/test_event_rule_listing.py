#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only

"""
Test the listing of recording rules associated to a channel.
"""

import pathlib
import sys
from typing import List

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest


def _describe_recording_rule(rule: lttngtest.UserTracepointEventRule) -> str:
    properties = []

    if isinstance(rule.log_level_rule, lttngtest.LogLevelRuleExactly):
        properties.append("log level exactly {}".format(rule.log_level_rule.level.name))
    elif isinstance(rule.log_level_rule, lttngtest.LogLevelRuleAsSevereAs):
        properties.append(
            "log level as severe as {}".format(rule.log_level_rule.level.name)
        )
    else:
        properties.append("any log level")

    if rule.filter_expression is not None:
        properties.append("filter `{}`".format(rule.filter_expression))

    if rule.name_pattern_exclusions:
        properties.append(
            "excluding {}".format(
                ", ".join(
                    "`{}`".format(exclusion)
                    for exclusion in rule.name_pattern_exclusions
                )
            )
        )

    description = "`{}`".format(rule.name_pattern)

    if properties:
        description += " ({})".format(", ".join(properties))

    return description


class _ExpectedRecordingRule:
    def __init__(self, rule: lttngtest.UserTracepointEventRule, enabled: bool):
        self.rule = rule
        self.enabled = enabled


def _test_listed_recording_rules(
    tap: lttngtest.TapGenerator,
    channel: lttngtest.Channel,
    expected_rules: List[_ExpectedRecordingRule],
) -> None:
    """
    Check that `channel` lists exactly the rules of `expected_rules`, each with
    its expected enabled state.
    """
    listed_rules = list(channel.recording_rules)

    tap.test(
        len(listed_rules) == len(expected_rules),
        "Channel lists {} recording rule(s)".format(len(expected_rules)),
    )

    for expected in expected_rules:
        matching_rules = [rule for rule in listed_rules if rule == expected.rule]
        tap.test(
            len(matching_rules) == 1 and matching_rules[0].enabled == expected.enabled,
            "Recording rule {} is listed once and {}".format(
                _describe_recording_rule(expected.rule),
                "enabled" if expected.enabled else "disabled",
            ),
        )


def test_recording_rules_differing_by_log_level_rule_type(
    tap: lttngtest.TapGenerator, test_env: lttngtest._Environment
) -> None:
    tap.diagnostic(
        "Test listing recording rules that differ only by their log level rule type"
    )

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session()
    channel = session.add_channel(lttngtest.TracingDomain.User)

    rule_exact_log_level = lttngtest.UserTracepointEventRule(
        "lttng*",
        None,
        lttngtest.LogLevelRuleExactly(lttngtest.UserLogLevel.DEBUG_LINE),
        None,
    )
    rule_as_severe_as_log_level = lttngtest.UserTracepointEventRule(
        "lttng*",
        None,
        lttngtest.LogLevelRuleAsSevereAs(lttngtest.UserLogLevel.DEBUG_LINE),
        None,
    )
    rule_no_log_level = lttngtest.UserTracepointEventRule("lttng*", None, None, None)

    channel.add_recording_rule(rule_exact_log_level)
    channel.add_recording_rule(rule_as_severe_as_log_level)
    channel.add_recording_rule(rule_no_log_level)

    tap.diagnostic("Listing after adding the three rules")
    _test_listed_recording_rules(
        tap,
        channel,
        [
            _ExpectedRecordingRule(rule_exact_log_level, enabled=True),
            _ExpectedRecordingRule(rule_as_severe_as_log_level, enabled=True),
            _ExpectedRecordingRule(rule_no_log_level, enabled=True),
        ],
    )


def test_recording_rules_differing_by_exclusions(
    tap: lttngtest.TapGenerator, test_env: lttngtest._Environment
) -> None:
    tap.diagnostic(
        "Test listing recording rules that differ only by their name pattern exclusions"
    )

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session()
    channel = session.add_channel(lttngtest.TracingDomain.User)

    log_level_rule = lttngtest.LogLevelRuleAsSevereAs(lttngtest.UserLogLevel.INFO)
    rule_excluding_hlm = lttngtest.UserTracepointEventRule(
        "*", None, log_level_rule, ["hlm_*"]
    )
    rule_excluding_gyproc = lttngtest.UserTracepointEventRule(
        "*", None, log_level_rule, ["gyproc_*"]
    )

    channel.add_recording_rule(rule_excluding_hlm)
    channel.add_recording_rule(rule_excluding_gyproc)

    tap.diagnostic("Listing after adding the two rules")
    _test_listed_recording_rules(
        tap,
        channel,
        [
            _ExpectedRecordingRule(rule_excluding_hlm, enabled=True),
            _ExpectedRecordingRule(rule_excluding_gyproc, enabled=True),
        ],
    )


tap = lttngtest.TapGenerator(7)
tap.diagnostic("Test the listing of recording rules associated to a channel")

with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
    test_recording_rules_differing_by_log_level_rule_type(tap, test_env)
    test_recording_rules_differing_by_exclusions(tap, test_env)

sys.exit(0 if tap.is_successful else 1)
