#!/usr/bin/env python3
#
# Copyright (C) 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only

import pathlib
import sys
import os
from typing import Any, Callable, Type, Dict, Iterator
import random
import string
from collections.abc import Mapping

"""
Test the listing of recording rules associated to a channel.
"""

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest


def test_identical_recording_rules_except_log_level_rule_type(tap, test_env):
    # type: (lttngtest.TapGenerator, lttngtest._Environment) -> None
    tap.diagnostic(
        "Test adding and listing event rules that differ only by their log level rule type"
    )

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

    session = client.create_session()
    channel = session.add_channel(lttngtest.TracingDomain.User)
    session.start()

    app = test_env.launch_wait_trace_test_application(100)

    llr_exactly = lttngtest.LogLevelRuleExactly(lttngtest.UserLogLevel.DEBUG_LINE)
    llr_as_severe_as = lttngtest.LogLevelRuleAsSevereAs(
        lttngtest.UserLogLevel.DEBUG_LINE
    )

    recording_rule_log_at_level = lttngtest.UserTracepointEventRule(
        "lttng*", None, llr_exactly, None
    )
    recording_rule_log_at_least_level = lttngtest.UserTracepointEventRule(
        "lttng*", None, llr_as_severe_as, None
    )
    recording_rule_no_log_level = lttngtest.UserTracepointEventRule(
        "lttng*", None, None, None
    )

    with tap.case("Adding a recording rule with an `exact` log level rule"):
        channel.add_recording_rule(recording_rule_log_at_level)

    with tap.case("Adding a recording rule with an `as severe as` log level rule"):
        channel.add_recording_rule(recording_rule_log_at_least_level)

    with tap.case(
        "Adding a recording rule without a log level rule (all log levels enabled)"
    ):
        channel.add_recording_rule(recording_rule_no_log_level)

    rule_match_count = 0
    for rule in channel.recording_rules:
        if (
            rule != recording_rule_no_log_level
            and rule != recording_rule_log_at_level
            and rule != recording_rule_log_at_least_level
        ):
            continue

        rule_match_count = rule_match_count + 1

    tap.test(
        rule_match_count == 3,
        "Recording rules are added and listed",
    )


tap = lttngtest.TapGenerator(4)
tap.diagnostic("Test the addition and listing of event rules associated to a channel")

with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
    test_identical_recording_rules_except_log_level_rule_type(tap, test_env)

sys.exit(0 if tap.is_successful else 1)
