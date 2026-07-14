#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Test that the counters of a user space map channel count the log
statements of the agent domains (JUL, Log4j 1.x, Log4j 2.x, and Python).

For each agent domain, this test registers, on a single map channel,
triggers which count:

* Every log statement of the first logger of the test application.

* The `INFO` log statements of that same logger only.

* The log statements of the second logger of the test application.

* The log statements of every logger of the domain.

It then runs the test application of the domain and confirms that each
counter holds the expected value.

Finally, it confirms that an agent "event rule matches" condition and an
"increment map value" action with a key template placeholder are
rejected.
"""

import pathlib
import sys

# Import in-tree test utils.
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest
import common

# Number of `INFO` log statements that the test application emits on its
# first logger, and therefore the expected value of the counter of a
# trigger counting them.
#
# The application also emits as many log statements of a more verbose log
# level (`DEBUG`, or `FINEST` for JUL) on that same logger, and a single
# `INFO` log statement on its second logger.
EVENT_COUNT = 10

# Number of tests of test_agent_map_channel(), which the TAP plan needs
# to skip the domains whose test application is unavailable.
TESTS_PER_DOMAIN = 6

# The agent domains, in the order in which they are tested.
AGENT_DOMAINS = [
    lttngtest.lttngctl.TracingDomain.JUL,
    lttngtest.lttngctl.TracingDomain.Log4j,
    lttngtest.lttngctl.TracingDomain.Log4j2,
    lttngtest.lttngctl.TracingDomain.Python,
]


# Reports, as a single test, whether the counter `key` of the map
# channels of `session` holds `expected_val`.
def _test_map_value(
    tap: lttngtest.TapGenerator,
    session: lttngtest.Session,
    key: str,
    expected_val: int,
    what: str,
) -> None:
    val = common.read_map_value(session, key)
    tap.test(
        val == expected_val,
        "counter `{}` ({}) is {} (expected {})".format(key, what, val, expected_val),
    )


# Reports, as a single test, whether registering a trigger which pairs an
# "event rule matches" condition of the agent domain `domain` with an
# "increment map value" action using the key template `key` (which
# carries a placeholder) fails.
def _test_placeholder_key_is_rejected(
    tap: lttngtest.TapGenerator,
    client: lttngtest.LTTngClient,
    session: lttngtest.Session,
    channel_name: str,
    domain: lttngtest.lttngctl.TracingDomain,
    key: str,
) -> None:
    try:
        common.add_agent_event_count_trigger(
            client, session, channel_name, domain, "*", key
        )
    except lttngtest.LTTngClientError:
        tap.test(True, "key template `{}` is rejected".format(key))
        return

    tap.test(False, "key template `{}` is rejected".format(key))


def test_agent_map_channel(
    test_env: lttngtest._Environment,
    tap: lttngtest.TapGenerator,
    domain: lttngtest.lttngctl.TracingDomain,
) -> None:
    app_descriptor = lttngtest.agent_test_application_descriptor(domain)
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("map-trace")
        )
    )

    channel = session.add_user_map_channel()

    for logger_name_pattern, key, log_level_rule in (
        # Every log statement of the first logger, whatever its log level.
        (app_descriptor.logger_name, "first-logger", None),
        # The `INFO` log statements of the first logger only, which the
        # more verbose statements of that same logger must not increment.
        (
            app_descriptor.logger_name,
            "first-logger-info",
            lttngtest.lttngctl.LogLevelRuleExactly(app_descriptor.info_log_level),
        ),
        # The log statements of the second logger, which the statements of
        # the first logger must not increment.
        (app_descriptor.second_logger_name, "second-logger", None),
        # The log statements of every logger of the domain.
        ("*", "any-logger", None),
    ):
        common.add_agent_event_count_trigger(
            client,
            session,
            channel.name,
            domain,
            logger_name_pattern,
            key,
            log_level_rule=log_level_rule,
        )

    # A key template placeholder names the user space event class of the
    # agent, which would be the same for every logger of the domain.
    for key in ("any-logger/{event_name}", "any-logger/{provider_name}"):
        _test_placeholder_key_is_rejected(
            tap, client, session, channel.name, domain, key
        )

    session.start()

    app = test_env.launch_agent_test_application(
        domain,
        EVENT_COUNT,
        fire_debug_events=True,
        fire_second_logger_event=True,
    )
    app.wait_for_exit()

    # The first logger emits an `INFO` and a more verbose log statement
    # per iteration; the second logger emits a single `INFO` statement.
    first_logger_event_count = 2 * EVENT_COUNT
    total_event_count = first_logger_event_count + 1

    _test_map_value(
        tap,
        session,
        "first-logger",
        first_logger_event_count,
        "every log statement of `{}`".format(app_descriptor.logger_name),
    )
    _test_map_value(
        tap,
        session,
        "first-logger-info",
        EVENT_COUNT,
        "`{}` log statements of `{}`".format(
            app_descriptor.info_log_level.name, app_descriptor.logger_name
        ),
    )
    _test_map_value(
        tap,
        session,
        "second-logger",
        1,
        "log statements of `{}`".format(app_descriptor.second_logger_name),
    )
    _test_map_value(
        tap,
        session,
        "any-logger",
        total_event_count,
        "log statements of every logger of the domain",
    )

    session.destroy()


tap = lttngtest.TapGenerator(TESTS_PER_DOMAIN * len(AGENT_DOMAINS))

for domain in AGENT_DOMAINS:
    if not lttngtest._Environment.run_agent_domain_tests(domain):
        tap.skip(
            "the {} test application is unavailable".format(domain.name),
            TESTS_PER_DOMAIN,
        )
        continue

    tap.diagnostic("Testing the {} agent domain".format(domain.name))

    with lttngtest.test_environment(
        with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=False
    ) as test_env:
        test_agent_map_channel(test_env, tap, domain)

sys.exit(0 if tap.is_successful else 1)
