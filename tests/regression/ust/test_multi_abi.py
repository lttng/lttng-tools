#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Given the build profiles the framework discovered (the in-tree build plus any
found through LTTNG_TOOLS_BUILD_PROFILE_DIR), this runs a tracing session for
every combination of:

  - the build providing each word size's test application and its matching
    consumer daemon. An application is always consumed by a consumer daemon of
    its own build (so that their LTTng-UST ABI matches exactly), hence the two
    are chosen together rather than independently;
  - the session daemon's build;
  - the client's build;
  - the relay daemon's build, or none at all (a local session).

Each scenario traces one application per word size at the same time (so both
consumer daemons are exercised) and checks that every application's events were
recorded.

Combinations where the client and session daemon have different word sizes are
skipped: there are known issues that apparently cause liblttng-ctl's protocol
with the session daemon to not be word-size portable, so such a pairing is a
known-broken configuration rather than something this test exercises (the
consumer daemon, application and relay daemon boundaries, in contrast, are
ABI-independent and are covered in both directions).

The test is skipped unless profiles of at least two word sizes are available
(e.g. a 32-bit build in addition to the in-tree 64-bit one); point the
test to them through LTTNG_TOOLS_BUILD_PROFILE_DIR.
"""

import itertools
import logging
import pathlib
import sys
from typing import List, Optional, Sequence

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[2] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest


class Scenario:
    """
    One run of the matrix: the build providing each component, plus the builds
    whose applications are traced. `app_builds` holds one build per word size;
    each build is both the application traced and its matching consumer daemon
    (an application is always consumed by a consumer daemon of its own build, so
    the LTTng-UST ABI matches exactly). `relayd` is None for a local session.
    """

    def __init__(
        self,
        sessiond: lttngtest._BuildProfile,
        client: lttngtest._BuildProfile,
        relayd: Optional[lttngtest._BuildProfile],
        test_apps: Sequence[lttngtest._BuildProfile],
    ) -> None:
        self.sessiond = sessiond
        self.client = client
        self.relayd = relayd
        self.test_apps = test_apps

    @property
    def description(self) -> str:
        return "sessiond=`{}` client=`{}` apps/consumerds=[{}] relayd={}".format(
            self.sessiond.name,
            self.client.name,
            ", ".join("`{}`".format(build.name) for build in self.test_apps),
            "none" if self.relayd is None else "`{}`".format(self.relayd.name),
        )


def build_scenarios(profiles: List[lttngtest._BuildProfile]) -> List[Scenario]:
    """Every component/build-profile combination to exercise, one per planned test."""
    word_sizes_bits = sorted({profile.word_size_bits for profile in profiles})

    # The builds that can provide each word size's application and matching
    # consumer daemon; one build per word size is picked per scenario.
    builds_by_word_size_bits = [
        lttngtest._Environment.profiles_with_word_size_bits(word_size_bits)
        for word_size_bits in word_sizes_bits
    ]
    test_app_build_combinations = list(itertools.product(*builds_by_word_size_bits))

    # A relay daemon of any build, or none at all (a local session).
    relayd_options = [None] + profiles

    return [
        Scenario(sessiond=sessiond, client=client, relayd=relayd, test_apps=test_apps)
        for sessiond, test_apps, client, relayd in itertools.product(
            profiles, test_app_build_combinations, profiles, relayd_options
        )
    ]


def trace_scenario(
    test_env: lttngtest._Environment,
    tap: lttngtest.TapGenerator,
    scenario: Scenario,
    description: str,
) -> None:
    event_count_per_application = 10

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

    if scenario.relayd is None:
        output = lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("trace")
        )
    else:
        output = lttngtest.NetworkSessionOutputLocation(
            "net://localhost:{}:{}/".format(
                test_env.lttng_relayd_control_port, test_env.lttng_relayd_data_port
            )
        )

    session = client.create_session(output=output)
    channel = session.add_channel(lttngtest.lttngctl.TracingDomain.User)
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()

    # One application per word size; each registers to the session daemon, which
    # spawns the matching consumer daemon (the same build as the application).
    applications = [
        test_env.launch_wait_trace_test_application(
            event_count_per_application, profile=build
        )
        for build in scenario.test_apps
    ]
    for application in applications:
        application.trace()
    for application in applications:
        application.wait_for_tracing_done()
        application.wait_for_exit()

    session.stop()

    if scenario.relayd is None:
        received, discarded = lttngtest.count_events(output.path)
    else:
        relayd_output_path = pathlib.Path(test_env.lttng_relayd_output_path)
        received, discarded = lttngtest.count_events(
            relayd_output_path.glob("{}*".format(session.name))
        )

    expected = event_count_per_application * len(applications)
    session.destroy()

    tap.test(
        received == expected and discarded == 0,
        "{}: received {} of {} events ({} discarded)".format(
            description, received, expected, discarded
        ),
    )


def run_scenario(scenario: Scenario, tap: lttngtest.TapGenerator) -> None:
    description = scenario.description

    # A client and session daemon of different ABIs do not interoperate:
    # a bug prevents liblttng-ctl's protocol with the session daemon from
    # being word-size portable (the "enable-channel" channel payload, for
    # instance). This is a known issue, so those combinations are skipped
    # for the moment.
    if scenario.client.word_size_bits != scenario.sessiond.word_size_bits:
        tap.skip(
            "{}: client/session daemon ABI mismatch (known broken)".format(description)
        )
        return

    # A failure to set up or trace a scenario (e.g. a daemon that fails to
    # launch) is recorded as a failed test so that the rest of the matrix runs.
    try:
        with lttngtest.test_environment(
            with_sessiond=True,
            with_relayd=scenario.relayd is not None,
            log=tap.diagnostic,
            sessiond_profile=scenario.sessiond,
            client_profile=scenario.client,
            relayd_profile=scenario.relayd,
            consumerd_profiles=list(scenario.test_apps),
        ) as test_env:
            trace_scenario(test_env, tap, scenario, description)
    except Exception as scenario_error:
        logging.exception("Unhandled exception during scenario %s", description)
        tap.fail("{}: {}".format(description, scenario_error))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format=lttngtest.utils.get_logging_format())

    profiles = lttngtest._Environment.profiles()

    if len({profile.word_size_bits for profile in profiles}) < 2:
        tap = lttngtest.TapGenerator(1)
        tap.skip_all_remaining(
            "Fewer than two ABIs available; set LTTNG_TOOLS_BUILD_PROFILE_DIR"
        )
        sys.exit(0)

    scenarios = build_scenarios(profiles)
    tap = lttngtest.TapGenerator(len(scenarios))

    tap.diagnostic("Planned {} scenario(s):".format(len(scenarios)))
    for scenario in scenarios:
        tap.diagnostic("  {}".format(scenario.description))

    for scenario in scenarios:
        run_scenario(scenario, tap)

    sys.exit(0 if tap.is_successful else 1)
