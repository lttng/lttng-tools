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
Test the session commands of the `lttng` CLI client.
"""

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest
import bt2


class SessionSet(Mapping):
    def __init__(self, client, name_prefixes):
        self._sessions = {}  # type dict[str, lttngtest.Session]
        for prefix in name_prefixes:
            new_session = client.create_session(
                name=self._generate_session_name_from_prefix(prefix),
                output=lttngtest.LocalSessionOutputLocation(
                    test_env.create_temporary_directory("trace")
                ),
            )
            # Add a channel to all sessions to ensure the sessions can be started.
            new_session.add_channel(lttngtest.TracingDomain.User)
            self._sessions[prefix] = new_session

    @staticmethod
    def _generate_session_name_from_prefix(prefix):
        # type: (str) -> str
        return (
            prefix
            + "_"
            + "".join(
                random.choice(string.ascii_lowercase + string.digits) for _ in range(8)
            )
        )

    def __getitem__(self, __key):
        # type: (str) -> lttngtest.Session
        return self._sessions[__key]

    def __len__(self):
        # type: () -> int
        return len(self._sessions)

    def __iter__(self):
        # type: () -> Iterator[str]
        return iter(self._sessions)


def test_start_globbing(tap, test_env):
    # type: (lttngtest.TapGenerator, lttngtest._Environment) -> None
    tap.diagnostic("Test --glob match of start command")
    name_prefixes = ["abba", "alakazou", "alakazam"]

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

    tap.diagnostic("Create a set of sessions to test globbing")
    sessions = None
    with tap.case(
        "Create sessions with prefixes [{}]".format(", ".join(name_prefixes))
    ) as test_case:
        sessions = SessionSet(client, name_prefixes)

    tap.test(
        all(not session.is_active for prefix, session in sessions.items()),
        "All sessions created are in the inactive state",
    )

    start_pattern = "alak*"
    with tap.case("Start sessions with --glob={}".format(start_pattern)) as test_case:
        client.start_session_by_glob_pattern(start_pattern)

    tap.test(
        sessions["alakazou"].is_active
        and sessions["alakazam"].is_active
        and not sessions["abba"].is_active,
        "Only sessions 'alakazou' and 'alakazam' are active",
    )

    with tap.case(
        "Starting already started sessions with --glob={} doesn't produce an error".format(
            start_pattern
        )
    ) as test_case:
        client.start_session_by_glob_pattern(start_pattern)

    start_pattern = "tintina*"
    with tap.case(
        "Starting with --glob={} that doesn't match any session doesn't produce an error".format(
            start_pattern
        )
    ) as test_case:
        client.start_session_by_glob_pattern(start_pattern)

    for name, session in sessions.items():
        session.destroy()

    with tap.case(
        "Starting with --glob={} when no sessions exist doesn't produce an error".format(
            start_pattern
        )
    ) as test_case:
        client.start_session_by_glob_pattern(start_pattern)


def test_start_single(tap, test_env):
    # type: (lttngtest.TapGenerator, lttngtest._Environment) -> None
    tap.diagnostic("Test match of start command targeting a single session")
    name_prefixes = ["un", "deux", "patate", "pouel"]

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

    tap.diagnostic("Create a set of sessions to test single session start")
    sessions = None
    with tap.case(
        "Create sessions with prefixes [{}]".format(", ".join(name_prefixes))
    ) as test_case:
        sessions = SessionSet(client, name_prefixes)

    tap.test(
        all(not session.is_active for prefix, session in sessions.items()),
        "All sessions created are in the inactive state",
    )

    session_to_start_prefix = "patate"
    full_session_name = sessions[session_to_start_prefix].name
    with tap.case("Start session '{}'".format(session_to_start_prefix)) as test_case:
        client.start_session_by_name(full_session_name)

    tap.test(
        any(
            session.is_active and prefix != session_to_start_prefix
            for prefix, session in sessions.items()
        )
        is False,
        "Only session '{}' is active".format(session_to_start_prefix),
    )

    with tap.case(
        "Starting already started session '{}' doesn't produce an error".format(
            session_to_start_prefix
        )
    ) as test_case:
        client.start_session_by_name(full_session_name)

    for name, session in sessions.items():
        session.destroy()


def test_start_all(tap, test_env):
    # type: (lttngtest.TapGenerator, lttngtest._Environment) -> None
    tap.diagnostic("Test start command with the --all option")
    name_prefixes = ["a", "b", "c", "d"]

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

    tap.diagnostic("Create a set of sessions to test starting all sessions")
    sessions = None
    with tap.case(
        "Create sessions with prefixes [{}]".format(", ".join(name_prefixes))
    ) as test_case:
        sessions = SessionSet(client, name_prefixes)

    tap.test(
        all(not session.is_active for prefix, session in sessions.items()),
        "All sessions created are in the inactive state",
    )

    with tap.case("Start all sessions") as test_case:
        client.start_sessions_all()

    tap.test(
        all(session.is_active for prefix, session in sessions.items()),
        "All sessions are active",
    )

    with tap.case("Starting already started sessions") as test_case:
        client.start_sessions_all()

    for name, session in sessions.items():
        session.destroy()

    with tap.case(
        "Starting all sessions when none exist doesn't produce an error"
    ) as test_case:
        client.start_sessions_all()


def test_stop_globbing(tap, test_env):
    # type: (lttngtest.TapGenerator, lttngtest._Environment) -> None
    tap.diagnostic("Test --glob match of stop command")
    name_prefixes = ["East Farnham", "Amqui", "Amos"]

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

    tap.diagnostic("Create a set of sessions to test globbing")
    sessions = None
    with tap.case(
        "Create sessions with prefixes [{}]".format(", ".join(name_prefixes))
    ) as test_case:
        sessions = SessionSet(client, name_prefixes)

    client.start_sessions_all()
    tap.test(
        all(session.is_active for prefix, session in sessions.items()),
        "All sessions are in the active state",
    )

    stop_pattern = "Am??i*"
    with tap.case("Stop sessions with --glob={}".format(stop_pattern)) as test_case:
        client.stop_session_by_glob_pattern(stop_pattern)

    tap.test(
        (
            sessions["East Farnham"].is_active
            and sessions["Amos"].is_active
            and (not sessions["Amqui"].is_active)
        ),
        "Only session 'Amqui' is inactive",
    )

    stop_pattern = "Am*"
    with tap.case(
        "Stopping more sessions, including a stopped session, with --glob={} doesn't produce an error".format(
            stop_pattern
        )
    ) as test_case:
        client.stop_session_by_glob_pattern(stop_pattern)

    tap.test(
        sessions["East Farnham"].is_active
        and (not sessions["Amqui"].is_active)
        and (not sessions["Amos"].is_active),
        "Only session 'East Farnham' is active",
    )

    stop_pattern = "Notre-Dame*"
    with tap.case(
        "Stopping with --glob={} that doesn't match any session doesn't produce an error".format(
            stop_pattern
        )
    ) as test_case:
        client.stop_session_by_glob_pattern(stop_pattern)

    for name, session in sessions.items():
        session.destroy()

    with tap.case(
        "Stopping with --glob={} when no sessions exist doesn't produce an error".format(
            stop_pattern
        )
    ) as test_case:
        client.stop_session_by_glob_pattern(stop_pattern)


def test_stop_single(tap, test_env):
    # type: (lttngtest.TapGenerator, lttngtest._Environment) -> None
    tap.diagnostic("Test match of stop command targeting a single session")
    name_prefixes = ["Grosses-Roches", "Kazabazua", "Laval", "Magog"]

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

    tap.diagnostic("Create a set of sessions to test single session stop")
    sessions = None
    with tap.case(
        "Create sessions with prefixes [{}]".format(", ".join(name_prefixes))
    ) as test_case:
        sessions = SessionSet(client, name_prefixes)

    client.start_sessions_all()
    tap.test(
        all(session.is_active for prefix, session in sessions.items()),
        "All sessions are in the active state",
    )

    session_to_stop_prefix = "Kazabazua"
    full_session_name = sessions[session_to_stop_prefix].name
    with tap.case("Stop session '{}'".format(session_to_stop_prefix)) as test_case:
        client.stop_session_by_name(full_session_name)

    inactive_session_prefixes = [
        prefix for prefix, session in sessions.items() if not session.is_active
    ]
    tap.test(
        len(inactive_session_prefixes) == 1
        and inactive_session_prefixes[0] == session_to_stop_prefix,
        "Only session '{}' is inactive".format(session_to_stop_prefix),
    )

    with tap.case(
        "Stopping already stopped session '{}' doesn't produce an error".format(
            session_to_stop_prefix
        )
    ) as test_case:
        client.stop_session_by_name(full_session_name)

    for name, session in sessions.items():
        session.destroy()


def test_stop_all(tap, test_env):
    # type: (lttngtest.TapGenerator, lttngtest._Environment) -> None
    tap.diagnostic("Test stop command with the --all option")
    name_prefixes = ["a", "b", "c", "d"]

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

    tap.diagnostic("Create a set of sessions to test stopping all sessions")
    sessions = None
    with tap.case(
        "Create sessions with prefixes [{}]".format(", ".join(name_prefixes))
    ) as test_case:
        sessions = SessionSet(client, name_prefixes)

    client.start_sessions_all()
    tap.test(
        all(session.is_active for prefix, session in sessions.items()),
        "All sessions are in the active state",
    )

    with tap.case("Stop all sessions") as test_case:
        client.stop_sessions_all()

    tap.test(
        all(not session.is_active for prefix, session in sessions.items()),
        "All sessions are inactive",
    )

    with tap.case("Stopping already stopped sessions") as test_case:
        client.stop_sessions_all()

    for name, session in sessions.items():
        session.destroy()

    with tap.case(
        "Stopping all sessions when none exist doesn't produce an error"
    ) as test_case:
        client.stop_sessions_all()


def test_destroy_globbing(tap, test_env):
    # type: (lttngtest.TapGenerator, lttngtest._Environment) -> None
    tap.diagnostic("Test --glob match of destroy command")
    name_prefixes = ["Mont-Laurier", "Montreal", "Montmagny", "Neuville"]

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

    tap.diagnostic("Create a set of sessions to test globbing")
    sessions = None
    with tap.case(
        "Create sessions with prefixes [{}]".format(", ".join(name_prefixes))
    ) as test_case:
        sessions = SessionSet(client, name_prefixes)

    destroy_pattern = "Mont*"
    with tap.case(
        "Destroy sessions with --glob={}".format(destroy_pattern)
    ) as test_case:
        client.destroy_session_by_glob_pattern(destroy_pattern)

    listed_sessions = client.list_sessions()
    tap.test(
        len(listed_sessions) == 1
        and listed_sessions[0].name == sessions["Neuville"].name,
        "Neuville is the only remaining session",
    )

    for session in listed_sessions:
        session.destroy()

    with tap.case(
        "Destroying with --glob={} when no sessions exist doesn't produce an error".format(
            destroy_pattern
        )
    ) as test_case:
        client.destroy_session_by_glob_pattern(destroy_pattern)


def test_destroy_single(tap, test_env):
    # type: (lttngtest.TapGenerator, lttngtest._Environment) -> None
    tap.diagnostic("Test match of destroy command targeting a single session")
    name_prefixes = ["Natashquan", "Normetal", "Notre-Dame-des-Sept-Douleurs"]

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

    tap.diagnostic("Create a set of sessions to test single session destruction")
    sessions = None
    with tap.case(
        "Create sessions with prefixes [{}]".format(", ".join(name_prefixes))
    ) as test_case:
        sessions = SessionSet(client, name_prefixes)

    session_to_destroy_prefix = "Normetal"
    full_session_name = sessions[session_to_destroy_prefix].name
    with tap.case(
        "Destroy session '{}'".format(session_to_destroy_prefix)
    ) as test_case:
        client.destroy_session_by_name(full_session_name)

    listed_sessions = client.list_sessions()
    tap.test(
        len(listed_sessions) == 2
        and full_session_name not in [session.name for session in listed_sessions],
        "Session '{}' no longer exists".format(session_to_destroy_prefix),
    )

    for session in listed_sessions:
        session.destroy()


def test_destroy_all(tap, test_env):
    # type: (lttngtest.TapGenerator, lttngtest._Environment) -> None
    tap.diagnostic("Test destroy command with the --all option")
    name_prefixes = ["a", "b", "c", "d"]

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)

    tap.diagnostic("Create a set of sessions to test destroying all sessions")
    sessions = None
    with tap.case(
        "Create sessions with prefixes [{}]".format(", ".join(name_prefixes))
    ) as test_case:
        sessions = SessionSet(client, name_prefixes)

    with tap.case("Destroy all sessions") as test_case:
        client.destroy_sessions_all()

    tap.test(
        len(client.list_sessions()) == 0,
        "No sessions exist after destroying all sessions",
    )

    with tap.case(
        "Destroy all sessions when none exist doesn't produce an error"
    ) as test_case:
        client.destroy_sessions_all()


tap = lttngtest.TapGenerator(48)
tap.diagnostic("Test client session command --glob and --all options")

with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
    test_start_globbing(tap, test_env)

with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
    test_start_single(tap, test_env)

with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
    test_start_all(tap, test_env)

with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
    test_stop_globbing(tap, test_env)

with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
    test_stop_single(tap, test_env)

with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
    test_stop_all(tap, test_env)

with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
    test_destroy_globbing(tap, test_env)

with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
    test_destroy_single(tap, test_env)

with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
    test_destroy_all(tap, test_env)

sys.exit(0 if tap.is_successful else 1)
