#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Olivier Dion <odion@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only

import os
import pathlib
import shlex
import sys

import xml.etree.ElementTree as xml

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest

"""
Ensure that legacy options, `--buffers-uid', `--buffers-pid' and
`--buffers-global' for the command `enable-channel' are working as before with
the introduction of the new `--buffer-ownership' option.
"""


def do_test_cli_buffer_ownership(
    client: lttngtest.LTTngClient,
    session: lttngtest.Session,
    legacy: str,
    new: str,
    expected_buffer_type: str,
    userspace: bool = True,
):

    def make_channel(ownership):
        name = lttngtest.lttngctl.Channel._generate_name()
        args = [
            "enable-channel",
            "--userspace" if userspace else "--kernel",
            "--session",
            session.name,
            ownership,
            name,
        ]
        client._run_cmd(" ".join(shlex.quote(x) for x in args))
        return name

    channel_names = {make_channel(legacy), make_channel(new)}
    session_xml = client.list_session_raw(session.name)

    # Check that only a single domain is present and that both channels are in it.
    domains = client._mi_get_in_element(session_xml, "domains")
    domain = domains[0]

    tap.test(
        client._mi_get_in_element(domain, "buffer_type").text == expected_buffer_type,
        "Domain has correct buffer type",
    )

    channels = client._mi_get_in_element(domain, "channels")

    for channel in channels:
        name = client._mi_get_in_element(channel, "name").text
        channel_names.remove(name)

    tap.test(
        len(channel_names) == 0, "All created channels were part of the same domain"
    )


def test_cli_buffer_ownership_userspace(
    client: lttngtest.LTTngClient, tap: lttngtest.TapGenerator
):
    # Userspace domains
    for legacy, new, buffer_type in [
        ("--buffers-uid", "--buffer-ownership=user", "PER_UID"),
        ("--buffers-pid", "--buffer-ownership=process", "PER_PID"),
    ]:
        tap.diagnostic("Testing buffer ownership: {} and {}".format(legacy, new))
        session = client.create_session()
        do_test_cli_buffer_ownership(client, session, legacy, new, buffer_type)
        session.destroy()


def test_cli_buffer_ownership_kernel(
    client: lttngtest.LTTngClient, tap: lttngtest.TapGenerator
):
    for legacy, new, buffer_type in [
        (
            "--buffers-global",
            "--buffer-ownership=system",
            "GLOBAL",
        )
    ]:
        tap.diagnostic("Testing buffer ownership: {} and {}".format(legacy, new))
        session = client.create_session()
        do_test_cli_buffer_ownership(
            client, session, legacy, new, buffer_type, userspace=False
        )
        session.destroy()


BUFFER_OWNERSHIP_COUNT = 3
TEST_PER_BUFFER_OWNERSHIP = 2

tap = lttngtest.TapGenerator(BUFFER_OWNERSHIP_COUNT * TEST_PER_BUFFER_OWNERSHIP)

with lttngtest.test_environment(
    with_sessiond=True, log=tap.diagnostic, enable_kernel_domain=True
) as test_env:
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    test_cli_buffer_ownership_userspace(client, tap)

    if test_env.run_kernel_tests():
        test_cli_buffer_ownership_kernel(client, tap)
    else:
        tap.skip_all_remaining(
            "Remaining tests require root to create kernel domain buffers"
        )

sys.exit(0 if tap.is_successful else 1)
