#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Validate that a simple call to `lttng reclaim-memory` will work
"""

import pathlib
import sys
import xml.etree.ElementTree


# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest


def test(tap, test_env, wait=False):
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session()
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User,
        buffer_sharing_policy=lttngtest.lttngctl.BufferSharingPolicy.PerUID,
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()

    app = test_env.launch_wait_trace_test_application(10)
    app.trace()

    args = ["reclaim-memory", "-u", channel.name]
    if not wait:
        args.append("--no-wait")

    try:
        # Python >= 3.8: use shlex.join()
        output, error = client._run_cmd(
            " ".join(args), lttngtest.LTTngClient.CommandOutputFormat.MI_XML
        )

        try:
            root = xml.etree.ElementTree.fromstring(output)
            command_output = lttngtest.LTTngClient._mi_get_in_element(root, "output")
            channels_elem = lttngtest.LTTngClient._mi_get_in_element(
                command_output, "channels"
            )

            # Look for matching channel with valid reclaimed_subbuffers
            test_pass = False
            for chan in channels_elem:
                name_elem = lttngtest.LTTngClient._mi_find_in_element(chan, "name")
                reclaimed_elem = lttngtest.LTTngClient._mi_find_in_element(
                    chan, "reclaimed_subbuffers"
                )

                if name_elem is not None and name_elem.text == channel.name:
                    if reclaimed_elem is not None and reclaimed_elem.text is not None:
                        try:
                            # Check if reclaimed_subbuffers is a valid number
                            reclaimed_value = int(reclaimed_elem.text)
                            test_pass = True
                            tap.diagnostic(
                                "Channel '{}' has {} sub-buffer(s) reclaimed".format(
                                    channel.name, reclaimed_value
                                )
                            )
                            break
                        except (ValueError, TypeError):
                            tap.diagnostic(
                                "reclaimed_subbuffers value '{}' is not a valid number".format(
                                    reclaimed_elem.text
                                )
                            )

            if not test_pass:
                tap.diagnostic(
                    "Could not find channel '{}' with valid reclaimed_subbuffers in XML output: {}".format(
                        channel.name, output
                    )
                )
        except xml.etree.ElementTree.ParseError as xml_err:
            tap.diagnostic(
                "Failed to parse XML output: {}. Output was: {}".format(
                    str(xml_err), output
                )
            )
        except lttngtest.InvalidMI as mi_err:
            tap.diagnostic(
                "Invalid MI structure: {}. Output was: {}".format(str(mi_err), output)
            )

    except Exception as e:
        tap.diagnostic("Exception while running client command: {}".format(str(e)))
        test_pass = False

    tap.test(test_pass, "Reclaim memory (wait={}) finished with no error".format(wait))


if __name__ == "__main__":
    cases = {
        "reclaim with wait": {
            "function": test,
            "args": [],
            "kwargs": {
                "wait": True,
            },
        },
        "reclaim with --no-wait": {
            "function": test,
            "args": [],
            "kwargs": {
                "wait": False,
            },
        },
    }

    tap = lttngtest.TapGenerator(len(cases))
    for test_case_name, test_case in cases.items():
        tap.diagnostic("Running test case '{}'".format(test_case_name))
        with lttngtest.test_environment(
            with_sessiond=True, log=tap.diagnostic
        ) as test_env:
            test_case["function"](
                tap=tap, test_env=test_env, *test_case["args"], **test_case["kwargs"]
            )

    sys.exit(0 if tap.is_successful else 1)
