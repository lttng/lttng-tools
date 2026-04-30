#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

import pathlib
import subprocess
import sys

# Import in-tree test utils
# Modify this depending on where the test file is in the tree
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest


def test_notification_channel_subscription_twice(
    tap: lttngtest.TapGenerator,
    test_env: lttngtest._Environment,
    domain: lttngtest.lttngctl.TracingDomain = lttngtest.lttngctl.TracingDomain.User,
    condition_type: lttngtest.lttngctl.ConditionType = lttngtest.lttngctl.ConditionType.BufferUsageLow,
) -> None:
    tap.diagnostic(
        "Running 'test_notification_channel_subscription_twice' with domain={}, condition_type={}".format(
            domain, condition_type
        )
    )
    notification_app = pathlib.Path(__file__).absolute().parents[0] / "notification"
    output_path = test_env.create_temporary_directory("trace")

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_path)
    )
    channel = session.add_channel(domain)
    if domain == lttngtest.lttngctl.TracingDomain.User:
        channel.add_recording_rule(
            lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
        )
    else:
        channel.add_recording_rule(
            lttngtest.lttngctl.KernelTracepointEventRule("lttng_test_filter_event")
        )

    session.start()
    args = [
        str(notification_app),
        "8",
        (
            "LTTNG_DOMAIN_UST"
            if domain == lttngtest.lttngctl.TracingDomain.User
            else "LTTNG_DOMAIN_KERNEL"
        ),
        str(-1),
        "/dev/null",
        session.name,
        channel.name,
        condition_type.value,
    ]
    tap.diagnostic("Launching test application: {}".format(args))
    p = subprocess.Popen(args, env=test_env.get_ust_test_app_env())
    p.wait()
    session.destroy()
    tap.test(
        p.returncode == 0,
        "Subscription test program completed successfully: returncode={}".format(
            p.returncode
        ),
    )


def test_triggers_buffer_usage_condition(
    tap: lttngtest.TapGenerator,
    test_env: lttngtest._Environment,
    domain: lttngtest.lttngctl.TracingDomain = lttngtest.lttngctl.TracingDomain.User,
    condition_type: lttngtest.lttngctl.ConditionType = lttngtest.lttngctl.ConditionType.BufferUsageLow,
) -> None:
    tap.diagnostic(
        "Running 'test_triggers_buffer_usage_condition' with domain={}, condition_type={}".format(
            domain, condition_type
        )
    )
    notification_app = pathlib.Path(__file__).absolute().parents[0] / "notification"
    output_path = test_env.create_temporary_directory("trace")

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_path)
    )
    channel = session.add_channel(domain)
    if domain == lttngtest.lttngctl.TracingDomain.User:
        channel.add_recording_rule(
            lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
        )
    else:
        channel.add_recording_rule(
            lttngtest.lttngctl.KernelTracepointEventRule("lttng_test_filter_event")
        )

    session.start()
    args = [
        str(notification_app),
        "9",
        (
            "LTTNG_DOMAIN_UST"
            if domain == lttngtest.lttngctl.TracingDomain.User
            else "LTTNG_DOMAIN_KERNEL"
        ),
        str(-1),
        "/dev/null",
        session.name,
        channel.name,
        condition_type.value,
    ]
    tap.diagnostic("Launching test application: {}".format(args))
    p = subprocess.Popen(args, env=test_env.get_ust_test_app_env())
    p.wait()
    session.destroy()
    tap.test(
        p.returncode == 0,
        "Trigger test program completed successfully: returncode={}".format(
            p.returncode
        ),
    )
