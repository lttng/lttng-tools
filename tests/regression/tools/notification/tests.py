#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

import pathlib
import platform
import signal
import subprocess
import sys
import time

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


def test_buffer_usage_notification_channel(
    tap: lttngtest.TapGenerator,
    test_env: lttngtest._Environment,
    domain: lttngtest.lttngctl.TracingDomain = lttngtest.lttngctl.TracingDomain.User,
) -> None:
    tap.diagnostic(
        "Running 'test_buffer_usage_notification_channel' with domain={}".format(domain)
    )
    event_generator_script = (
        pathlib.Path(__file__).absolute().parents[0] / "util_event_generator.py"
    )
    notification_app = pathlib.Path(__file__).absolute().parents[0] / "notification"
    output_path = test_env.create_temporary_directory("trace")

    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_path)
    )
    channel = session.add_channel(domain, subbuf_size=lttngtest.getconf("PAGE_SIZE"))
    if domain == lttngtest.lttngctl.TracingDomain.User:
        channel.add_recording_rule(
            lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
        )
    else:
        channel.add_recording_rule(
            lttngtest.lttngctl.KernelTracepointEventRule("lttng_test_filter_event")
        )

    # Spawn test event_generator_script with ready_file, state_file,
    # and ( 'userspace_testapp' or 'kernel_generate_filter_events')
    temp_dir = test_env.create_temporary_directory()
    ready_file_path = temp_dir / "generator_ready"
    state_file_path = temp_dir / "testapp_state"
    state_file_path.touch()
    args = [
        str(event_generator_script),
        "--ready-file",
        str(ready_file_path),
        "--state-file",
        str(state_file_path),
        (
            "userspace_testapp"
            if domain == lttngtest.lttngctl.TracingDomain.User
            else "kernel_generate_filter_events"
        ),
    ]
    event_generator_env = test_env.get_ust_test_app_env()
    event_generator_env["EVENT_GENERATOR_SCRIPT"] = str(
        test_env._project_root / "tests" / "utils" / "testapp" / "gen-ust-events"
    )
    tap.diagnostic("Running event generator script: {}".format(args))
    event_generator = subprocess.Popen(args, env=event_generator_env)

    # Wait until ready file is present
    while not ready_file_path.exists():
        time.sleep(0.1)
        if event_generator.poll() is not None:
            # The event_generator has terminated
            raise Exception(
                "event_generator has terminated earlier than expected: ret={}".format(
                    event_generator.poll()
                )
            )

    consumerd_type = (
        lttngtest.ConsumerType.KERNEL
        if domain == lttngtest.lttngctl.TracingDomain.Kernel
        else (
            lttngtest.ConsumerType.UST64
            if platform.architecture()[0] == "64bit"
            else lttngtest.ConsumerType.UST32
        )
    )
    args = [
        str(notification_app),
        "2",
        (
            "LTTNG_DOMAIN_UST"
            if domain == lttngtest.lttngctl.TracingDomain.User
            else "LTTNG_DOMAIN_KERNEL"
        ),
        str(event_generator.pid),
        str(state_file_path),
        session.name,
        channel.name,
        str(test_env.lttng_consumerd_get_pid(consumerd_type)),
    ]
    tap.diagnostic("Launching test application: {}".format(args))
    p = subprocess.Popen(args, env=test_env.get_ust_test_app_env())
    p.wait()
    tap.test(
        p.returncode == 0,
        "Trigger test program completed successfully: returncode={}".format(
            p.returncode
        ),
    )

    session.stop()
    session.destroy()
    event_generator.send_signal(signal.SIGUSR2)
    event_generator.wait()
