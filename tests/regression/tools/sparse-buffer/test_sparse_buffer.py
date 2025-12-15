#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Olivier Dion <odion@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only

import itertools
import mmap
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import traceback

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest

"""
This test suite validates some properties of sparse buffers.

See individual tests docstring.
"""


def gdb_exists():
    """Return True if GDB can be executed."""
    return shutil.which("gdb") is not None


def get_consumerd_pid(sessiond_pid):
    """
    Get the PID of the UST consumer daemon that is a child of the session daemon.

    Returns None if no matching consumer daemon is found.
    """
    try:
        process = subprocess.Popen(
            ["pgrep", "-P", str(sessiond_pid), "-f", "ustconsumerd"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        process.wait()
        output = str(process.stdout.read(), encoding="UTF-8").splitlines()
        if len(output) == 1:
            return int(output[0])
    except Exception:
        pass
    return None


def wait_for_memory_reclaim_timer(test_env, log, channel_names):
    """
    Wait for the memory reclaim timer to fire for the specified channels.

    This function attaches GDB to the consumer daemon and sets conditional
    breakpoints on the memory_reclaim_timer_task::_run method for each channel.
    It waits for each breakpoint to be hit and the function to return, ensuring
    that memory reclamation has completed for all specified channels.
    """
    sessiond_pid = test_env._sessiond.pid
    consumerd_pid = get_consumerd_pid(sessiond_pid)

    if consumerd_pid is None:
        raise RuntimeError(
            "Could not find consumer daemon (child of sessiond pid {})".format(
                sessiond_pid
            )
        )

    log("Found consumer daemon with PID {}".format(consumerd_pid))

    # Create a temporary directory for the GDB script
    script_dir = tempfile.mkdtemp(prefix="gdb_sync_")
    gdb_script_path = os.path.join(script_dir, "gdb_script")

    try:
        gdb_commands = [
            "set breakpoint pending on",
            "set pagination off",
        ]

        # Set debug file directory if specified
        gdb_debug_directory = os.getenv("GDB_DEBUG_FILE_DIRECTORY")
        if gdb_debug_directory:
            gdb_commands.append(
                "set debug-file-directory {}".format(gdb_debug_directory)
            )

        gdb_commands.append("attach {}".format(consumerd_pid))

        # For each channel: set breakpoint, continue until hit, finish, delete breakpoint
        # This ensures we wait for each specific channel's timer to fire exactly once
        for i, channel_name in enumerate(channel_names, start=1):
            gdb_commands.append(
                'break lttng::consumer::memory_reclaim_timer_task::_run if $_streq(this->_channel.name, "{}")'.format(
                    channel_name
                )
            )
            gdb_commands.extend(["continue", "finish", "delete {}".format(i)])

        gdb_commands.extend(["detach", "quit"])

        with open(gdb_script_path, "w") as f:
            for cmd in gdb_commands:
                f.write(cmd + "\n")

        log("GDB script contents:")
        for cmd in gdb_commands:
            log("  {}".format(cmd))

        gdb_args = ["gdb", "--nx", "--nw", "--batch", "-x", gdb_script_path]

        log(
            "Running GDB to wait for memory reclaim timer on channels: {}".format(
                ", ".join(channel_names)
            )
        )

        with subprocess.Popen(
            gdb_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        ) as process:
            output, _ = process.communicate()

        for line in output.decode("utf-8", errors="ignore").splitlines():
            log("GDB: {}".format(line))

        if process.returncode != 0:
            raise RuntimeError(
                "GDB exited with non-zero return code: {}".format(process.returncode)
            )

        log("Memory reclaim timer has fired for all channels")

    finally:
        shutil.rmtree(script_dir, ignore_errors=True)


def channel_preallocation_policy_from_session(client, channel_name, session_name):
    """
    Return the value of the channel attribute `preallocation_policy` of the
    channel matching `channel_name` of the first domain listed in
    `session_name`.
    """

    session_xml = client.list_session_raw(session_name)

    domain_xml = client._mi_get_in_element(session_xml, "domains")[0]

    for channel_xml in client._mi_get_in_element(domain_xml, "channels"):

        name = client._mi_get_in_element(channel_xml, "name").text

        if name != channel_name:
            continue

        channel_attributes_xml = client._mi_get_in_element(channel_xml, "attributes")

        return client._mi_get_in_element(
            channel_attributes_xml, "preallocation_policy"
        ).text

    return None


def channel_reclaim_policy_from_session(client, channel_name, session_name):
    """
    Return the value of the channel attribute `reclaim_policy` of the
    channel matching `channel_name` of the first domain listed in
    `session_name`.
    """

    session_xml = client.list_session_raw(session_name)

    domain_xml = client._mi_get_in_element(session_xml, "domains")[0]

    for channel_xml in client._mi_get_in_element(domain_xml, "channels"):

        name = client._mi_get_in_element(channel_xml, "name").text

        if name != channel_name:
            continue

        channel_attributes_xml = client._mi_get_in_element(channel_xml, "attributes")

        try:
            policy_xml = client._mi_get_in_element(
                channel_attributes_xml, "reclaim_policy"
            )
        except lttngtest.lttng.InvalidMI:
            return None

        try:
            periodic_reclaim_xml = client._mi_get_in_element(policy_xml, "periodic")
            age_xml = client._mi_get_in_element(periodic_reclaim_xml, "age_threshold")
            return int(age_xml.text)
        except lttngtest.lttng.InvalidMI:
            # Not periodic, check if it's consumed policy (raises if not present).
            client._mi_get_in_element(policy_xml, "consumed")
            return 0

    return None


def get_channel_memory_usage_bytes(client, session_name, channel_name):

    session_xml = client.list_session_raw(session_name)
    domain_xml = client._mi_get_in_element(session_xml, "domains")[0]

    for channel_xml in client._mi_get_in_element(domain_xml, "channels"):

        name = client._mi_get_in_element(channel_xml, "name").text

        if name != channel_name:
            continue

        data_stream_info_sets_xml = client._mi_get_in_element(
            channel_xml, "data_stream_info_sets"
        )

        total_memory_usage_bytes = client._mi_get_in_element(
            data_stream_info_sets_xml, "total_memory_usage_bytes"
        )

        return int(total_memory_usage_bytes.text)

    return -1


def get_channel_data_streams_count(client, session_name, channel_name):

    session_xml = client.list_session_raw(session_name)
    domain_xml = client._mi_get_in_element(session_xml, "domains")[0]

    for channel_xml in client._mi_get_in_element(domain_xml, "channels"):

        name = client._mi_get_in_element(channel_xml, "name").text

        if name != channel_name:
            continue

        data_stream_info_sets_xml = client._mi_get_in_element(
            channel_xml, "data_stream_info_sets"
        )

        sets_xml = client._mi_get_in_element(data_stream_info_sets_xml, "sets")

        total = 0

        for set_xml in sets_xml:
            stream_info_list_xml = client._mi_get_in_element(
                set_xml, "data_stream_info_list"
            )
            total += len(stream_info_list_xml)

        return total

    return -1


def test_memory_reclamation_convergence(
    tap,
    test_env,
    client,
    event_record_loss_mode=None,
    buffer_allocation_policy=None,
    snapshot=None,
):
    """
    Ensure that memory usage of channels will reduce in time and converge
    to the same amount, no matter the buffer preallocation policy.
    """
    max_age_us = 100000

    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("trace")
        ),
        snapshot=snapshot,
    )

    def get_memory_usage(channel):
        return get_channel_memory_usage_bytes(client, session.name, channel.name)

    channel_preallocate = session.add_channel(
        lttngtest.TracingDomain.User,
        event_record_loss_mode=event_record_loss_mode,
        buffer_allocation_policy=buffer_allocation_policy,
        buffer_preallocation_policy=lttngtest.BufferPreAllocationPolicy.PreAllocate,
        auto_reclaim_memory_older_than=max_age_us,
    )

    channel_on_demand = session.add_channel(
        lttngtest.TracingDomain.User,
        event_record_loss_mode=event_record_loss_mode,
        buffer_allocation_policy=buffer_allocation_policy,
        buffer_preallocation_policy=lttngtest.BufferPreAllocationPolicy.OnDemand,
        auto_reclaim_memory_older_than=max_age_us,
    )

    # Adding a non automatically reclaimed variants of the channels to accurately
    # measure their base memory usage before and after the grace period.
    # This is needed because memory may be reclaimed by the consumer
    # between the session's start and the first sampling of memory usage.
    non_reclaimed_channel_preallocate = session.add_channel(
        lttngtest.TracingDomain.User,
        event_record_loss_mode=event_record_loss_mode,
        buffer_allocation_policy=buffer_allocation_policy,
        buffer_preallocation_policy=lttngtest.BufferPreAllocationPolicy.PreAllocate,
    )

    non_reclaimed_channel_on_demand = session.add_channel(
        lttngtest.TracingDomain.User,
        event_record_loss_mode=event_record_loss_mode,
        buffer_allocation_policy=buffer_allocation_policy,
        buffer_preallocation_policy=lttngtest.BufferPreAllocationPolicy.OnDemand,
    )

    channel_on_demand.add_recording_rule(
        lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
    )
    channel_preallocate.add_recording_rule(
        lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
    )
    non_reclaimed_channel_on_demand.add_recording_rule(
        lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
    )
    non_reclaimed_channel_preallocate.add_recording_rule(
        lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
    )

    session.start()

    # Use the non-reclaimed channels to sample initial memory usage since
    # the auto-reclaimed ones may have already reclaimed memory.
    preallocate_initial = get_memory_usage(non_reclaimed_channel_preallocate)
    on_demand_initial = get_memory_usage(non_reclaimed_channel_on_demand)
    tap.diagnostic(
        "preallocate initial memory_usage={}, expected == 0".format(preallocate_initial)
    )
    assert preallocate_initial == 0
    tap.diagnostic(
        "on_demand initial memory_usage={}, expected == 0".format(on_demand_initial)
    )
    assert on_demand_initial == 0

    app = test_env.launch_wait_trace_test_application(10000)

    preallocate_after_allocation = get_memory_usage(non_reclaimed_channel_preallocate)
    on_demand_after_allocation = get_memory_usage(non_reclaimed_channel_on_demand)

    app.trace()
    app.wait_for_exit()

    # Sample memory usage resulting from the application using the buffers.
    preallocate_memory_usage_before_timer = get_memory_usage(non_reclaimed_channel_preallocate)
    on_demand_memory_usage_before_timer = get_memory_usage(non_reclaimed_channel_on_demand)

    # Wait enough time for the grace period to be exceeded.
    # We can't simply wait for the timer since the timer can fire "too close" to the
    # application's execution, causing no memory to be reclaimed.
    # This way, we ensure the subbuffers are old enough to be reclaimed at the time of the
    # timer execution we track with gdb.
    time.sleep(max_age_us / 1000000)

    if not snapshot:
        session.stop()

    while True:
        wait_for_memory_reclaim_timer(
            test_env, tap.diagnostic, [channel_preallocate.name, channel_on_demand.name]
        )

        preallocate_memory_usage_now = get_memory_usage(channel_preallocate)
        on_demand_memory_usage_now = get_memory_usage(channel_on_demand)

        # log the four values
        tap.diagnostic(
            "preallocate_memory_usage_now={}, expected == preallocate_after_allocation={}".format(
                preallocate_memory_usage_now, preallocate_after_allocation
            )
        )
        tap.diagnostic(
            "on_demand_initial_memory_usage_now={}, expected == on_demand_after_allocation={}".format(
                on_demand_memory_usage_now, on_demand_after_allocation
            )
        )

        if on_demand_memory_usage_now == on_demand_after_allocation:
            # Memory usage has converged.
            break

    preallocate_memory_usage_after_timer = get_memory_usage(channel_preallocate)
    on_demand_memory_usage_after_timer = get_memory_usage(channel_on_demand)

    tap.diagnostic(
        "preallocate_memory_usage_before_timer={}, expected > 0".format(
            preallocate_memory_usage_before_timer
        )
    )
    assert preallocate_memory_usage_before_timer > 0

    tap.diagnostic(
        "on_demand_memory_usage_before_timer={}, expected > 0".format(
            on_demand_memory_usage_before_timer
        )
    )
    assert on_demand_memory_usage_before_timer > 0

    tap.diagnostic(
        "preallocate_memory_usage_after_timer={}, expected < {}".format(
            preallocate_memory_usage_after_timer,
            preallocate_memory_usage_before_timer,
        )
    )
    assert (
        preallocate_memory_usage_after_timer
        < preallocate_memory_usage_before_timer
    )

    tap.diagnostic(
        "on_demand_memory_usage_after_timer={}, expected < {}".format(
            on_demand_memory_usage_after_timer,
            on_demand_memory_usage_before_timer,
        )
    )
    assert (
        on_demand_memory_usage_after_timer
        < on_demand_memory_usage_before_timer
    )

    tap.diagnostic(
        "on_demand_memory_usage_after_timer={}, expected == preallocate_memory_usage_after_timer={}".format(
            on_demand_memory_usage_after_timer,
            preallocate_memory_usage_after_timer,
        )
    )
    assert (
        on_demand_memory_usage_after_timer
        == preallocate_memory_usage_after_timer
    )


def test_memory_reclamation_convergence_consumed(
    tap,
    test_env,
    client,
    event_record_loss_mode=None,
    buffer_allocation_policy=None,
    snapshot=None,
):
    """
    Ensure that memory usage of channels will reduce in time and converge
    to the same amount, no matter the buffer preallocation policy.
    """

    # --auto-reclaim-consumed is invalid in snapshot mode.
    if snapshot:
        return

    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("trace")
        ),
        snapshot=snapshot,
    )

    def get_memory_usage(channel):
        return get_channel_memory_usage_bytes(client, session.name, channel.name)

    channel_preallocate = session.add_channel(
        lttngtest.TracingDomain.User,
        event_record_loss_mode=event_record_loss_mode,
        buffer_allocation_policy=buffer_allocation_policy,
        buffer_preallocation_policy=lttngtest.BufferPreAllocationPolicy.PreAllocate,
        auto_reclaim_memory_consumed=True,
    )

    channel_preallocate.add_recording_rule(
        lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
    )

    channel_on_demand = session.add_channel(
        lttngtest.TracingDomain.User,
        event_record_loss_mode=event_record_loss_mode,
        buffer_allocation_policy=buffer_allocation_policy,
        buffer_preallocation_policy=lttngtest.BufferPreAllocationPolicy.OnDemand,
        auto_reclaim_memory_consumed=True,
    )

    channel_on_demand.add_recording_rule(
        lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
    )

    session.start()

    preallocate_initial = get_memory_usage(channel_preallocate)
    on_demand_initial = get_memory_usage(channel_on_demand)
    tap.diagnostic(
        "preallocate initial memory_usage={}, expected == 0".format(preallocate_initial)
    )
    assert preallocate_initial == 0
    tap.diagnostic(
        "on_demand initial memory_usage={}, expected == 0".format(on_demand_initial)
    )
    assert on_demand_initial == 0

    app = test_env.launch_wait_trace_test_application(10000)
    app.trace()
    app.wait_for_exit()

    preallocate_memory_usage_before_rotation = get_memory_usage(channel_preallocate)
    on_demand_memory_usage_before_rotation = get_memory_usage(channel_on_demand)

    tap.diagnostic(
        "preallocate_memory_usage_before_rotation={}, expected > 0".format(
            preallocate_memory_usage_before_rotation
        )
    )
    assert preallocate_memory_usage_before_rotation > 0
    tap.diagnostic(
        "on_demand_memory_usage_before_rotation={}, expected > 0".format(
            on_demand_memory_usage_before_rotation
        )
    )
    assert on_demand_memory_usage_before_rotation > 0

    session.rotate()

    preallocate_memory_usage_after_rotation = get_memory_usage(channel_preallocate)
    on_demand_memory_usage_after_rotation = get_memory_usage(channel_on_demand)

    tap.diagnostic(
        "preallocate_memory_usage_after_rotation={}, expected < {}".format(
            preallocate_memory_usage_after_rotation,
            preallocate_memory_usage_before_rotation,
        )
    )
    assert (
        preallocate_memory_usage_after_rotation
        < preallocate_memory_usage_before_rotation
    )
    tap.diagnostic(
        "on_demand_memory_usage_after_rotation={}, expected < {}".format(
            on_demand_memory_usage_after_rotation,
            on_demand_memory_usage_before_rotation,
        )
    )
    assert (
        on_demand_memory_usage_after_rotation < on_demand_memory_usage_before_rotation
    )

    # Because only consumed memory is reclaimed, we can not make this check with
    # per-cpu buffer allocation.
    if buffer_allocation_policy == lttngtest.BufferAllocationPolicy.PerChannel:
        tap.diagnostic(
            "on_demand_memory_usage_after_rotation={}, expected == {}".format(
                on_demand_memory_usage_after_rotation,
                preallocate_memory_usage_after_rotation,
            )
        )
        assert (
            on_demand_memory_usage_after_rotation
            == preallocate_memory_usage_after_rotation
        )


def test_no_events_memory_reclaim(
    tap,
    test_env,
    client,
    event_record_loss_mode=None,
    buffer_allocation_policy=None,
    snapshot=None,
):
    """
    Ensure that a channel with the buffer preallocation policy `preallocate`,
    will reclaim its memory even if no events were emitted in it.
    """

    max_age_us = 100000

    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("trace")
        ),
        snapshot=snapshot,
    )

    auto_reclaimed_channel = session.add_channel(
        lttngtest.TracingDomain.User,
        event_record_loss_mode=event_record_loss_mode,
        buffer_allocation_policy=buffer_allocation_policy,
        buffer_preallocation_policy=lttngtest.BufferPreAllocationPolicy.PreAllocate,
        auto_reclaim_memory_older_than=max_age_us,
    )

    non_reclaimed_channel = session.add_channel(
        lttngtest.TracingDomain.User,
        event_record_loss_mode=event_record_loss_mode,
        buffer_allocation_policy=buffer_allocation_policy,
        buffer_preallocation_policy=lttngtest.BufferPreAllocationPolicy.PreAllocate,
    )

    session.start()

    # Emitting event, but no recording rules were added to the channel.
    app = test_env.launch_wait_trace_test_application(1000)
    app.trace()
    app.wait_for_exit()

    memory_usage_before_timer = get_channel_memory_usage_bytes(
        client, session.name, non_reclaimed_channel.name
    )

    # Wait enough time for the grace period to be exceeded.
    # We can't simply wait for the timer since the timer can fire "too close" to the
    # application's execution, causing no memory to be reclaimed.
    # This way, we ensure the subbuffers are old enough to be reclaimed at the time of the
    # timer execution we track with gdb.
    time.sleep((max_age_us * 2) / 1000000)

    # Wait for the memory reclaim timer to fire using GDB synchronization.
    wait_for_memory_reclaim_timer(
        test_env, tap.diagnostic, [auto_reclaimed_channel.name]
    )

    memory_usage_after_timer = get_channel_memory_usage_bytes(
        client, session.name, auto_reclaimed_channel.name
    )

    tap.diagnostic(
        "memory_usage_before_timer={}, expected > 0".format(
            memory_usage_before_timer
        )
    )
    assert memory_usage_before_timer > 0

    tap.diagnostic(
        "memory_usage_after_timer={}, expected < {}".format(
            memory_usage_after_timer, memory_usage_before_timer
        )
    )
    assert memory_usage_after_timer < memory_usage_before_timer


def test_temporal_backlog(
    tap,
    test_env,
    client,
    event_record_loss_mode=None,
    buffer_allocation_policy=None,
    snapshot=None,
):
    """
    Ensure that events that were too old and were reclaimed but not consumed,
    do not end up in the final trace.

    This is done by creating a snapshot session. A channel with the
    auto-reclaim-memory-older-than option is created using a grace period.

    The session is started and the memory usage of the channel is sampled. It
    should be 0.

    A first user application is spawned, emitting a single event, the memory
    usage is sampled again. It should be non-zero.

    Ten times the grace period is waited, giving enough time for the reclamation
    of the sub-buffer containing the event emitted by the first application.

    A second user application is spawned, emitting a single event. A snapshot
    record is made. Only a single event should be in the final trace.
    """
    max_age_us = 100000

    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("trace")
        ),
        snapshot=snapshot,
    )

    channel_on_demand = session.add_channel(
        lttngtest.TracingDomain.User,
        event_record_loss_mode=event_record_loss_mode,
        buffer_allocation_policy=buffer_allocation_policy,
        auto_reclaim_memory_older_than=max_age_us,
    )

    channel_on_demand.add_recording_rule(
        lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
    )

    session.start()

    def get_memory_usage():
        return get_channel_memory_usage_bytes(
            client, session.name, channel_on_demand.name
        )

    def run_user_app():
        app = test_env.launch_wait_trace_test_application(1)
        app.trace()
        app.wait_for_exit()

    memory_usage_before_app = get_memory_usage()
    run_user_app()
    memory_usage_after_first_app = get_memory_usage()

    time.sleep((max_age_us * 10) / 1000000)

    # Wait for the memory reclaim timer to fire using GDB synchronization.
    wait_for_memory_reclaim_timer(test_env, tap.diagnostic, [channel_on_demand.name])

    memory_usage_after_timer = get_memory_usage()
    run_user_app()

    trace_path = None
    expected_event_count = None
    if snapshot:
        session.record_snapshot()
        trace_path = session.output.path
        expected_event_count = 1
    else:
        session.rotate()
        trace_path = session.output.path / "archives"
        expected_event_count = 2

    tap.diagnostic(
        "memory_usage_before_app={}, expected == 0".format(memory_usage_before_app)
    )
    assert memory_usage_before_app == 0

    tap.diagnostic(
        "memory_usage_after_first_app={}, expected > 0".format(
            memory_usage_after_first_app
        )
    )
    assert memory_usage_after_first_app > 0

    tap.diagnostic(
        "memory_usage_after_timer={}, expected < {}".format(
            memory_usage_after_timer, memory_usage_after_first_app
        )
    )
    assert memory_usage_after_timer < memory_usage_after_first_app

    recorded_event_count, _ = lttngtest.count_events(trace_path)
    tap.diagnostic(
        "recorded_event_count={}, expected == {}".format(
            recorded_event_count, expected_event_count
        )
    )
    assert recorded_event_count == expected_event_count


def test_buffer_preallocation_policy(
    tap,
    test_env,
    client,
    event_record_loss_mode=None,
    buffer_allocation_policy=None,
    snapshot=None,
):
    """
    Ensure that channel with the buffer preallocation policy `on-demand` will
    use less memory than a channel with the buffer preallocation policy
    `preallocate`.

    The test works by making two channels with the two buffer preallocation
    policy. Then, a user application is run, emitting a single event.

    It is expected that the memory usage, in bytes, of the channel with the
    buffer preallocation policy `on-demand`, to be lower than the one from the
    channel with the buffer preallocation policy `preallocate`.
    """
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("trace")
        ),
        snapshot=snapshot,
    )

    channel_preallocate = session.add_channel(
        lttngtest.TracingDomain.User,
        event_record_loss_mode=event_record_loss_mode,
        buffer_allocation_policy=buffer_allocation_policy,
        buffer_preallocation_policy=lttngtest.BufferPreAllocationPolicy.PreAllocate,
    )

    channel_on_demand = session.add_channel(
        lttngtest.TracingDomain.User,
        event_record_loss_mode=event_record_loss_mode,
        buffer_allocation_policy=buffer_allocation_policy,
        buffer_preallocation_policy=lttngtest.BufferPreAllocationPolicy.OnDemand,
    )

    channel_preallocate.add_recording_rule(
        lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
    )
    channel_on_demand.add_recording_rule(
        lttngtest.lttngctl.UserTracepointEventRule("tp:tptest")
    )

    session.start()

    app = test_env.launch_wait_trace_test_application(1)
    app.trace()
    app.wait_for_exit()

    preallocate_memory_usage_bytes = get_channel_memory_usage_bytes(
        client, session.name, channel_preallocate.name
    )

    on_demand_memory_usage_bytes = get_channel_memory_usage_bytes(
        client, session.name, channel_on_demand.name
    )

    tap.diagnostic(
        "on_demand_memory_usage_bytes={}, expected < preallocate_memory_usage_bytes={}".format(
            on_demand_memory_usage_bytes, preallocate_memory_usage_bytes
        )
    )
    assert on_demand_memory_usage_bytes < preallocate_memory_usage_bytes


def test_load_save_preallocation_policy(
    tap,
    test_env,
    client,
    preallocation_policy,
    expected_mi_result,
    event_record_loss_mode=None,
    buffer_allocation_policy=None,
    snapshot=None,
):
    """
    Ensure that created channel with the
    `--buffer-preallocation=preallocation_policy' option will keep that policy
    upon a save/load cycle

    The test passes if the channel preallocation policy in the loaded session
    match `expected_mi_result`.

    Furthermore, the memory usage of the channel is verified according to the
    preallocation policy.
    """

    subbuf_count = 2
    subbuf_size = mmap.PAGESIZE

    original_session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("trace")
        ),
        snapshot=snapshot,
    )

    original_session_name = original_session.name

    channel = original_session.add_channel(
        lttngtest.TracingDomain.User,
        subbuf_size=mmap.PAGESIZE,
        subbuf_count=subbuf_count,
        event_record_loss_mode=event_record_loss_mode,
        buffer_allocation_policy=buffer_allocation_policy,
        buffer_preallocation_policy=preallocation_policy,
    )

    original_channel_name = channel.name

    client.save_sessions(session_name=original_session_name)

    original_session.destroy()

    client.load_sessions(session_name=original_session_name)

    saved_preallocation_policy = channel_preallocation_policy_from_session(
        client, original_channel_name, original_session_name
    )

    tap.diagnostic(
        "saved_preallocation_policy={}, expected == {}".format(
            saved_preallocation_policy, expected_mi_result
        )
    )
    assert saved_preallocation_policy == expected_mi_result

    client.start_session_by_name(original_session_name)

    test_env.launch_wait_trace_test_application(0)

    mem = get_channel_memory_usage_bytes(
        client, original_session_name, original_channel_name
    )

    # Header and footer pages allocated by LTTng-UST for internal data
    # structures. These are always allocated.
    control_pages_size = 2 * mmap.PAGESIZE

    # The ring-buffer is using N sub-buffer plus a single sub-buffer for
    # swapping during reclamation. These are lazily allocated.
    data_pages_size = (subbuf_count + 1) * subbuf_size

    stream_count = get_channel_data_streams_count(
        client, original_session_name, original_channel_name
    )

    if (
        preallocation_policy is None
        or preallocation_policy == lttngtest.BufferPreAllocationPolicy.PreAllocate
    ):
        expected_mem = stream_count * (control_pages_size + data_pages_size)
        tap.diagnostic("mem={}, expected == {}".format(mem, expected_mem))
        assert mem == expected_mem
    else:
        expected_mem = stream_count * control_pages_size
        tap.diagnostic("mem={}, expected == {}".format(mem, expected_mem))
        assert mem == expected_mem


def test_load_save_preallocation_default(tap, test_env, client, **kwargs):
    "Ensure that load/save of default session works like preallocate."
    test_load_save_preallocation_policy(
        tap, test_env, client, None, "PREALLOCATE", **kwargs
    )


def test_load_save_preallocation_preallocate(tap, test_env, client, **kwargs):
    """Ensure that load/save of session with preallocate policy preserves the policy."""
    test_load_save_preallocation_policy(
        tap,
        test_env,
        client,
        lttngtest.BufferPreAllocationPolicy.PreAllocate,
        "PREALLOCATE",
        **kwargs,
    )


def test_load_save_preallocation_on_demand(tap, test_env, client, **kwargs):
    """Ensure that load/save of session with on-demand policy preserves the policy."""
    test_load_save_preallocation_policy(
        tap,
        test_env,
        client,
        lttngtest.BufferPreAllocationPolicy.OnDemand,
        "ON_DEMAND",
        **kwargs,
    )


def test_reclaim_memory_command_all(
    tap,
    test_env,
    client,
    event_record_loss_mode=None,
    buffer_allocation_policy=None,
    snapshot=None,
):
    """
    Ensure that all channels have their memory reclaim with the `--all`
    option when using the `lttng-reclaim-memory(1)` command.
    """
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("trace")
        ),
        snapshot=snapshot,
    )

    channels = [
        session.add_channel(
            lttngtest.TracingDomain.User,
            event_record_loss_mode=event_record_loss_mode,
            buffer_allocation_policy=buffer_allocation_policy,
        )
        for x in range(2)
    ]

    # Trigger allocation of sub-buffer pages.
    session.start()
    test_env.launch_wait_trace_test_application(0)

    memory_usages_then = [
        get_channel_memory_usage_bytes(client, session.name, channel.name)
        for channel in channels
    ]

    session.reclaim_memory(all_channels=True)

    memory_usages_now = [
        get_channel_memory_usage_bytes(client, session.name, channel.name)
        for channel in channels
    ]

    for i, (then, now) in enumerate(zip(memory_usages_then, memory_usages_now)):
        tap.diagnostic(
            "channel[{}]: memory_usage then={}, now={}, expected then > now".format(
                i, then, now
            )
        )
        assert then > now


def test_reclaim_memory_command_specific_channels(
    tap,
    test_env,
    client,
    event_record_loss_mode=None,
    buffer_allocation_policy=None,
    snapshot=None,
):
    """
    Ensure that only select channels passed to the `lttng-reclaim-memory(1)`
    command have their memory reclaimed.
    """
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("trace")
        ),
        snapshot=snapshot,
    )

    channels = [
        session.add_channel(
            lttngtest.TracingDomain.User,
            event_record_loss_mode=event_record_loss_mode,
            buffer_allocation_policy=buffer_allocation_policy,
        )
        for x in range(4)
    ]

    no_reclaim_targets = channels[0:2]
    reclaim_targets = channels[2:]

    # Trigger allocation of sub-buffer pages.
    session.start()
    test_env.launch_wait_trace_test_application(0)

    memory_usages_no_reclaim_targets_then = [
        get_channel_memory_usage_bytes(client, session.name, channel.name)
        for channel in no_reclaim_targets
    ]

    memory_usages_reclaim_targets_then = [
        get_channel_memory_usage_bytes(client, session.name, channel.name)
        for channel in reclaim_targets
    ]

    session.reclaim_memory(channels=[channel.name for channel in reclaim_targets])

    memory_usages_no_reclaim_targets_now = [
        get_channel_memory_usage_bytes(client, session.name, channel.name)
        for channel in no_reclaim_targets
    ]

    memory_usages_reclaim_targets_now = [
        get_channel_memory_usage_bytes(client, session.name, channel.name)
        for channel in reclaim_targets
    ]

    for i, (then, now) in enumerate(
        zip(memory_usages_no_reclaim_targets_then, memory_usages_no_reclaim_targets_now)
    ):
        tap.diagnostic(
            "no_reclaim_target[{}]: memory_usage then={}, now={}, expected then == now".format(
                i, then, now
            )
        )
        assert then == now

    for i, (then, now) in enumerate(
        zip(memory_usages_reclaim_targets_then, memory_usages_reclaim_targets_now)
    ):
        tap.diagnostic(
            "reclaim_target[{}]: memory_usage then={}, now={}, expected then > now".format(
                i, then, now
            )
        )
        assert then > now


def test_reclaim_memory_older_than(
    tap,
    test_env,
    client,
    event_record_loss_mode=None,
    buffer_allocation_policy=None,
    snapshot=None,
):
    """
    Ensure that the `--older-than` option of the `lttng-reclaim-memory(1)`
    command works as intended.

    This is done by sampling the memory usage of a channel first. Then, a
    memory reclamation is asked for sub-buffer older than 1000 seconds. We
    expect that the memory usage has not changed if the system is not that slow.

    Finally, another memory reclamation is done, this time with sub-buffer older
    than 0.1 second. A sleep of 0.5 second is done prior that to ensure that
    the reclamation will effectively happen.

    The test pass if the final memory usage of the channel is lower than the
    initial one.
    """
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("trace")
        ),
        snapshot=snapshot,
    )

    channel = session.add_channel(
        lttngtest.TracingDomain.User,
        event_record_loss_mode=event_record_loss_mode,
        buffer_allocation_policy=buffer_allocation_policy,
    )

    # Trigger allocation of sub-buffer pages.
    session.start()
    test_env.launch_wait_trace_test_application(0)

    memory_usages_then = get_channel_memory_usage_bytes(
        client, session.name, channel.name
    )

    # 1000 seconds.
    session.reclaim_memory(older_than_us=1000000000, all_channels=True)

    memory_usages_now = get_channel_memory_usage_bytes(
        client, session.name, channel.name
    )

    tap.diagnostic(
        "after older_than=1000s: memory_usages_then={}, memory_usages_now={}, expected == (no change)".format(
            memory_usages_then, memory_usages_now
        )
    )
    assert memory_usages_then == memory_usages_now

    time.sleep(2)

    # 0.1 second
    session.reclaim_memory(older_than_us=100000, all_channels=True)

    memory_usages_now = get_channel_memory_usage_bytes(
        client, session.name, channel.name
    )

    tap.diagnostic(
        "after older_than=0.1s: memory_usages_then={}, memory_usages_now={}, expected then > now".format(
            memory_usages_then, memory_usages_now
        )
    )
    assert memory_usages_then > memory_usages_now


def test_reclaim_memory_no_wait(
    tap,
    test_env,
    client,
):
    """
    Ensure that the `--no-wait` option of the `lttng-reclaim-memory(1)`
    command works as intended.

    This is done be polling the memory usage of a channel before asking for memory
    reclamation.

    Then, a poll loop samples the channel memory usage at a frequency of 1
    Hz, one hundred time

    The test passes if the memory usage has reduced from the original polling
    before the loop is done.
    """
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("trace")
        ),
    )

    channel = session.add_channel(
        lttngtest.TracingDomain.User,
    )

    # Trigger allocation of sub-buffer pages.
    session.start()
    test_env.launch_wait_trace_test_application(0)

    memory_usages_then = get_channel_memory_usage_bytes(
        client, session.name, channel.name
    )

    session.reclaim_memory(wait=False, all_channels=True)

    tap.diagnostic("Polling memory reclamation ...")
    memory_usages_now = memory_usages_then
    for x in range(1, 100):
        time.sleep(1)
        memory_usages_now = get_channel_memory_usage_bytes(
            client, session.name, channel.name
        )
        tap.diagnostic("Sample {} = {}".format(x, memory_usages_now))
        if memory_usages_now < memory_usages_then:
            tap.diagnostic(
                "memory_usages_now={} < memory_usages_then={}, reclamation succeeded".format(
                    memory_usages_now, memory_usages_then
                )
            )
            return

    tap.diagnostic(
        "memory_usages_then={}, memory_usages_now={}, expected now < then after polling".format(
            memory_usages_then, memory_usages_now
        )
    )
    assert memory_usages_now < memory_usages_then


def test_reclaim_memory_command_unknown_channel(tap, test_env, client):
    """
    Ensure that reclaiming memory of a channel that does not exist yield an
    error.
    """
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("trace")
        ),
    )

    try:
        session.reclaim_memory(channels=["not-a-channel"])
        tap.diagnostic("Expected LTTngClientError but command succeeded")
        assert not "lttng-reclaim-memory(1) succeeds on non-existing channel"
    except lttngtest.LTTngClientError as ex:
        expected_error = "Error: Channel `not-a-channel` does not exist"
        tap.diagnostic(
            "error_output contains '{}': {}".format(
                expected_error, expected_error in ex._error_output
            )
        )
        assert expected_error in ex._error_output


def test_auto_reclaim_memory_consumed_snapshot_mode(tap, test_env, client):
    """
    Ensure that the `--auto-reclaim-consumed` option of the `enable-channel`
    command is invalid for session in snapshot mode.
    """
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("trace")
        ),
        snapshot=True,
    )

    session_name = session.name
    channel_name = "channel_123"
    try:
        session.add_channel(
            lttngtest.TracingDomain.User,
            channel_name,
            auto_reclaim_memory_consumed=True,
        )
        tap.diagnostic("Expected LTTngClientError but command succeeded")
        assert (
            not "lttng enable-channel --auto-reclaim-consumed succeed on session with snapshot mode"
        )
    except lttngtest.LTTngClientError as ex:
        expected_error = "Error: Failed to enable channel `{}` under session `{}`: Invalid reclamation policy for this channel".format(
            channel_name, session_name
        )
        tap.diagnostic(
            "error_output contains expected error: {}".format(
                expected_error in ex._error_output
            )
        )
        assert expected_error in ex._error_output


def test_auto_reclaim_memory_consumed_no_output(tap, test_env, client):
    """
    Ensure that the `--auto-reclaim-consumed` option of the `enable-channel`
    command is invalid for session without output.
    """
    session = client.create_session()

    session_name = session.name
    channel_name = "channel_123"
    try:
        session.add_channel(
            lttngtest.TracingDomain.User,
            channel_name,
            auto_reclaim_memory_consumed=True,
        )
        tap.diagnostic("Expected LTTngClientError but command succeeded")
        assert (
            not "lttng enable-channel --auto-reclaim-consumed succeed on session without output"
        )
    except lttngtest.LTTngClientError as ex:
        expected_error = "Error: Failed to enable channel `{}` under session `{}`: Invalid reclamation policy for this channel".format(
            channel_name, session_name
        )
        tap.diagnostic(
            "error_output contains expected error: {}".format(
                expected_error in ex._error_output
            )
        )
        assert expected_error in ex._error_output


def test_load_save_reclaim_policy(
    tap,
    test_env,
    client,
    expected_mi_result,
    auto_reclaim_memory_older_than=None,
    auto_reclaim_memory_consumed=False,
):
    """
    Ensure that `reclaim_policy` channel attribute is kept upon a save/load
    cycle

    The test passes if the channel memory reclamation policy in the loaded
    session match `expected_mi_result`.
    """

    original_session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("trace")
        ),
    )

    original_session_name = original_session.name

    channel_preallocate = original_session.add_channel(
        lttngtest.TracingDomain.User,
        auto_reclaim_memory_older_than=auto_reclaim_memory_older_than,
        auto_reclaim_memory_consumed=auto_reclaim_memory_consumed,
    )

    original_channel_name = channel_preallocate.name

    client.save_sessions(session_name=original_session_name)
    original_session.destroy()

    client.load_sessions(session_name=original_session_name)

    saved_reclaim_policy = channel_reclaim_policy_from_session(
        client, original_channel_name, original_session_name
    )

    tap.diagnostic(
        "Saved reclaim policy = {}, expected = {}".format(
            saved_reclaim_policy, expected_mi_result
        )
    )
    assert saved_reclaim_policy == expected_mi_result


def test_load_save_reclaim_policy_default(tap, test_env, client):
    test_load_save_reclaim_policy(tap, test_env, client, None)


def test_load_save_reclaim_policy_periodic(tap, test_env, client):
    test_load_save_reclaim_policy(
        tap,
        test_env,
        client,
        3141592653589793,
        auto_reclaim_memory_older_than=3141592653589793,
    )


def test_load_save_reclaim_policy_consumed(tap, test_env, client):
    test_load_save_reclaim_policy(
        tap, test_env, client, 0, auto_reclaim_memory_consumed=True
    )


def run_test(test, variant):
    try:
        test_name = "{}({})".format(
            test.__name__,
            ", ".join(["{}={}".format(key, value) for key, value in variant.items()]),
        )
        with lttngtest.test_environment(
            with_sessiond=True, log=tap.diagnostic
        ) as test_env:
            client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
            test(tap, test_env, client, **variant)
            tap.ok(test_name)
    except AssertionError:
        _, _, bt = sys.exc_info()
        traceback.print_tb(bt)
        top_frame = traceback.extract_tb(bt)[-1]
        filename, line, _, _ = top_frame
        tap.fail("{} - Failed assertion at: {}:{}".format(test_name, filename, line))
    except Exception as exn:
        tap.fail("{} - Uncaught exception".format(test_name))
        tap.diagnostic("".join(traceback.format_exception(exn)))


if __name__ == "__main__":

    tests = (
        test_memory_reclamation_convergence,
        test_memory_reclamation_convergence_consumed,
        test_no_events_memory_reclaim,
        test_temporal_backlog,
        test_buffer_preallocation_policy,
        test_load_save_preallocation_default,
        test_load_save_preallocation_preallocate,
        test_load_save_preallocation_on_demand,
        test_reclaim_memory_command_all,
        test_reclaim_memory_command_specific_channels,
        test_reclaim_memory_older_than,
    )

    tests_no_variants = (
        test_reclaim_memory_command_unknown_channel,
        test_auto_reclaim_memory_consumed_snapshot_mode,
        test_auto_reclaim_memory_consumed_no_output,
        test_load_save_reclaim_policy_default,
        test_load_save_reclaim_policy_periodic,
        test_load_save_reclaim_policy_consumed,
        test_reclaim_memory_no_wait,
    )

    def list_variants():

        options = {
            "event_record_loss_mode": [
                lttngtest.EventRecordLossMode.Discard,
                lttngtest.EventRecordLossMode.Overwrite
            ],
            "buffer_allocation_policy": [
                lttngtest.BufferAllocationPolicy.PerCPU,
                lttngtest.BufferAllocationPolicy.PerChannel
            ],
            "snapshot": [
                True,
                False
            ],
        }

        keys = options.keys()

        return [
            dict(zip(keys, items)) for items in itertools.product(*options.values())
        ]

    variants = list_variants()

    tap = lttngtest.TapGenerator(len(variants) * len(tests) + len(tests_no_variants))

    if not gdb_exists():
        tap.missing_platform_requirement("GDB not available")

    for variant in variants:
        for test in tests:
            run_test(test, variant)

    for test in tests_no_variants:
        run_test(test, {})

    sys.exit(0 if tap.is_successful else 1)
