#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Olivier Dion <odion@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only

import concurrent.futures
import itertools
import logging
import mmap
import os
import pathlib
import signal
import subprocess
import sys
import time
import traceback

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest

gdb_helper_script_path = test_utils_import_path / "gdb_helper.py"
_MEMORY_RECLAIM_TASK_TESTPOINT_PREFIX = "lttng_tools_testpoint_memory_reclaim_timer"
_MEMORY_RECLAIM_DEFERRED_TESTPOINT_PREFIX = (
    "lttng_tools_testpoint_memory_reclaim_request_deferred"
)
_MEMORY_RECLAIM_CHANNEL_SUSPENDED_TESTPOINT_PREFIX = (
    "lttng_tools_testpoint_memory_reclaim_channel_suspended"
)
_MEMORY_RECLAIM_STREAM_DEFERRED_TESTPOINT_PREFIX = (
    "lttng_tools_testpoint_memory_reclaim_stream_deferred"
)

"""
This test suite validates some properties of sparse buffers.

See individual tests docstring.
"""


def extra_tap_points(count):
    """
    Declare the number of tap test points a test publishes itself, on top of
    the completion point published by run_test(). The declared count is
    included in the test plan; run_test() publishes the points a test did not
    reach (failure or skip) as skipped.
    """

    def annotate(test):
        test.extra_tap_points = count
        return test

    return annotate


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
        if len(output) > 1:
            print(
                "# Warning: multiple consumerds found, using the first (pid: {})".format(
                    output[0]
                ),
                file=sys.stderr,
            )

        return int(output[0])
    except Exception:
        pass
    return None


def _interrupt_and_wait_gdb(process):
    """
    Interrupt a GDB blocked in `continue` and reap it.

    Only SIGINT/SIGTERM are used so GDB detaches and restores the breakpointed
    instructions; SIGKILL would leave the breakpoints in place and crash the
    daemon with SIGTRAP.
    """
    process.send_signal(signal.SIGINT)
    while process.poll() is None:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.send_signal(signal.SIGTERM)


def make_memory_reclaim_timer_gdb_commands(
    consumerd_pid, channel_names, gdb_debug_directory
):
    """
    Build a GDB command list that waits, in order, for the memory reclaim timer
    of every channel in `channel_names` to fire and complete a reclaim pass.

    The timer task is observed through a TESTPOINT(). For each channel, a
    breakpoint conditional on the channel name is armed on that label;
    `continue` then blocks until the timer fires and `finish` lets the reclaim
    pass complete before moving on to the next channel. GDB exits once every
    channel's timer has fired, so a caller only has to wait for its termination.
    """
    commands = [
        "source {}".format(gdb_helper_script_path),
    ]

    if gdb_debug_directory:
        commands.append("set debug-file-directory {}".format(gdb_debug_directory))

    commands.append("attach {}".format(consumerd_pid))

    for channel_name in channel_names:
        commands.extend(
            [
                "python",
                "bps = break_testpoint({!r})".format(
                    _MEMORY_RECLAIM_TASK_TESTPOINT_PREFIX
                ),
                "if not bps:",
                "    raise gdb.GdbError('No memory reclaim timer testpoint found')",
                "for bp in bps:",
                "    bp.condition = '$_streq(this->_channel.name, \"{}\")'".format(
                    channel_name
                ),
                "end",
                "continue",
                "finish",
                "delete",
            ]
        )

    commands.extend(["detach", "quit"])

    return commands


def make_memory_reclaim_request_deferred_gdb_commands(
    consumerd_pid, ready_fifo, gdb_debug_directory, count_setup=False
):
    """
    Build a GDB command list that blocks until an explicit reclaim request has
    deferred its sub-buffers in the consumer daemon.

    The point at which a request's deferral is fully in place is observed through
    a TESTPOINT(). A breakpoint is armed on that label, the `ready_fifo` is
    signalled so the caller knows the breakpoint is in place before it issues the
    request, and `continue` then blocks until the testpoint fires. GDB detaches
    and exits once it does, so a caller only has to wait for its termination.

    With `count_setup`, two additional non-stopping breakpoints count how many
    channel timer suspensions and stream deferrals the request performed before
    reaching that point. The counts are printed on GDB's output as
    `RECLAIM_SETUP_SUSPENDED_CHANNELS:` and `RECLAIM_SETUP_DEFERRED_STREAMS:`
    lines for the caller to parse, letting it assert that the request actually
    took the asynchronous (deferral) path over every expected channel.
    """
    commands = [
        "source {}".format(gdb_helper_script_path),
    ]

    if gdb_debug_directory:
        commands.append("set debug-file-directory {}".format(gdb_debug_directory))

    commands.append("attach {}".format(consumerd_pid))

    if count_setup:
        commands.extend(
            [
                "python",
                "setup_counters = {'suspended': 0, 'deferred': 0}",
                "def count_suspended(breakpoint):",
                "    setup_counters['suspended'] += 1",
                "    return False",
                "def count_deferred(breakpoint):",
                "    setup_counters['deferred'] += 1",
                "    return False",
                "if not break_testpoint_callback({!r}, count_suspended):".format(
                    _MEMORY_RECLAIM_CHANNEL_SUSPENDED_TESTPOINT_PREFIX
                ),
                "    raise gdb.GdbError('No memory reclaim channel suspended testpoint found')",
                "if not break_testpoint_callback({!r}, count_deferred):".format(
                    _MEMORY_RECLAIM_STREAM_DEFERRED_TESTPOINT_PREFIX
                ),
                "    raise gdb.GdbError('No memory reclaim stream deferred testpoint found')",
                "end",
            ]
        )

    commands.extend(
        [
            "python",
            "bps = break_testpoint({!r})".format(
                _MEMORY_RECLAIM_DEFERRED_TESTPOINT_PREFIX
            ),
            "if not bps:",
            "    raise gdb.GdbError('No memory reclaim request deferred testpoint found')",
            "end",
            # Notify that the breakpoint is in place; the request can now be
            # fired. Backgrounded so GDB does not block on opening the FIFO (the
            # breakpoint is already armed above, so the ordering holds either
            # way).
            "shell echo . > {} &".format(ready_fifo),
            # Block until the request's deferral is in place.
            "continue",
        ]
    )

    if count_setup:
        commands.extend(
            [
                "python",
                "print('RECLAIM_SETUP_SUSPENDED_CHANNELS: {}'.format(setup_counters['suspended']))",
                "print('RECLAIM_SETUP_DEFERRED_STREAMS: {}'.format(setup_counters['deferred']))",
                "end",
            ]
        )

    commands.extend(
        [
            "detach",
            "quit",
        ]
    )

    return commands


def _run_memory_reclaim_timer_gdb(test_env, log, channel_names, timeout_s=None):
    """
    Attach GDB to the consumer daemon and wait for the memory reclaim timer to
    fire for every channel in `channel_names`.

    GDB runs a batch script that exits once every channel's timer has fired
    (see make_memory_reclaim_timer_gdb_commands()), so waiting for the timers
    amounts to waiting for GDB to terminate. Returns True on success, or False
    if `timeout_s` is set and expires first; any other GDB failure raises.
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
    log(
        "Running GDB to wait for memory reclaim timer on channels: {}".format(
            ", ".join(channel_names)
        )
    )

    process, gdb_script_file = lttngtest.utils.gdb_script(
        make_memory_reclaim_timer_gdb_commands(
            consumerd_pid, channel_names, os.getenv("GDB_DEBUG_FILE_DIRECTORY")
        ),
        {"stdout": subprocess.PIPE, "stderr": subprocess.STDOUT},
    )

    timed_out = False
    try:
        output, _ = process.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        _interrupt_and_wait_gdb(process)
        output, _ = process.communicate()

    for line in output.decode("utf-8", errors="ignore").splitlines():
        log("GDB: {}".format(line))

    if timed_out:
        log(
            "Timed out waiting for the memory reclaim timer to fire on channels: {}".format(
                ", ".join(channel_names)
            )
        )
        return False

    if process.returncode != 0:
        raise RuntimeError(
            "GDB exited with non-zero return code: {}".format(process.returncode)
        )

    log("Memory reclaim timer has fired for all channels")
    return True


def wait_for_memory_reclaim_timer(test_env, log, channel_names):
    """
    Wait for the memory reclaim timer to fire for the specified channels.

    Blocks until the timer has fired and completed a reclaim pass for every
    channel.
    """
    _run_memory_reclaim_timer_gdb(test_env, log, channel_names)


def memory_reclaim_timer_fires(test_env, log, channel_names, timeout_s):
    """
    Return True if the memory reclaim timer fires for every channel in
    `channel_names` within `timeout_s` seconds, False otherwise.

    A timer which never fires (for instance, a periodic reclaim task that was
    permanently cancelled) shows up as GDB never exiting; the timeout turns that
    into a negative result.
    """
    return _run_memory_reclaim_timer_gdb(test_env, log, channel_names, timeout_s)


def start_wait_for_reclaim_request_deferred(test_env, log, count_setup=False):
    """
    Attach GDB to the consumer daemon and arm a breakpoint on the point where an
    explicit reclaim request has finished deferring its sub-buffers.

    Returns the (GDB subprocess, GDB script tempfile) pair since the script must
    remain in place on the FS until GDB completes. The breakpoint is armed
    before this function returns: GDB writes to an internal FIFO once it is in
    place and this function blocks on that FIFO. The caller then issues the
    reclaim request and waits for the returned subprocess to terminate, which
    happens once the deferral is in place.

    With `count_setup`, the request's channel timer suspensions and stream
    deferrals are counted and reported on GDB's output (see
    make_memory_reclaim_request_deferred_gdb_commands()).
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

    fifo_directory = test_env.create_temporary_directory("reclaim_deferred_fifo")
    ready_fifo = os.path.join(str(fifo_directory), "ready")
    os.mkfifo(ready_fifo)

    process, gdb_script_file = lttngtest.utils.gdb_script(
        make_memory_reclaim_request_deferred_gdb_commands(
            consumerd_pid,
            ready_fifo,
            os.getenv("GDB_DEBUG_FILE_DIRECTORY"),
            count_setup,
        ),
        {"stdout": subprocess.PIPE, "stderr": subprocess.STDOUT},
    )

    # Block until GDB has armed the breakpoint so the request issued next can not
    # be serviced before it is in place.
    with open(ready_fifo, "r") as fifo:
        fifo.read(1)

    log("Breakpoint on the reclaim request deferred testpoint is armed")

    return process, gdb_script_file


def make_memory_reclaim_timer_keys_gdb_commands(
    consumerd_pid, channel_name, expected_key_count, gdb_debug_directory
):
    """
    Build a GDB command list that observes the distinct consumer channel keys
    whose memory reclaim timer fires for the channel named `channel_name`.

    The timer task is observed through a TESTPOINT() (like the other timer
    helpers). A callback breakpoint records the firing channel's key, printing
    each new key as a `RECLAIM_TIMER_KEY:` line on GDB's output, and stops GDB
    once `expected_key_count` distinct keys have been seen. GDB then detaches
    and exits, so a caller only has to wait for its termination and parse the
    keys from its output. The channel name is filtered in the callback itself:
    GDB documents that a stop() method must not be combined with a breakpoint
    condition.
    """
    commands = [
        "source {}".format(gdb_helper_script_path),
    ]

    if gdb_debug_directory:
        commands.append("set debug-file-directory {}".format(gdb_debug_directory))

    commands.extend(
        [
            "attach {}".format(consumerd_pid),
            "python",
            "seen_keys = set()",
            "def on_reclaim_timer_fire(breakpoint):",
            "    if gdb.parse_and_eval('this->_channel.name').string() != {!r}:".format(
                channel_name
            ),
            "        return False",
            "    key = int(gdb.parse_and_eval('this->_channel.key'))",
            "    if key not in seen_keys:",
            "        seen_keys.add(key)",
            "        print('RECLAIM_TIMER_KEY: {}'.format(key))",
            "    return len(seen_keys) >= {}".format(expected_key_count),
            "if not break_testpoint_callback({!r}, on_reclaim_timer_fire):".format(
                _MEMORY_RECLAIM_TASK_TESTPOINT_PREFIX
            ),
            "    raise gdb.GdbError('No memory reclaim timer testpoint found')",
            "end",
            # Block until `expected_key_count` distinct keys have fired.
            "continue",
            "detach",
            "quit",
        ]
    )

    return commands


def memory_reclaim_timer_distinct_channel_keys(
    test_env, log, channel_name, expected_key_count, timeout_s
):
    """
    Return the set of distinct consumer channel keys whose memory reclaim timer
    fires for the channel named `channel_name`.

    A single session daemon channel using per-process buffer ownership maps to
    one consumer channel (with its own reclaim timer task) per traced process.
    These consumer channels share the same name but have distinct keys.

    GDB exits on its own once `expected_key_count` distinct keys have fired
    (see make_memory_reclaim_timer_keys_gdb_commands()), so waiting for the
    timers amounts to waiting for GDB to terminate. If `timeout_s` elapses
    first (for instance, a timer that never resumes), GDB is interrupted
    cleanly (SIGINT, so it detaches and restores the breakpointed
    instructions) and the keys seen so far are returned, letting the caller
    fail on the count instead of blocking forever.
    """
    consumerd_pid = get_consumerd_pid(test_env._sessiond.pid)
    if consumerd_pid is None:
        raise RuntimeError(
            "Could not find consumer daemon (child of sessiond pid {})".format(
                test_env._sessiond.pid
            )
        )

    log(
        "Observing distinct memory reclaim timer keys (until {} keys or {}s) for channel: {}".format(
            expected_key_count, timeout_s, channel_name
        )
    )
    process, gdb_script_file = lttngtest.utils.gdb_script(
        make_memory_reclaim_timer_keys_gdb_commands(
            consumerd_pid,
            channel_name,
            expected_key_count,
            os.getenv("GDB_DEBUG_FILE_DIRECTORY"),
        ),
        {"stdout": subprocess.PIPE, "stderr": subprocess.STDOUT},
    )

    try:
        output, _ = process.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _interrupt_and_wait_gdb(process)
        output, _ = process.communicate()

    keys = set()
    for line in output.decode("utf-8", errors="ignore").splitlines():
        log("GDB: {}".format(line))
        if line.startswith("RECLAIM_TIMER_KEY:"):
            keys.add(int(line.split(":", 1)[1]))

    log("Distinct memory reclaim timer keys observed: {}".format(sorted(keys)))
    return keys


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
    preallocate_memory_usage_before_timer = get_memory_usage(
        non_reclaimed_channel_preallocate
    )
    on_demand_memory_usage_before_timer = get_memory_usage(
        non_reclaimed_channel_on_demand
    )

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
    assert preallocate_memory_usage_after_timer < preallocate_memory_usage_before_timer

    tap.diagnostic(
        "on_demand_memory_usage_after_timer={}, expected < {}".format(
            on_demand_memory_usage_after_timer,
            on_demand_memory_usage_before_timer,
        )
    )
    assert on_demand_memory_usage_after_timer < on_demand_memory_usage_before_timer

    tap.diagnostic(
        "on_demand_memory_usage_after_timer={}, expected == preallocate_memory_usage_after_timer={}".format(
            on_demand_memory_usage_after_timer,
            preallocate_memory_usage_after_timer,
        )
    )
    assert on_demand_memory_usage_after_timer == preallocate_memory_usage_after_timer


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

    # --auto-reclaim-memory=consumed is invalid in snapshot mode.
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
        "memory_usage_before_timer={}, expected > 0".format(memory_usage_before_timer)
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
    --auto-reclaim-memory=older-than: option is created using a grace period.

    The session is started and the memory usage of the channel is sampled. It
    should be 0.

    A first user application is spawned, emitting a single event, the memory
    usage is sampled again. It should be non-zero.

    Ten times the grace period is waited, giving enough time for the reclamation
    of the sub-buffer containing the event emitted by the first application.

    A second user application is spawned, emitting a single event. A snapshot
    record is made. Only a single event should be in the final trace.
    """
    max_age_us = 5000000

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

    # Add some slack to ensure the sub-buffer is old enough to be reclaimed.
    # This is needed to account for the time imprecision on 32-bit platforms
    # (~260ms).
    time.sleep(((max_age_us) / 1000000) + 0.3)

    # Wait for the memory reclaim timer to fire using GDB synchronization.
    wait_for_memory_reclaim_timer(test_env, tap.diagnostic, [channel_on_demand.name])

    memory_usage_after_timer = get_memory_usage()

    # There is a race here: the timer may fire again before we take the
    # snapshot/rotate. To reduce the likelihood of that happening,
    # we increase the max age to account for slow platforms. Still, this
    # is not foolproof. We measure the time between the completion of the second
    # application and the snapshot/rotate. If more than max_age_us passed,
    # the test should be skipped.
    time_before_second_app = time.monotonic()
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

    time_after_snapshot_rotate = time.monotonic()
    elapsed_us = (time_after_snapshot_rotate - time_before_second_app) * 1000000
    if elapsed_us > max_age_us:
        raise lttngtest.TestSkipped(
            "Elapsed time ({:.0f} us) exceeded max_age_us ({} us); the test is unreliable".format(
                elapsed_us, max_age_us
            )
        )

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


def test_auto_reclaim_resumes_after_explicit_reclaim(tap, test_env, client):
    """
    Ensure that a channel's automatic (periodic) memory reclaim timer keeps
    firing after an explicit `lttng reclaim-memory` request.

    An explicit memory reclaim request suspends the channel's periodic reclaim
    timer task while the request is serviced, and is supposed to resume it once
    the request completes. This test configures a channel with a periodic
    reclaim policy, confirms that its timer is firing, issues an explicit
    reclaim request, then verifies that the periodic timer fires again.

    The timer is observed directly through a GDB breakpoint on the reclaim timer
    task's TESTPOINT() label, so the result does not depend on the amount of
    reclaimable memory.
    """
    max_age_us = 100000

    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("trace")
        ),
    )

    channel = session.add_channel(
        lttngtest.TracingDomain.User,
        buffer_preallocation_policy=lttngtest.BufferPreAllocationPolicy.PreAllocate,
        auto_reclaim_memory_older_than=max_age_us,
    )

    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))

    session.start()

    app = test_env.launch_wait_trace_test_application(10000)
    app.trace()
    app.wait_for_exit()

    # The periodic timer fires on its own period (a few hundred milliseconds),
    # so this timeout only needs to cover GDB's attach time plus a handful of
    # periods.
    timer_timeout_s = 60

    # The periodic reclaim timer must be running before any explicit request is
    # issued, otherwise the check below would be meaningless.
    fired_before = memory_reclaim_timer_fires(
        test_env, tap.diagnostic, [channel.name], timer_timeout_s
    )
    tap.diagnostic(
        "periodic reclaim timer fired before explicit request={}, expected True".format(
            fired_before
        )
    )
    assert fired_before

    # Issue an explicit reclaim request. It suspends the periodic timer task and
    # is meant to resume it on completion.
    session.reclaim_memory(wait=True, channels=[channel.name])

    # The periodic timer must resume and fire again after the request completed.
    fired_after = memory_reclaim_timer_fires(
        test_env, tap.diagnostic, [channel.name], timer_timeout_s
    )
    tap.diagnostic(
        "periodic reclaim timer fired after explicit request={}, expected True".format(
            fired_after
        )
    )
    assert fired_after


def test_auto_reclaim_resumes_after_explicit_reclaim_per_process_buffers(
    tap, test_env, client
):
    """
    Ensure that every per-process consumer channel of a single session daemon
    channel has its periodic memory reclaim timer resumed after one explicit
    `lttng reclaim-memory` request.

    A session daemon channel using per-process buffer ownership maps to one
    consumer channel per traced process, each with its own periodic reclaim
    timer task. A single request for that channel suspends all of those timers
    under one completion token and must resume them all when it completes.

    Several applications are traced into a per-process channel, so several
    consumer channels (distinct keys, same name) exist. The test checks that
    all of their reclaim timers fire, issues an explicit reclaim, then checks
    that all of them fire again.

    The request must complete asynchronously for every channel to cover the
    scenario. Data consumption is paused before the applications trace, so the
    request finds every sub-buffer unconsumed and defers them all; it can only
    complete after consumption resumes, which the test does once the request is
    known (through GDB) to be pending for every channel.
    """
    consumerd_type = (
        lttngtest.ConsumerType.UST64
        if sys.maxsize > 2**32
        else lttngtest.ConsumerType.UST32
    )
    application_count = 4
    timer_timeout_s = 15

    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("trace")
        ),
    )

    channel = session.add_channel(
        lttngtest.TracingDomain.User,
        buffer_sharing_policy=lttngtest.lttngctl.BufferSharingPolicy.PerPID,
        buffer_preallocation_policy=lttngtest.BufferPreAllocationPolicy.PreAllocate,
        auto_reclaim_memory_older_than=100000,
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))

    session.start()

    # Paused before anything is traced: no sub-buffer is ever consumed, so the
    # explicit request below can not reclaim anything synchronously and defers
    # every sub-buffer of every per-process channel.
    test_env.lttng_consumerd_pause(consumerd_type)

    # One per-process consumer channel (with its own reclaim timer) per
    # application. The applications wait before exiting so their channels
    # persist for the whole test; all of their events are written before the
    # request is issued.
    apps = lttngtest.WaitTraceTestApplicationGroup(
        test_env,
        application_count,
        event_count=10000,
        wait_before_exit=True,
    )
    apps.trace()
    apps.wait_for_tracing_done()

    # Every reclaim timer must fire before the request is issued: GDB records
    # the distinct channel keys reaching the timer testpoint and exits once
    # `application_count` keys have been seen.
    keys_before = memory_reclaim_timer_distinct_channel_keys(
        test_env, tap.diagnostic, channel.name, application_count, timer_timeout_s
    )
    tap.diagnostic(
        "distinct reclaim timer keys before explicit request={}, expected {}".format(
            sorted(keys_before), application_count
        )
    )
    assert len(keys_before) == application_count

    # Armed before the request is issued: this GDB exits once the request is
    # fully set up (every timer suspended, every sub-buffer deferred) and
    # reports the suspension and deferral counts.
    barrier_gdb, barrier_gdb_script = start_wait_for_reclaim_request_deferred(
        test_env, tap.diagnostic, count_setup=True
    )

    suspended_count = None
    deferred_count = None

    # The blocking request only completes once consumption resumes: issue it
    # from a worker thread.
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        reclaim_future = executor.submit(
            session.reclaim_memory,
            wait=True,
            channels=[channel.name],
        )

        try:
            # GDB's exit means the request is set up and, since consumption is
            # still paused, pending for every channel.
            barrier_gdb.wait(timeout=60)
            output = barrier_gdb.stdout.read().decode("utf-8", errors="ignore")
            assert barrier_gdb.returncode == 0, "GDB did not reach the testpoint"
            barrier_gdb = None

            for line in output.splitlines():
                tap.diagnostic("GDB: {}".format(line))
                if line.startswith("RECLAIM_SETUP_SUSPENDED_CHANNELS:"):
                    suspended_count = int(line.split(":", 1)[1])
                elif line.startswith("RECLAIM_SETUP_DEFERRED_STREAMS:"):
                    deferred_count = int(line.split(":", 1)[1])
        finally:
            # Resume consumption even on failure, or waiting on the worker
            # thread would hang. GDB is reaped first (the resume attaches its
            # own GDB), and reaped here if the testpoint was never hit.
            if barrier_gdb is not None:
                _interrupt_and_wait_gdb(barrier_gdb)
            test_env.lttng_consumerd_pause(consumerd_type, False)

        # Completing the request (its deferred sub-buffers are reclaimed from
        # the consumption path) must resume every suspended timer.
        reclaim_future.result(timeout=60)

    tap.diagnostic(
        "reclaim setup observed: suspended_channels={}, deferred_streams={}".format(
            suspended_count, deferred_count
        )
    )

    # Every channel is suspended and, having only unconsumed sub-buffers,
    # defers at least one stream. Anything else means the request did not
    # complete asynchronously for every channel and the resume under test was
    # not exercised.
    assert suspended_count == application_count
    assert deferred_count >= application_count

    keys_after = memory_reclaim_timer_distinct_channel_keys(
        test_env, tap.diagnostic, channel.name, application_count, timer_timeout_s
    )
    tap.diagnostic(
        "distinct reclaim timer keys after explicit request={}, expected superset of {}".format(
            sorted(keys_after), sorted(keys_before)
        )
    )
    assert keys_before.issubset(keys_after)

    apps.exit(wait_for_apps=True)


def test_explicit_reclaim_without_age_limit_survives_deferral(tap, test_env, client):
    """
    Ensure that an explicit `lttng reclaim-memory` request issued without an age
    limit does not crash the consumer daemon when it defers sub-buffers.

    A request without `--older-than` has no age limit. When such a request can't
    reclaim a sub-buffer synchronously (it is not consumed yet), the sub-buffer
    is deferred and reclaimed later in the consumption path. That path must not
    access an unset age limit while completing the deferred reclamation.

    The bug was only reached when a stream deferred more than one sub-buffer:
    the completion of the first deferred sub-buffer decrements the stream's
    pending count to a non-zero value, and only that branch accessed the age
    limit.

    To make deferral deterministic, data consumption is paused before the
    application traces. The sub-buffers therefore remain unconsumed when the
    request is serviced and are all deferred. The explicit request is issued in
    blocking mode from a separate thread (it completes once consumption
    resumes).

    Consumption must only resume once the deferral is actually in place,
    otherwise the buggy path is never exercised. A GDB breakpoint is armed on a
    testpoint the consumer daemon reaches once the deferred reclaim request has
    been put in place. The blocking request is then awaited: its return signals
    that the consumer daemon survived completing the deferred reclamation. A
    follow-up request then verifies the daemon is still responding.
    """
    consumerd_type = (
        lttngtest.ConsumerType.UST64
        if sys.maxsize > 2**32
        else lttngtest.ConsumerType.UST32
    )

    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(
            test_env.create_temporary_directory("trace")
        ),
    )

    # Small sub-buffers so that a single application fills several of them,
    # guaranteeing that more than one sub-buffer is deferred per stream.
    channel = session.add_channel(
        lttngtest.TracingDomain.User,
        subbuf_size=mmap.PAGESIZE,
        subbuf_count=4,
        buffer_sharing_policy=lttngtest.lttngctl.BufferSharingPolicy.PerPID,
        buffer_preallocation_policy=lttngtest.BufferPreAllocationPolicy.PreAllocate,
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))

    session.start()

    # Pause consumption before any event is produced so that no sub-buffer is
    # consumed: every sub-buffer must be deferred when the request is serviced.
    test_env.lttng_consumerd_pause(consumerd_type)

    app = test_env.launch_wait_trace_test_application(10000, wait_before_exit=True)
    app.trace()
    app.wait_for_tracing_done()

    # Arm a GDB breakpoint on the consumer daemon that is hit once a reclaim
    # request has finished deferring its sub-buffers, so the request issued below
    # can not be serviced before the breakpoint is armed.
    deferred_gdb, deferred_gdb_script = start_wait_for_reclaim_request_deferred(
        test_env, tap.diagnostic
    )

    # Consumption is paused, so the sub-buffers can not be reclaimed
    # synchronously and are deferred. Issue the request in blocking mode from a
    # worker thread: it can only complete once consumption resumes below, so it
    # must not block this thread in the meantime.
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        reclaim_future = executor.submit(
            session.reclaim_memory, wait=True, channels=[channel.name]
        )

        try:
            # Wait for GDB to hit the testpoint and exit: this deterministically
            # confirms that the request's deferral is in place before consumption
            # resumes.
            deferred_gdb.wait(timeout=60)
            output = deferred_gdb.stdout.read().decode("utf-8", errors="ignore")
            for line in output.splitlines():
                tap.diagnostic("GDB: {}".format(line))
            assert deferred_gdb.returncode == 0, "GDB did not reach the testpoint"
            deferred_gdb = None
        finally:
            # Reap GDB if it is still attached (for instance if the testpoint
            # was never hit), then resume consumption unconditionally: the
            # blocking request must be released even on the failure path,
            # otherwise waiting on the worker thread (here and when the
            # executor is shut down) would hang instead of failing. GDB must
            # detach first, as resuming attaches a GDB of its own.
            if deferred_gdb is not None:
                _interrupt_and_wait_gdb(deferred_gdb)

            # On the nominal path, resuming consumption completes the deferred
            # sub-buffers from the consumption path. On the buggy daemon this
            # aborts the consumer daemon and the blocking request below never
            # returns.
            test_env.lttng_consumerd_pause(consumerd_type, False)

        # Await the blocking request. Its return proves the consumer daemon
        # survived completing the deferred reclamation; a crash fails it or
        # fails the test on the timeout.
        reclaim_future.result(timeout=60)

    # The first request has completed, so the channel no longer has a
    # reclamation in progress: a follow-up request must succeed, confirming the
    # daemon is still able to service requests.
    session.reclaim_memory(wait=True, channels=[channel.name])
    tap.diagnostic("explicit reclaim without age limit completed without crashing")

    app.touch_exit_file()
    app.wait_for_exit()


@extra_tap_points(4)
def test_rotation_creates_packet_for_inactive_streams(tap, test_env, client):
    """
    Ensure that a rotation produces a packet for every stream of a channel,
    including streams that never recorded an event.

    The tracer defers the production of a stream's first packet header until
    the stream is first used (it is then stamped with the stream's creation
    timestamp). A rotation must materialize that packet so the archived trace
    chunk records the lifetime of every stream: without it, the chunk is
    missing stream files and its stream intersection is unusable.

    The application is pinned to a single CPU so the channel's other per-CPU
    streams never record anything. The session is rotated while active and
    the archived chunk is checked for one non-empty stream file per possible
    CPU, since the tracer allocates one stream per possible CPU (not per
    online CPU).
    """
    stream_count = lttngtest.possible_cpus_array_len()
    if stream_count < 2:
        raise lttngtest.TestSkipped("at least 2 possible CPUs are required")

    event_count = 10
    output_path = test_env.create_temporary_directory("trace")
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_path)
    )
    channel = session.add_channel(
        lttngtest.TracingDomain.User,
        buffer_allocation_policy=lttngtest.BufferAllocationPolicy.PerCPU,
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()

    # Keep the application alive across the rotation so its departure does
    # not tear down or flush anything before the rotation runs.
    app = test_env.launch_wait_trace_test_application(
        event_count, wait_before_exit=True
    )
    pinned_cpu = app.taskset_anycpu()
    tap.diagnostic("Application pinned to CPU {}".format(pinned_cpu))
    app.trace()
    app.wait_for_tracing_done()

    session.rotate(wait=True)

    archived_chunks = list(pathlib.Path(str(output_path)).glob("archives/*"))
    tap.diagnostic(
        "Archived trace chunks: {}".format([str(chunk) for chunk in archived_chunks])
    )
    tap.test(len(archived_chunks) == 1, "Rotation produced a trace chunk archive")

    stream_files = sorted(
        stream_file
        for chunk in archived_chunks
        for stream_file in chunk.rglob("{}_*".format(channel.name))
        if stream_file.is_file() and stream_file.parent.name != "index"
    )
    tap.diagnostic(
        "Stream files in archived chunk: {}".format(
            ["{} ({} bytes)".format(f.name, f.stat().st_size) for f in stream_files]
        )
    )
    tap.test(
        len(stream_files) == stream_count,
        "Archived chunk contains one stream file per possible CPU",
    )
    tap.test(
        len(stream_files) > 0
        and all(stream_file.stat().st_size > 0 for stream_file in stream_files),
        "Every stream file of the archived chunk contains at least one packet",
    )

    received_event_count, _ = lttngtest.count_events(
        archived_chunks, ignore_exceptions=True
    )
    tap.diagnostic(
        "Events in archived chunk: {}, expected {}".format(
            received_event_count, event_count
        )
    )
    tap.test(
        received_event_count == event_count,
        "Events recorded before the rotation are readable from the archived chunk",
    )

    app.touch_exit_file()
    app.wait_for_exit()
    session.destroy()


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
        assert (
            not "lttng-reclaim-memory(1) succeeds on non-existing event record channel"
        )
    except lttngtest.LTTngClientError as ex:
        expected_error = "Failed to reclaim memory: Event record channel `not-a-channel` does not exist"
        tap.diagnostic(
            "error_output contains '{}': {}".format(
                expected_error, expected_error in ex._error_output
            )
        )
        assert expected_error in ex._error_output


def test_auto_reclaim_memory_consumed_snapshot_mode(tap, test_env, client):
    """
    Ensure that the `--auto-reclaim-memory=consumed` option of the
    `enable-channel` command is invalid for session in snapshot mode.
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
            not "lttng enable-channel --auto-reclaim-memory=consumed succeed on session with snapshot mode"
        )
    except lttngtest.LTTngClientError as ex:
        expected_error = "Error: Failed to enable event record channel `{}` under session `{}`: Invalid reclamation policy for this event record channel".format(
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
    Ensure that the `--auto-reclaim-memory=consumed` option of the
    `enable-channel` command is invalid for session without output.
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
            not "lttng enable-channel --auto-reclaim-memory=consumed succeed on session without output"
        )
    except lttngtest.LTTngClientError as ex:
        expected_error = "Error: Failed to enable event record channel `{}` under session `{}`: Invalid reclamation policy for this event record channel".format(
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


def test_plan_size(test):
    """
    Number of tap test points a test accounts for in the plan: the points it
    publishes itself (see extra_tap_points()) plus its completion point.
    """
    return getattr(test, "extra_tap_points", 0) + 1


def run_test(test, variant):
    test_name = "{}({})".format(
        test.__name__,
        ", ".join(["{}={}".format(key, value) for key, value in variant.items()]),
    )
    remaining_before_test = tap.remaining_test_cases

    def unpublished_test_points():
        published = remaining_before_test - tap.remaining_test_cases
        return test_plan_size(test) - published

    try:
        with lttngtest.test_environment(
            with_sessiond=True, log=tap.diagnostic
        ) as test_env:
            client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
            test(tap, test_env, client, **variant)
            tap.ok(test_name)
    except lttngtest.TestSkipped as skip:
        tap.skip("{} - {}".format(test_name, str(skip)), unpublished_test_points())
    except AssertionError:
        _, _, bt = sys.exc_info()
        traceback.print_tb(bt)
        top_frame = traceback.extract_tb(bt)[-1]
        filename, line, _, _ = top_frame
        tap.fail("{} - Failed assertion at: {}:{}".format(test_name, filename, line))
        tap.skip("{} - unreached".format(test_name), unpublished_test_points())
    except Exception as exn:
        tap.fail("{} - Uncaught exception".format(test_name))
        tap.diagnostic("".join(traceback.format_exception(exn)))
        tap.skip("{} - unreached".format(test_name), unpublished_test_points())


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format=lttngtest.utils.get_logging_format())
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
        test_auto_reclaim_resumes_after_explicit_reclaim,
        test_auto_reclaim_resumes_after_explicit_reclaim_per_process_buffers,
        test_explicit_reclaim_without_age_limit_survives_deferral,
        test_rotation_creates_packet_for_inactive_streams,
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
                lttngtest.EventRecordLossMode.Overwrite,
            ],
            "buffer_allocation_policy": [
                lttngtest.BufferAllocationPolicy.PerCPU,
                lttngtest.BufferAllocationPolicy.PerChannel,
            ],
            "snapshot": [True, False],
        }

        keys = options.keys()

        return [
            dict(zip(keys, items)) for items in itertools.product(*options.values())
        ]

    variants = list_variants()

    tap = lttngtest.TapGenerator(
        len(variants) * sum(test_plan_size(test) for test in tests)
        + sum(test_plan_size(test) for test in tests_no_variants)
    )

    if not lttngtest.utils.gdb_exists():
        tap.missing_platform_requirement("GDB not available")

    for variant in variants:
        for test in tests:
            run_test(test, variant)

    for test in tests_no_variants:
        run_test(test, {})

    sys.exit(0 if tap.is_successful else 1)
