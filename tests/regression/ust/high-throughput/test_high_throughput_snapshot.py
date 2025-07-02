#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Validate that the trailing packet in snapshots contains the appropriate
events discarded for the ring buffer.

See test_ust_local_snapshot_duplicate_seq_num in
tests/regression/tools/snapshots/ust_test.
"""

import os
import pathlib
import platform
import shutil
import subprocess
import sys
import time

test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import bt2
import lttngtest


def get_bytes_at_offset(file_name, offset, length):
    with open(file_name, "rb") as f:
        f.seek(offset)
        data = f.read(length)
    return data


def bytes_to_hex_str(b):
    return " ".join("{:02x}".format(byte) for byte in b)


def test_high_throughput_snapshot(tap, test_env, events_per_app=100):
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(output=None, snapshot=True)
    channel = session.add_channel(
        lttngtest.lttngctl.TracingDomain.User, subbuf_size=4096, subbuf_count=4
    )
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("tp:tptest"))
    session.start()

    # 1. Trace application to set-up a situation where the ring-buffers have discarded events
    # Note: in snapshot mode this is less likely to happen than in discard mode, so an application
    # that explicitly emits events that are too large is used.
    online_cpus = list(lttngtest.online_cpus())
    app_kwargs = [
        # If there are no events produced ever, the sub-buffers remain empty (despite
        # accruing lost events) and so they are never delivered. Therefore, an application
        # that doesn't have discarded events for being too large is run first.
        {"event_count": events_per_app},
        # Then this application is run and all the events it emits should be discarded
        # as too large due to the text_size + fill_text vs. configured sub-buffer size.
        {"event_count": events_per_app, "text_size": 2048, "fill_text": True},
    ]
    for app_kwarg in app_kwargs:
        app = test_env.launch_wait_trace_test_application(**app_kwarg)
        proc = subprocess.Popen(
            ["taskset", "-c", "-p", str(online_cpus[0]), str(app.vpid)]
        )
        proc.wait()
        if proc.returncode != 0:
            tap.diagnostic(
                "Failed to tasket pid '{}' to CPU '{}': {}".format(
                    app.vpid, online_cpus[0], proc.returncode
                )
            )
            tap.bail_out("All tasksets need to succeed")
            return
        app.trace()
        app.wait_for_tracing_done()
        app.wait_for_exit()

    # 2. Snapshot and Confirm that there are discarded events
    output_path_a = test_env.create_temporary_directory()
    client.snapshot_record(session.name, output_path_a)
    received_a = 0
    discarded_a = 0
    for msg in bt2.TraceCollectionMessageIterator(str(output_path_a)):
        if type(msg) is bt2._EventMessageConst:
            received_a += 1
            continue

        if type(msg) is bt2._DiscardedEventsMessageConst:
            discarded_a += msg.count

    tap.diagnostic(
        "Total={}, Received={}, Discarded={}".format(
            received_a + discarded_a, received_a, discarded_a
        )
    )

    # 3. Snapshot and confirm that discarded events match, and that the trailing packets for the streams
    # have events discarded
    output_path_b = test_env.create_temporary_directory()
    client.snapshot_record(session.name, output_path_b)
    received_b = 0
    discarded_b = 0
    for msg in bt2.TraceCollectionMessageIterator(str(output_path_b)):
        if type(msg) is bt2._EventMessageConst:
            received_b += 1
            continue

        if type(msg) is bt2._DiscardedEventsMessageConst:
            discarded_b += msg.count

    tap.diagnostic(
        "Total={}, Received={}, Discarded={}".format(
            received_b + discarded_b, received_b, discarded_b
        )
    )

    tap.test(
        discarded_a == discarded_b,
        "The events discarded in snapshot A ({}) and snapshot B ({}) match".format(
            discarded_a, discarded_b
        ),
    )
    tap.test(
        discarded_a == events_per_app,
        "The number of discarded events ({}) match the number events emitted by a single run of the application ({})".format(
            discarded_a, events_per_app
        ),
    )

    # Get the configure page size.
    proc = subprocess.Popen(["getconf", "PAGE_SIZE"], stdout=subprocess.PIPE)
    proc.wait()
    if proc.returncode != 0:
        tap.bail_out("Unable to determine page size")
        return

    page_size = int(proc.stdout.read().decode("utf-8").strip())

    # Get the file associated with the chosen CPU from Snapshot B
    file_name = os.path.join(
        output_path_b,
        str(list(pathlib.Path(output_path_b).glob("*"))[0]),
        "ust",
        "uid",
        str(os.getuid()),
        "64-bit",
        "{}_{}".format(channel.name, online_cpus[0]),
    )

    # start of last (of the 4 from the ringbuffer) packet = page_size * 3
    # start of terminal packet = page_size * 4
    # CTF1 x86_64 : events_discarded at offset (decimal) 72, 8 bytes long
    events_discarded_fourth_packet = get_bytes_at_offset(
        file_name, 72 + 3 * page_size, 8
    )
    events_discarded_terminal_packet = get_bytes_at_offset(
        file_name, 72 + 4 * page_size, 8
    )

    tap.test(
        events_discarded_terminal_packet == events_discarded_fourth_packet,
        "events_discarded header field in fourth packet (`{}`) and terminal packet (`{}`) match.".format(
            bytes_to_hex_str(events_discarded_fourth_packet),
            bytes_to_hex_str(events_discarded_terminal_packet),
        ),
    )


if __name__ == "__main__":
    tap = lttngtest.TapGenerator(3)
    if platform.machine() != "x86_64":
        tap.skip_all_remaining("Only run on x86_64")
        sys.exit(0)

    if sys.maxsize <= 2**32:
        tap.skip_all_remaining("Only run on 64-bit systems")
        sys.exit(0)

    with lttngtest.test_environment(log=tap.diagnostic, with_sessiond=True) as test_env:
        test_high_throughput_snapshot(tap, test_env)

    sys.exit(0 if tap.is_successful else 1)
