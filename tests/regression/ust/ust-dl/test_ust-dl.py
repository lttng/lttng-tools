#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# SPDX-FileCopyrightText: 2015 Antoine Busque <abusque@efficios.com>
# SPDX-FileCopyrightText: 2025 Kienan Stewart <kstewart@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only

import ctypes
import ctypes.util
import os
import pathlib
import subprocess
import re
import shutil
import sys

# Import in-tree test utils
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.append(str(test_utils_import_path))

import lttngtest
import bt2


def test(tap, test_env):
    expected_events = [
        "lttng_ust_dl:dlopen",
        "lttng_ust_dl:dlmopen",  # > 0 iff dlmopen available
        "lttng_ust_dl:build_id",
        "lttng_ust_dl:debug_link",
        "lttng_ust_dl:dlclose",
        "lttng_ust_lib:build_id",
        "lttng_ust_lib:debug_link",
        "lttng_ust_lib:unload",
        "lttng_ust_lib:load",
    ]
    expected_library_loads = ["libfoo.so", "libbar.so", "libzzz.so"]

    test_path = os.path.dirname(os.path.abspath(__file__)) + "/"
    output_path = test_env.create_temporary_directory("trace")
    client = lttngtest.LTTngClient(test_env, log=tap.diagnostic)
    session = client.create_session(
        output=lttngtest.LocalSessionOutputLocation(output_path)
    )
    channel = session.add_channel(lttngtest.lttngctl.TracingDomain.User)
    channel.add_recording_rule(lttngtest.lttngctl.UserTracepointEventRule("*"))
    session.start()

    app_env = {
        "LD_PRELOAD": "{}:{}".format(os.getenv("LD_PRELOAD", ""), "liblttng-ust-dl.so"),
        "LD_LIBRARY_PATH": "{}:{}".format(os.getenv("LD_LIBRARY_PATH", ""), test_path),
    }
    app = test_env.launch_test_application(
        os.path.join(test_path, "prog"), extra_env_vars=app_env
    )
    app.wait_for_exit()
    session.stop()
    received_events = {x: 0 for x in expected_events}
    received_library_loads = {x: 0 for x in expected_library_loads}
    for msg in bt2.TraceCollectionMessageIterator(str(output_path)):
        if type(msg) is bt2._EventMessageConst:
            if msg.event.name in expected_events:
                received_events[msg.event.name] += 1
            if msg.event.name == "lttng_ust_lib:load":
                if "path" in msg.event.payload_field:
                    lib = os.path.basename(str(msg.event.payload_field["path"]))
                    received_library_loads[lib] += 1

    for event, count in received_events.items():
        if event == "lttng_ust_dl:dlmopen" and not have_dlmopen:
            tap.skip(
                "lttng_ust_dl:dlmopen has at least 1 event",
                "dlmopen not detected in libdl.so",
            )
        else:
            tap.test(count > 0, "Event '{}' has at least 1 event".format(event))

    for lib, count in received_library_loads.items():
        tap.test(count == 1, "Library '{}' loaded exactly once".format(lib))


if __name__ == "__main__":
    have_dlmopen = False
    dl_lib = ctypes.util.find_library("dl")
    if dl_lib:
        dl = ctypes.cdll.LoadLibrary(dl_lib)
        if dl.dlmopen:
            have_dlmopen = True

    tap = lttngtest.TapGenerator(12)
    with lttngtest.test_environment(with_sessiond=True, log=tap.diagnostic) as test_env:
        test(tap, test_env)

    sys.exit(0 if tap.is_successful else 1)
