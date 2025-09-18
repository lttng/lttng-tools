# SPDX-FileCopyrightText: 2025 Olivier Dion <odion@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only

import gdb
import shlex
import subproces

pid_to_testpoints = dict()


def list_testpoints(path):
    cmd = (
        "nm --quiet --format=posix %s | cut -d ' ' -f 1 | grep lttng_ust_testpoint | sort | uniq"
        % shlex.quote(path)
    )
    result = subprocess.check_output(cmd, shell=True)
    if isinstance(result, bytes):
        result = result.decode("utf-8")
    return result.splitlines()


def get_testpoints(pid):
    if pid not in pid_to_testpoints:
        testpoints = []
        lttng_ust_objects = [
            obj for obj in gdb.objfiles() if "lttng-ust.so" in obj.filename
        ]
        for obj in lttng_ust_objects:
            testpoints.extend(list_testpoints(obj.filename))
        pid_to_testpoints[pid] = set(testpoints)
    return pid_to_testpoints[pid]


def break_testpoint(prefix):

    for testpoint in get_testpoints(gdb.selected_inferior().pid):
        if testpoint.startswith(prefix):
            bp = gdb.Breakpoint(testpoint)
            bp.enabled = True
