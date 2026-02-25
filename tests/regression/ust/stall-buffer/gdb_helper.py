# SPDX-FileCopyrightText: 2025 Olivier Dion <odion@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only

import gdb
import os
import shlex
import subprocess

pid_to_testpoints = dict()


def list_testpoints(path):
    """List all lttng testpoint symbols (both UST and tools) from a binary."""
    cmd = (
        "nm --format=posix %s 2>/dev/null | cut -d ' ' -f 1 | grep -E 'lttng_(ust|tools)_testpoint' | sort | uniq"
        % shlex.quote(path)
    )
    try:
        result = subprocess.check_output(cmd, shell=True)
        if isinstance(result, bytes):
            result = result.decode("utf-8")
        return result.splitlines()
    except subprocess.CalledProcessError:
        return []


def is_lttng_object(filename):
    """Check if an objfile is an LTTng binary or shared library."""
    if not filename:
        return False
    basename = os.path.basename(filename)
    return "lttng" in basename


def get_testpoints(pid):
    if pid not in pid_to_testpoints:
        testpoints = []
        for obj in gdb.objfiles():
            if is_lttng_object(obj.filename):
                testpoints.extend(list_testpoints(obj.filename))
        pid_to_testpoints[pid] = set(testpoints)
    return pid_to_testpoints[pid]


def install_breakpoint_commands(breakpoints, commands):
    if isinstance(commands, str):
        commands_text = commands
    else:
        commands_text = "\n".join(commands)

    for bp in breakpoints:
        bp.commands = commands_text


def break_testpoint(prefix):
    pid = gdb.selected_inferior().pid
    testpoints = get_testpoints(pid)
    breakpoints = []
    for testpoint in testpoints:
        # TESTPOINT() symbols are emitted as <name>.<unique-id>.
        if testpoint.startswith(prefix):
            bp = gdb.Breakpoint(testpoint)
            bp.enabled = True
            breakpoints.append(bp)

    return breakpoints
