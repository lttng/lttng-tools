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


class CallbackBreakpoint(gdb.Breakpoint):
    """
    Breakpoint whose stop() delegates to a Python callback.

    The callback receives the breakpoint and returns whether GDB must stop:
    returning False resumes the inferior without any `continue` command,
    returning True stops it so a batch script proceeds to its next commands.

    Do not set a condition on such a breakpoint: GDB documents that `stop()`
    and breakpoint conditions must not be combined. Filter in the callback.
    """

    def __init__(self, spec, callback):
        super(CallbackBreakpoint, self).__init__(spec)
        self._callback = callback

    def stop(self):
        return self._callback(self)


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


def break_testpoint_callback(prefix, callback):
    """
    Like break_testpoint(), but the breakpoints delegate their stop decision
    to `callback` (see CallbackBreakpoint).
    """
    pid = gdb.selected_inferior().pid
    testpoints = get_testpoints(pid)
    breakpoints = []
    for testpoint in testpoints:
        # TESTPOINT() symbols are emitted as <name>.<unique-id>.
        if testpoint.startswith(prefix):
            bp = CallbackBreakpoint(testpoint, callback)
            bp.enabled = True
            breakpoints.append(bp)

    return breakpoints
